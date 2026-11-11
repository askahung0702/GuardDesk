#include "session.hpp"
#include "video_geometry.hpp"
#include <limits>
#include <stdexcept>

namespace remote {
SessionRuntime::SessionRuntime(ipc::Session session,std::uint64_t transport,std::uint64_t now,std::uint64_t deadline,
    std::function<UINT(const std::vector<INPUT>&)> sink,std::function<void()> clear)
    :gate_(session,transport,now,deadline),input_(std::move(sink)),clear_frames_(std::move(clear)){
    if(!clear_frames_)throw std::invalid_argument("frame_reset_missing");
}
void SessionRuntime::pause(DesktopState state){
    gate_.pause();if(state_!=state)clear_frames_();state_=state;
}
void SessionRuntime::close(const DesktopObservation& current){
    if(terminal_)return;
    gate_.revoke();clear_frames_();
    if(!current.same_logon)input_.abandon_logon();
    else input_.release_all(current.allowed && desktop_.identity!=0 && current.identity==desktop_.identity);
    terminal_=true;state_=DesktopState::ended;
}
bool SessionRuntime::observe(const DesktopObservation& current,std::uint64_t now){
    if(terminal_)return false;
    if(!current.same_logon){close(current);return false;}
    if(!gate_.authorized(now)){close(current);return false;}
    if(!current.allowed || !current.identity){
        input_.release_all(current.identity!=0 && current.identity==desktop_.identity);
        pause(DesktopState::paused);return false;
    }
    const auto width=std::int64_t(current.output.right)-current.output.left;
    const auto height=std::int64_t(current.output.bottom)-current.output.top;
    if(width<=0 || height<=0 || width>8192 || height>8192 || width*height>16777216){close(current);return false;}
    const bool changed=current.identity!=desktop_.identity || current.secure!=desktop_.secure ||
        !EqualRect(&current.output,&desktop_.output) || !EqualRect(&current.virtual_screen,&desktop_.virtual_screen) ||
        state_==DesktopState::paused || state_==DesktopState::switching;
    if(changed){
        // Transition cleanup contains ONLY locally tracked key/button ups, no
        // replayed down/move. It may enter the new authorized desktop only
        // after the host has verified the same logon and (for secure) real UAC.
        // Revoke/expiry cleanup above remains original-desktop-only.
        if((input_.held() || input_.failed()) && !input_.release_all(current.allowed && current.same_logon)){
            pause(DesktopState::switching);return false;
        }
        pause(DesktopState::switching);
        const auto size=video_size(static_cast<unsigned>(width),static_cast<unsigned>(height));
        if(generation_==std::numeric_limits<std::uint64_t>::max() ||
            !gate_.set_desktop(++generation_,size.first,size.second)){close(current);return false;}
        desktop_=current;
    }
    state_=current.secure?DesktopState::active_secure:DesktopState::active_default;return true;
}
bool SessionRuntime::command(const ipc::Message& message,std::uint64_t now,const DesktopObservation& current){
    rejection_=0;if(terminal_){rejection_=2;return false;}
    // Consume even a refused sequence, so it cannot be retried after ACK or a
    // later desktop change. The transport must already validate session/schema.
    if(message.header.sequence<=last_command_){rejection_=1;return false;}
    last_command_=message.header.sequence;
    if(!current.same_logon){rejection_=4;close(current);return false;}
    const auto kind=message.header.kind;
    if(!gate_.accept_broker(message,now)){
        rejection_=gate_.refusal();
        if(!gate_.authorized(now))close(current);return false;
    }
    if(kind==ipc::Kind::stop){close(current);return true;}
    if(kind==ipc::Kind::release_all){
        if(message.payload.size()==8){
            const bool same=current.allowed && current.identity && current.identity==desktop_.identity && current.secure==desktop_.secure &&
                EqualRect(&current.output,&desktop_.output) && EqualRect(&current.virtual_screen,&desktop_.virtual_screen);
            const auto code=unsigned(message.payload.at(2))|(unsigned(message.payload.at(3))<<8);
            const bool clean=input_.release_up(message.payload.at(0),code,same);
            if(input_.failed())pause(DesktopState::paused);
            return clean && !input_.failed(); // Never bless a failed input ledger.
        }
        const bool clean=input_.release_all(current.allowed && current.identity==desktop_.identity);
        // Focus loss and stale-input cleanup do not change a verified desktop.
        // Recreating DXGI here discards its last image, and pointer-only updates
        // may then leave capture without a usable image. Keep capture only for
        // the exact live desktop; require a newly published/presented frame
        // before accepting more input. Cleanup never extends authorization.
        const bool same=clean && gate_.authorized(now) && current.allowed && current.identity &&
            current.identity==desktop_.identity && current.secure==desktop_.secure &&
            EqualRect(&current.output,&desktop_.output) && EqualRect(&current.virtual_screen,&desktop_.virtual_screen) &&
            (state_==DesktopState::active_default || state_==DesktopState::active_secure);
        if(same)gate_.invalidate_input_ack();
        else pause(DesktopState::paused);
        return clean;
    }
    if(kind==ipc::Kind::lease){
        std::uint64_t authorization=0;for(unsigned i=0;i<8;++i)authorization|=std::uint64_t(message.payload.at(8+i))<<(8*i);
        const bool control=message.payload.at(16)==1;
        if(authorization_ && (authorization!=authorization_ || control!=control_)){
            input_.release_all(current.allowed && current.identity==desktop_.identity);pause(DesktopState::paused);
        }
        authorization_=authorization;control_=control;return true;
    }
    if(!observe(current,now)){rejection_=4;return false;}
    if(kind==ipc::Kind::input){
        if(message.header.desktop_generation!=generation_){rejection_=4;return false;}
        const auto size=video_size(static_cast<unsigned>(desktop_.output.right-desktop_.output.left),static_cast<unsigned>(desktop_.output.bottom-desktop_.output.top));
        if(!input_.apply(message,desktop_.output,desktop_.virtual_screen,size.first,size.second)){
            rejection_=7;
            // A rejected unmatched up has injected nothing. Only an OS input
            // failure needs release/resync; it is not evidence DXGI changed.
            if(input_.failed())pause(DesktopState::paused);
            return false;
        }
    }
    return true;
}
bool SessionRuntime::publish_frame(std::uint64_t sequence,std::uint64_t now){
    if(terminal_ || (state_!=DesktopState::active_default && state_!=DesktopState::active_secure) || sequence<=last_frame_)return false;
    if(!gate_.frame(sequence,now))return false;
    last_frame_=sequence;return true;
}
}
