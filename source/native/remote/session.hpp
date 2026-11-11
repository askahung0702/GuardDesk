#pragma once
#include "capture.hpp"
#include "input.hpp"
#include <functional>

namespace remote {
enum class DesktopState:unsigned{requested=0,active_default=1,switching=2,active_secure=3,paused=4,closing=5,ended=6};
struct DesktopObservation{
    bool same_logon=false,allowed=false,secure=false;
    std::uint64_t identity=0; // Local desktop identity, not supplied by the viewer.
    RECT output{},virtual_screen{};
};
class SessionRuntime {
    ipc::ControlGate gate_;
    InputLedger input_;
    DesktopObservation desktop_{};
    DesktopState state_=DesktopState::requested;
    std::uint64_t generation_=0,last_frame_=0,last_command_=0;
    std::uint64_t authorization_=0;
    bool control_=false;
    bool terminal_=false;
    unsigned rejection_=0;
    std::function<void()> clear_frames_;
    void pause(DesktopState state);
public:
    SessionRuntime(ipc::Session session,std::uint64_t transport,std::uint64_t now,std::uint64_t consent_deadline,
        std::function<UINT(const std::vector<INPUT>&)> sink,std::function<void()> clear_frames);
    bool command(const ipc::Message& message,std::uint64_t now,const DesktopObservation& current);
    bool observe(const DesktopObservation& current,std::uint64_t now);
    bool publish_frame(std::uint64_t sequence,std::uint64_t now);
    void close(const DesktopObservation& current);
    DesktopState state() const{return state_;}
    const DesktopObservation& desktop()const{return desktop_;}
    unsigned rejection()const{return rejection_;}
    std::uint64_t generation() const{return generation_;}
    bool ended() const{return terminal_;}
    bool held() const{return input_.held();}
    bool authorized(std::uint64_t now) const{return gate_.authorized(now);}
    std::uint64_t deadline()const{return gate_.deadline();}
};
}
