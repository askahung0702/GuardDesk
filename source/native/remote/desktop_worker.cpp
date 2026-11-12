#include "desktop_worker.hpp"
#include <algorithm>
#include <limits>

namespace remote {
namespace {
bool cleanup_only(const std::vector<INPUT>& batch){
    if(batch.empty())return false;
    for(const auto& item:batch){
        if(item.type==INPUT_KEYBOARD){if((item.ki.dwFlags&KEYEVENTF_KEYUP)==0)return false;}
        else if(item.type==INPUT_MOUSE){if(item.mi.dwFlags!=MOUSEEVENTF_LEFTUP && item.mi.dwFlags!=MOUSEEVENTF_RIGHTUP && item.mi.dwFlags!=MOUSEEVENTF_MIDDLEUP)return false;}
        else return false;
    }
    return true;
}
}
DesktopWorker::DesktopWorker(LogonBinding logon,ipc::Session session,std::uint64_t transport,std::uint64_t deadline,std::unique_ptr<FramePool> frames)
    :desktop_(logon),frames_(std::move(frames)),capture_(std::make_unique<CaptureTask>([logon]{return capture_processor(logon);})),runtime_(session,transport,GetTickCount64(),deadline,
        [this](const auto& batch){
            if((!runtime_.authorized(GetTickCount64()) && !cleanup_only(batch)) || !input_guard())return 0u;
            const auto start=monotonic_us();const auto result=send_windows_input(batch);status_.latency[3].record(monotonic_us()-start);return result;
        },[this]{
            status_.last_reason=status_.pending_reason;WorkerStatus::increment(status_.resets);WorkerStatus::increment(status_.reasons.at(status_.last_reason));
            frames_->clear();capture_->invalidate();capture_outstanding_=false;next_request_=0;opened_generation_=0;refresh_tick_=0;latest_cursor_.reset();cursor_refresh_=0;
            if(!latest_pixels_.bgra.empty())SecureZeroMemory(latest_pixels_.bgra.data(),latest_pixels_.bgra.size());latest_pixels_={};
        }),session_(session),transport_(transport){if(!frames_)throw std::invalid_argument("worker_frames_missing");}
DesktopWorker::~DesktopWorker(){try{close();}catch(...){/* OS tears down private mappings/handles; no retry or content log. */}}
bool DesktopWorker::input_guard(){
    const auto start=monotonic_us();const auto okay=desktop_.input_guard(current_);
    WorkerStatus::increment(status_.guard_checks);status_.latency[2].record(monotonic_us()-start);return okay;
}
bool DesktopWorker::command(const ipc::Message& message){
    const auto started=GetTickCount64();bool accepted=false;
    struct Timed{
        WorkerStatus& status;std::uint64_t start;bool input;bool& accepted;unsigned down_type;
        std::uint64_t us=monotonic_us();
        ~Timed(){
            status.latency[1].record(monotonic_us()-us);
            status.command_max_ms=std::max(status.command_max_ms,static_cast<std::uint32_t>(std::min<std::uint64_t>(GetTickCount64()-start,UINT32_MAX)));
            if(input){WorkerStatus::increment(status.input_received);WorkerStatus::increment(accepted?status.input_accepted:status.input_rejected);}
            if(input && (down_type==1 || down_type==2)){auto& counts=down_type==2?status.button_down:status.key_down;
                WorkerStatus::increment(counts[0]);WorkerStatus::increment(counts[accepted?1:2]);}
        }
    } timed{status_,started,message.header.kind==ipc::Kind::input,accepted,
        message.payload.size()==24 && message.payload[1]==1?unsigned(message.payload[0]):0u};
    if(runtime_.ended())return false;
    if(!initial_lease_){
        if(message.header.kind!=ipc::Kind::lease)return false;
        current_.same_logon=desktop_.logon_alive();
    }else if(runtime_.authorized(GetTickCount64())){
        const bool housekeeping=message.header.kind==ipc::Kind::lease || message.header.kind==ipc::Kind::consumed || message.header.kind==ipc::Kind::presented;
        if(housekeeping)WorkerStatus::increment(status_.housekeeping);
        else current_=desktop_.select(); // real input/cleanup still revalidates OS
    }
    const auto& prior=runtime_.desktop();
    const bool transition=current_.allowed && current_.same_logon && (current_.identity!=prior.identity || current_.secure!=prior.secure || !EqualRect(&current_.output,&prior.output) || !EqualRect(&current_.virtual_screen,&prior.virtual_screen));
    status_.reason(transition?WorkerStatus::desktop_change:message.header.kind==ipc::Kind::release_all?WorkerStatus::cleanup:
        message.header.kind==ipc::Kind::input?WorkerStatus::input_failure:WorkerStatus::desktop_guard);
    accepted=runtime_.command(message,GetTickCount64(),current_);
    if(!accepted && message.header.kind==ipc::Kind::input)WorkerStatus::increment(status_.rejections.at(runtime_.rejection()));
    if(accepted && message.header.kind==ipc::Kind::lease)initial_lease_=true;
    if(accepted && message.header.kind==ipc::Kind::consumed)frames_->release_sequence(message.header.desktop_generation,message.header.frame_sequence);
    return accepted;
}
void DesktopWorker::queue_observation(std::uint32_t coalesced,std::uint32_t high_water,std::uint64_t age,bool stale_input,unsigned down_type,bool stale_presented){
    status_.moves_coalesced=coalesced;status_.queue_high_water=high_water;
    status_.queue_age_max_ms=std::max(status_.queue_age_max_ms,static_cast<std::uint32_t>(std::min<std::uint64_t>(age,UINT32_MAX)));
    status_.latency[0].record(age*1000);
    if(stale_input){WorkerStatus::increment(status_.input_received);WorkerStatus::increment(status_.input_rejected);WorkerStatus::increment(status_.input_stale);WorkerStatus::increment(status_.rejections[5]);}
    if(stale_input && (down_type==1 || down_type==2)){auto& counts=down_type==2?status_.button_down:status_.key_down;
        WorkerStatus::increment(counts[0]);WorkerStatus::increment(counts[2]);}
    if(stale_presented)WorkerStatus::increment(status_.stale_presented_dropped);
}
std::optional<FrameTicket> DesktopWorker::poll(){
    if(!initial_lease_ || runtime_.ended())return std::nullopt;
    WorkerStatus::increment(status_.polls);status_.stage=1;
    current_=desktop_.select();const auto& prior=runtime_.desktop();
    status_.reason(current_.allowed && current_.same_logon && (current_.identity!=prior.identity || current_.secure!=prior.secure || !EqualRect(&current_.output,&prior.output) || !EqualRect(&current_.virtual_screen,&prior.virtual_screen))?WorkerStatus::desktop_change:WorkerStatus::desktop_guard);
    if(!runtime_.observe(current_,GetTickCount64())){status_.api=0;status_.error=static_cast<std::uint32_t>(HRESULT_FROM_WIN32(ERROR_INVALID_STATE));return std::nullopt;}
    try{
    // Do not replace a completed desktop frame with a later pointer-only
    // result before the owner has consumed it (the historical first-frame bug).
    status_.stage=5;auto result=capture_->take();if(result)capture_outstanding_=false;
    if(!capture_outstanding_ && GetTickCount64()>=next_request_){capture_->submit({current_,runtime_.generation(),runtime_.deadline()});capture_outstanding_=true;next_request_=GetTickCount64()+33;}
    if(!result){WorkerStatus::increment(status_.capture_pending);return std::nullopt;}
    if(result->generation!=runtime_.generation())return std::nullopt;
    if(result->deferred || (result->tick && (GetTickCount64()<result->tick || GetTickCount64()-result->tick>100)))return std::nullopt;
    status_.latency[4].record(result->elapsed_us);const auto status=result->status;
    status_.api=result->api;status_.error=result->error;
    if(status==CaptureStatus::reset_required || status==CaptureStatus::unavailable){
        status_.stage=7;status_.reason(WorkerStatus::capture_reset);auto paused=current_;paused.allowed=false;runtime_.observe(paused,GetTickCount64());return std::nullopt;
    }
    if(status==CaptureStatus::frame){WorkerStatus::increment(status_.acquired);
        if(!latest_pixels_.bgra.empty())SecureZeroMemory(latest_pixels_.bgra.data(),latest_pixels_.bgra.size());latest_pixels_=std::move(result->pixels);
    }
    status_.stage=8;bool cursor_changed=false;if(result->cursor){latest_cursor_=std::move(*result->cursor);cursor_changed=true;}
    if(latest_cursor_ && (cursor_changed || (!latest_cursor_->xor_mask.empty() && status==CaptureStatus::frame) || GetTickCount64()-cursor_refresh_>=500) && !latest_pixels_.bgra.empty() && input_guard() && runtime_.authorized(GetTickCount64())){
        auto cursor=latest_cursor_;
        if(cursor_sequence_==std::numeric_limits<std::uint64_t>::max()){close();return std::nullopt;}
        cursor->session=session_;cursor->transport=transport_;cursor->generation=runtime_.generation();cursor->sequence=++cursor_sequence_;
        const auto sw=static_cast<unsigned>(current_.output.right-current_.output.left),sh=static_cast<unsigned>(current_.output.bottom-current_.output.top);
        auto composed=compose_cursor(std::move(*cursor),latest_pixels_,sw,sh);
        auto scaled=scale_cursor(std::move(composed),sw,sh,latest_pixels_.width,latest_pixels_.height);
        const auto now=GetTickCount64();if(frames_->publish_cursor(scaled,now))cursor_refresh_=now;
    }
    status_.stage=6;if(status!=CaptureStatus::frame && (status!=CaptureStatus::unchanged || latest_pixels_.bgra.empty() || GetTickCount64()-refresh_tick_<500))return std::nullopt;
    // Recheck after capture; a frame sampled across a desktop/logon transition
    // is discarded and never tagged as the next epoch.
    status_.stage=9;if(!input_guard() || !runtime_.authorized(GetTickCount64())){
        status_.reason(WorkerStatus::publish_guard);
        return std::nullopt;
    }
    if(frame_sequence_==std::numeric_limits<std::uint64_t>::max()){close();return std::nullopt;}
    FrameTicket ticket{};const auto sequence=++frame_sequence_,tick=GetTickCount64();
    status_.stage=10;const bool published=frames_->publish(latest_pixels_,runtime_.generation(),sequence,tick,ticket);
    if(!published)return std::nullopt;
    status_.stage=11;if(!runtime_.publish_frame(sequence,tick)){frames_->clear();return std::nullopt;}
    status_.stage=12;WorkerStatus::increment(status_.published);refresh_tick_=tick;return ticket;
    }catch(const std::exception& error){
        const auto* graphics=dynamic_cast<const GraphicsFailure*>(&error);
        status_.error=static_cast<std::uint32_t>(graphics?graphics->result:E_FAIL);status_.stage=13;
        // A transient DXGI/driver resource loss resets capture and its ACK
        // epoch; it does not end original consent. No other desktop fallback.
        status_.reason(WorkerStatus::exception);auto paused=current_;paused.allowed=false;runtime_.observe(paused,GetTickCount64());retry_capture_=GetTickCount64()+500;return std::nullopt;
    }
}
void DesktopWorker::close(){
    if(runtime_.ended())return;
    if(initial_lease_)current_=desktop_.select();status_.reason(WorkerStatus::cleanup);runtime_.close(current_);capture_->invalidate();
}
}
