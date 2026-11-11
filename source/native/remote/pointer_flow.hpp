#pragma once
#include "ipc_wire.hpp"
#include <algorithm>
#include <deque>
#include <optional>
#include <stdexcept>

namespace remote {
// A completed, successfully sent final button-up is not loss of UI focus.
// Windows also sends WM_CAPTURECHANGED for our own ReleaseCapture call.
class CaptureGesture {
    unsigned buttons_=0;bool completed_release_=false;
public:
    void reset(){buttons_=0;}
    bool held() const{return buttons_!=0;}
    bool button(unsigned code,bool down,bool sent){
        if(code<1 || code>3 || !sent)return false;
        const auto bit=1u<<(code-1);const bool matched=(buttons_&bit)!=0;
        if(down)buttons_|=bit;else buttons_&=~bit;
        return !down && matched && !buttons_;
    }
    template<class F> bool release_completed(bool completed,F&& action){
        completed_release_=completed;
        try{const bool okay=action();completed_release_=false;return okay;}
        catch(...){completed_release_=false;throw;}
    }
    bool capture_changed(bool gaining_window){
        if(completed_release_ && !gaining_window && !buttons_)return false;
        reset();return true;
    }
};
// Local scheduling only. It neither changes a lease nor validates authority.
// The receiver still validates every retained command and its exact frame ACK.
class PointerPacer {
    std::optional<std::vector<std::uint8_t>> latest_;
    std::uint64_t queued_=0,last_sent_=0;
    bool sent_=false;
    unsigned interval_=33;
public:
    explicit PointerPacer(unsigned interval=33):interval_(interval){if(interval<16 || interval>33)throw std::invalid_argument("pointer_interval");}
    void reset(){latest_.reset();} // Keep cadence across focus changes.
    unsigned wait_ms(std::uint64_t now,unsigned ceiling=50)const{
        if(!latest_)return ceiling;
        if(!sent_ || now<last_sent_ || now-last_sent_>=interval_)return 0;
        return std::min(ceiling,static_cast<unsigned>(interval_-(now-last_sent_)));
    }
    void replace(std::vector<std::uint8_t> value,std::uint64_t now){latest_=std::move(value);queued_=now;}
    std::optional<std::vector<std::uint8_t>> take(std::uint64_t now){
        if(!latest_)return std::nullopt;
        if(now<queued_ || now-queued_>100){reset();return std::nullopt;}
        if(sent_ && (now<last_sent_ || now-last_sent_<interval_))return std::nullopt;
        sent_=true;last_sent_=now;auto result=std::move(latest_);latest_.reset();return result;
    }
};

struct QueuedCommand {ipc::Message message;std::uint64_t arrived;};
// Used under the worker's existing mutex. Only consecutive pure absolute
// positions for the SAME session/transport/desktop/frame can replace a tail.
// Key/button/wheel, ACK, release, lease and consumed packets are barriers.
class WorkerCommandQueue {
    std::deque<QueuedCommand> values_;
    std::uint64_t last_sequence_=0;
    std::uint64_t rate_started_=0;unsigned rate_count_=0;bool rate_initialized_=false;
    static bool move(const ipc::Message& m){
        return m.header.kind==ipc::Kind::input && m.header.payload_bytes==24 && m.payload.size()==24 && m.payload[0]==3 &&
            m.payload[1]==0 && m.payload[2]==0 && m.payload[3]==0 &&
            std::all_of(m.payload.begin()+12,m.payload.end(),[](auto x){return x==0;});
    }
public:
    std::uint32_t coalesced=0,high_water=0;
    bool empty()const{return values_.empty();}
    bool push(ipc::Message m,std::uint64_t arrived){
        if(m.header.sequence<=last_sequence_)return false;
        // Admission is counted BEFORE coalescing. Replacing a position must
        // never make flooding bypass the original per-instance wire bound.
        if(rate_initialized_ && arrived<rate_started_)return false;
        if(!rate_initialized_ || arrived-rate_started_>=1000){rate_initialized_=true;rate_started_=arrived;rate_count_=0;}
        if(rate_count_>=ipc::control_commands_per_second)return false;++rate_count_;
        if(!values_.empty() && move(m) && move(values_.back().message)){
            const auto& old=values_.back().message.header;const auto& next=m.header;
            if(old.session==next.session && old.transport_generation==next.transport_generation &&
                old.desktop_generation==next.desktop_generation && old.frame_sequence==next.frame_sequence){
                last_sequence_=next.sequence;values_.back()={std::move(m),arrived};
                if(coalesced<UINT32_MAX)++coalesced;return true;
            }
        }
        if(values_.size()>=32)return false;
        last_sequence_=m.header.sequence;values_.push_back({std::move(m),arrived});
        high_water=std::max(high_water,static_cast<std::uint32_t>(values_.size()));return true;
    }
    std::optional<QueuedCommand> pop(){
        if(values_.empty())return std::nullopt;auto result=std::move(values_.front());values_.pop_front();return result;
    }
};
}
