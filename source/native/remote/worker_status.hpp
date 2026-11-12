#pragma once
#include <array>
#include <cstdint>
#include <limits>
#include <vector>
#include "latency.hpp"

namespace remote {
// Content-free, fixed-size diagnostic. Never contains pixels, input, paths or
// identities and never grants capture/input authority. Counters saturate.
struct WorkerStatus {
    std::uint32_t stage=0,api=0,error=0,polls=0,acquired=0,published=0,resets=0;
    std::uint32_t input_received=0,input_accepted=0,input_rejected=0,input_stale=0;
    std::uint32_t moves_coalesced=0,queue_high_water=0,queue_age_max_ms=0,command_max_ms=0;
    static constexpr std::size_t wire_bytes=384;
    enum Reason:unsigned{none=0,desktop_guard=1,desktop_change=2,capture_reset=3,input_failure=4,cleanup=5,publish_guard=6,exception=7};
    std::uint32_t last_reason=0,housekeeping=0,guard_checks=0,capture_pending=0;
    Reason pending_reason=none;
    std::array<LatencyHistogram,5> latency; // queue, command, guard, SendInput, capture
    std::array<std::uint32_t,8> reasons{};
    std::array<std::uint32_t,8> rejections{};
    std::uint32_t stale_presented_dropped=0;
    std::array<std::uint32_t,3> button_down{},key_down{}; // received, applied, rejected
    void reason(Reason why){pending_reason=why;}
    static void increment(std::uint32_t& value){if(value<(std::numeric_limits<std::uint32_t>::max)())++value;}
    std::array<std::uint8_t,wire_bytes> encode() const{
        std::array<std::uint32_t,96> values{4,stage,api,error,polls,acquired,published,resets,
            input_received,input_accepted,input_rejected,input_stale,moves_coalesced,queue_high_water,queue_age_max_ms,command_max_ms};
        values[16]=last_reason;values[17]=housekeeping;values[18]=guard_checks;values[19]=capture_pending;
        for(unsigned i=0;i<latency.size();++i){values[20+i*10]=latency[i].count;values[21+i*10]=latency[i].max_us;
            std::copy(latency[i].bins.begin(),latency[i].bins.end(),values.begin()+22+i*10);}
        std::copy(reasons.begin(),reasons.end(),values.begin()+70);
        std::copy(rejections.begin(),rejections.end(),values.begin()+78);
        values[86]=stale_presented_dropped;
        std::copy(button_down.begin(),button_down.end(),values.begin()+87);
        std::copy(key_down.begin(),key_down.end(),values.begin()+90);
        std::array<std::uint8_t,wire_bytes> bytes{};
        for(unsigned i=0;i<values.size();++i)for(unsigned j=0;j<4;++j)bytes[i*4+j]=static_cast<std::uint8_t>(values[i]>>(j*8));
        return bytes;
    }
};
inline bool valid_worker_status(const std::vector<std::uint8_t>& bytes){
    if(bytes.size()!=WorkerStatus::wire_bytes)return false;
    auto number=[&](unsigned at){std::uint32_t value=0;for(unsigned i=0;i<4;++i)value|=std::uint32_t(bytes[at+i])<<(i*8);return value;};
    const auto api=number(8);
    for(unsigned i=93;i<96;++i)if(number(i*4))return false;
    return number(0)==4 && number(4)<=13 && (api==0 || (api>=100 && api<=112)) && number(52)<=32 && number(64)<=7;
}
}
