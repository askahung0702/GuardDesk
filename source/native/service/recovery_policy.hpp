#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace service_recovery {
// One bounded local record, no token, path, command or user/session data.
constexpr std::uint32_t Magic=0x31524447;
constexpr std::uint64_t Day=86400000;
enum Phase : std::uint32_t {idle=0,active=1,waiting=2,held=3};
enum Hold : std::uint32_t {none=0,security=1,exhausted=2,review=3};
struct Record {
    std::uint32_t magic=Magic,version=1,attempts=0,phase=idle,hold=none,last_error=0,first_error=0,checksum=0;
    std::uint64_t window_start=0,updated=0;
    std::array<char,24> device{};
    std::uint64_t sequence=0;
    std::array<std::uint64_t,3> retry_at{};
};
static_assert(sizeof(Record)==104,"Recovery record layout changed");
inline std::uint32_t checksum(Record value){
    value.checksum=0;std::uint32_t result=2166136261u;
    const auto* bytes=reinterpret_cast<const unsigned char*>(&value);
    for(std::size_t i=0;i<sizeof(value);++i)result=(result^bytes[i])*16777619u;
    return result;
}
inline void validate(const Record& r,const std::array<char,24>& device){
    if(r.magic!=Magic || r.version!=1 || r.device!=device || r.attempts>3 || r.phase>held || r.hold>review ||
       !r.sequence || r.checksum!=checksum(r) || !r.window_start || !r.updated ||
       r.updated<r.window_start || ((r.hold!=none)!=(r.phase==held)))
        throw std::runtime_error("recovery_record_invalid");
    for(std::size_t i=0;i<r.retry_at.size();++i){
        if(i<r.attempts){
            if(!r.retry_at[i] || r.retry_at[i]>r.updated || (i && r.retry_at[i]<r.retry_at[i-1]))
                throw std::runtime_error("recovery_retry_times_invalid");
        }else if(r.retry_at[i])throw std::runtime_error("recovery_retry_tail_invalid");
    }
}
inline void hold(Record& r,Hold reason,std::uint32_t error,std::uint64_t now){
    // Never downgrade or clear an existing hold on a later error/success.
    if(r.hold==none)r.hold=reason;
    r.phase=held;r.last_error=error;if(!r.first_error)r.first_error=error;r.updated=now;
}
inline std::uint32_t failure(Record& r,std::uint32_t error,std::uint64_t now){
    if(r.hold!=none)return 0;
    if(now<r.updated){hold(r,review,error, r.updated);return 0;}
    if(error==225 || error==226 || error==1260){hold(r,security,error,now);return 0;}
    // Access/policy/image failures require review, not repeated execution.
    if(error==2 || error==3 || error==5 || error==13 || error==193 || error==577 || error==1307 || error==1314){
        hold(r,review,error,now);return 0;}
    // Retain exact reservations in the rolling24h window; a fixed calendar
    // window could otherwise allow six retries around its reset boundary.
    std::array<std::uint64_t,3> recent{};std::uint32_t count=0;
    for(std::uint32_t i=0;i<r.attempts;++i)
        if(r.retry_at[i] && now-r.retry_at[i]<Day)recent.at(count++)=r.retry_at[i];
    r.retry_at=recent;r.attempts=count;r.window_start=count?recent[0]:now;
    r.last_error=error;if(!r.first_error)r.first_error=error;r.updated=now;
    if(r.attempts==3){hold(r,exhausted,error,now);return 0;}
    constexpr std::array<std::uint32_t,3> delays{30000,60000,300000};
    const auto delay=delays.at(r.attempts);r.retry_at.at(r.attempts++)=now;r.phase=waiting;return delay;
}
inline void stopped(Record& r,std::uint64_t now){
    if(r.hold==none)r.phase=idle;
    r.updated=now<r.updated?r.updated:now;
}
}
