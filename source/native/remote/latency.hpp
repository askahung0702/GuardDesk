#pragma once
#include <windows.h>
#include <array>
#include <cstdint>
#include <algorithm>
#include <limits>

namespace remote {
inline std::uint64_t monotonic_us(){
    LARGE_INTEGER now{},frequency{};QueryPerformanceCounter(&now);QueryPerformanceFrequency(&frequency);
    const auto f=static_cast<std::uint64_t>(frequency.QuadPart),n=static_cast<std::uint64_t>(now.QuadPart);
    return f?(n/f)*1000000+(n%f)*1000000/f:0;
}
struct LatencyHistogram {
    std::uint32_t count=0,max_us=0;std::array<std::uint32_t,8> bins{};
    static void add(std::uint32_t& value){if(value!=UINT32_MAX)++value;}
    void record(std::uint64_t us){
        constexpr std::array<std::uint64_t,7> limits{250,1000,4000,16000,32000,64000,128000};
        unsigned bucket=0;while(bucket<limits.size() && us>limits[bucket])++bucket;
        add(count);add(bins[bucket]);max_us=(std::max)(max_us,static_cast<std::uint32_t>(std::min<std::uint64_t>(us,UINT32_MAX)));
    }
};
}
