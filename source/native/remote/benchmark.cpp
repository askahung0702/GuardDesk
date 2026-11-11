// Bounded synthetic media measurement. No desktop, input, sockets or file output.
#include "benchmark.hpp"
#include "codec.hpp"
#include <mfapi.h>
#include <psapi.h>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <stdexcept>

namespace remote {
namespace {
using Clock=std::chrono::steady_clock;
double milliseconds(Clock::duration value) {return std::chrono::duration<double,std::milli>(value).count();}
double percentile(std::vector<double> values,unsigned percent) {
    if(values.empty()) throw std::runtime_error("benchmark_missing_samples");
    std::sort(values.begin(),values.end());return values[(values.size()-1)*percent/100];
}
std::uint64_t cpu_time() {
    FILETIME created{},exited{},kernel{},user{};
    if(!GetProcessTimes(GetCurrentProcess(),&created,&exited,&kernel,&user)) throw std::runtime_error("benchmark_cpu_api");
    ULARGE_INTEGER k{},u{};k.LowPart=kernel.dwLowDateTime;k.HighPart=kernel.dwHighDateTime;
    u.LowPart=user.dwLowDateTime;u.HighPart=user.dwHighDateTime;return k.QuadPart+u.QuadPart;
}
}
int synthetic_benchmark() {
    constexpr unsigned width=1920,height=1080,frames=60;
    if(FAILED(CoInitializeEx(nullptr,COINIT_MULTITHREADED))) throw std::runtime_error("benchmark_com");
    struct ComEnd {~ComEnd(){CoUninitialize();}} com_end;
    if(FAILED(MFStartup(MF_VERSION))) throw std::runtime_error("benchmark_mf");
    struct MfEnd {~MfEnd(){MFShutdown();}} mf_end;
    H264Encoder encoder(width,height,30,4000000);H264Decoder decoder(width,height);
    std::vector<std::uint8_t> nv12(std::size_t(width)*height*3/2,128);
    std::vector<double> encode,decode;encode.reserve(frames);decode.reserve(frames);
    std::uint64_t bytes=0,decoded=0;const auto cpu_start=cpu_time();const auto start=Clock::now();
    for(unsigned frame=0;frame<frames;++frame) {
        // Own luma grid and moving rectangle, intentionally not an Office score.
        for(unsigned y=0;y<height;++y) for(unsigned x=0;x<width;++x) {
            const bool moving=x>=frame*8 && x<frame*8+160 && y<80;
            nv12[std::size_t(y)*width+x]=static_cast<std::uint8_t>(moving?180:(x%80<2 || y%24<2?32:220));
        }
        auto stamp=Clock::now();auto packet=encoder.encode(nv12,frame==0);
        encode.push_back(milliseconds(Clock::now()-stamp));bytes+=packet.size();
        if(!packet.empty()) {
            stamp=Clock::now();auto image=decoder.decode(packet);decode.push_back(milliseconds(Clock::now()-stamp));
            if(!image.empty()) {if(image.size()!=nv12.size()) throw std::runtime_error("benchmark_decoded_size");++decoded;}
        }
    }
    const auto tail=encoder.drain();bytes+=tail.size();
    if(!tail.empty() && !decoder.decode(tail).empty()) ++decoded;
    const auto elapsed=milliseconds(Clock::now()-start);const auto cpu_ms=(cpu_time()-cpu_start)/10000.0;
    PROCESS_MEMORY_COUNTERS_EX memory{};memory.cb=sizeof(memory);
    if(!GetProcessMemoryInfo(GetCurrentProcess(),reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory),sizeof(memory)))
        throw std::runtime_error("benchmark_memory_api");
    if(decoded==0) throw std::runtime_error("benchmark_no_decoded_frames");
    std::cout<<"{\"synthetic_only\":true,\"desktop_capture\":false,\"os_input\":false,\"network\":false,"
        <<"\"codec\":\"Microsoft-MF-software-H264\",\"width\":"<<width<<",\"height\":"<<height
        <<",\"frames_submitted\":"<<frames<<",\"frames_decoded\":"<<decoded<<",\"encoded_bytes\":"<<bytes
        <<",\"elapsed_ms\":"<<elapsed<<",\"throughput_fps\":"<<frames*1000.0/elapsed
        <<",\"encode_p50_ms\":"<<percentile(encode,50)<<",\"encode_p95_ms\":"<<percentile(encode,95)
        <<",\"decode_p50_ms\":"<<percentile(decode,50)<<",\"decode_p95_ms\":"<<percentile(decode,95)
        <<",\"cpu_ms\":"<<cpu_ms<<",\"peak_working_set_bytes\":"<<memory.PeakWorkingSetSize
        <<",\"private_bytes\":"<<memory.PrivateUsage<<"}\n";
    return 0;
}
}
