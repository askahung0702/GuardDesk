#pragma once
#include "latest_task.hpp"
#include "windows_desktop.hpp"

namespace remote {
struct CaptureRequest {DesktopObservation desktop;std::uint64_t generation=0,deadline=0;};
struct CaptureResult {
    std::uint64_t generation=0,elapsed_us=0,tick=0;CaptureStatus status=CaptureStatus::unavailable;bool deferred=false;
    std::uint32_t api=0,error=0;Pixels pixels;std::optional<CursorUpdate> cursor;
    CaptureResult()=default;CaptureResult(const CaptureResult&)=delete;CaptureResult& operator=(const CaptureResult&)=delete;
    CaptureResult(CaptureResult&&)=default;
    CaptureResult& operator=(CaptureResult&& other){
        scrub();generation=other.generation;elapsed_us=other.elapsed_us;tick=other.tick;deferred=other.deferred;status=other.status;api=other.api;error=other.error;
        pixels=std::move(other.pixels);cursor=std::move(other.cursor);return *this;
    }
    ~CaptureResult(){scrub();}
    void scrub(){if(!pixels.bgra.empty())SecureZeroMemory(pixels.bgra.data(),pixels.bgra.size());}
};
using CaptureTask=LatestTask<CaptureRequest,CaptureResult>;
CaptureTask::Processor capture_processor(LogonBinding binding);
}
