#include "async_capture.hpp"
#include "latency.hpp"

namespace remote {
namespace {
struct State {
    WindowsDesktop desktop;DesktopCapture capture;std::uint64_t generation=0,retry=0;
    explicit State(LogonBinding binding):desktop(std::move(binding)){}
    CaptureResult run(CaptureRequest request){
        const auto started=monotonic_us();CaptureResult result;result.generation=request.generation;
        try{
            if(GetTickCount64()>=request.deadline){result.error=static_cast<std::uint32_t>(HRESULT_FROM_WIN32(ERROR_TIMEOUT));return result;}
            if(GetTickCount64()<retry){result.deferred=true;return result;}
            if(!desktop.input_guard(request.desktop)){
                result.error=static_cast<std::uint32_t>(HRESULT_FROM_WIN32(ERROR_INVALID_STATE));retry=GetTickCount64()+100;return result;
            }
            if(generation!=request.generation){
                capture.reset();if(GetTickCount64()<retry){result.deferred=true;return result;}
                const auto opened=capture.open(request.desktop.output);result.api=capture.diagnostic_api();result.error=static_cast<std::uint32_t>(opened);
                if(FAILED(opened)){retry=GetTickCount64()+500;return result;}
                const auto output=capture.output();if(!EqualRect(&output,&request.desktop.output)){result.error=static_cast<std::uint32_t>(HRESULT_FROM_WIN32(ERROR_INVALID_STATE));return result;}
                generation=request.generation;
            }
            if(GetTickCount64()>=request.deadline)return result;
            result.status=capture.poll(result.pixels);result.cursor=capture.take_cursor();
            result.api=capture.diagnostic_api();result.error=static_cast<std::uint32_t>(capture.diagnostic_result());
            if(GetTickCount64()>=request.deadline || !desktop.input_guard(request.desktop)){
                result.scrub();result.pixels={};result.cursor.reset();result.status=CaptureStatus::unavailable;
                result.error=static_cast<std::uint32_t>(HRESULT_FROM_WIN32(ERROR_INVALID_STATE));
            }
        }catch(const std::exception& error){
            const auto* graphics=dynamic_cast<const GraphicsFailure*>(&error);
            result.error=static_cast<std::uint32_t>(graphics?graphics->result:E_FAIL);result.api=capture.diagnostic_api();
            result.scrub();result.pixels={};result.cursor.reset();result.status=CaptureStatus::reset_required;
            capture.reset();generation=0;retry=GetTickCount64()+500;
        }
        result.elapsed_us=monotonic_us()-started;result.tick=GetTickCount64();return result;
    }
};
}
CaptureTask::Processor capture_processor(LogonBinding binding){
    auto state=std::make_shared<State>(std::move(binding));return [state](CaptureRequest request){return state->run(std::move(request));};
}
}
