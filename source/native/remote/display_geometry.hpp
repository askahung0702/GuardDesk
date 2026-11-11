#pragma once
#include <windows.h>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace remote {
// Thread-local: LatestTask constructs/destroys WindowsDesktop on its own
// thread. Never change the process-wide mode or a user's display settings.
class PhysicalPixelScope {
    DPI_AWARENESS_CONTEXT previous_=nullptr;
public:
    PhysicalPixelScope(){
        previous_=SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        if(!previous_)throw std::runtime_error("desktop_physical_DPI_context");
    }
    ~PhysicalPixelScope(){if(previous_ && !SetThreadDpiAwarenessContext(previous_))TerminateProcess(GetCurrentProcess(),0xe0000096u);}
    PhysicalPixelScope(const PhysicalPixelScope&)=delete;
    PhysicalPixelScope& operator=(const PhysicalPixelScope&)=delete;
};
inline bool valid_display_geometry(const RECT& output,const RECT& screen){
    const auto width=std::int64_t(output.right)-output.left,height=std::int64_t(output.bottom)-output.top;
    const auto sw=std::int64_t(screen.right)-screen.left,sh=std::int64_t(screen.bottom)-screen.top;
    return width>=2 && height>=2 && width<=8192 && height<=8192 && width*height<=16777216 &&
        sw>=width && sh>=height && output.left>=screen.left && output.top>=screen.top && output.right<=screen.right && output.bottom<=screen.bottom;
}
inline bool primary_display_geometry(RECT& output,RECT& screen){
    const auto monitor=MonitorFromPoint({0,0},MONITOR_DEFAULTTOPRIMARY);
    MONITORINFO info{sizeof(info)};
    if(!monitor || !GetMonitorInfoW(monitor,&info) || !(info.dwFlags&MONITORINFOF_PRIMARY))return false;
    const auto left=GetSystemMetrics(SM_XVIRTUALSCREEN),top=GetSystemMetrics(SM_YVIRTUALSCREEN);
    const auto right=std::int64_t(left)+GetSystemMetrics(SM_CXVIRTUALSCREEN),bottom=std::int64_t(top)+GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if(right>std::numeric_limits<LONG>::max() || bottom>std::numeric_limits<LONG>::max())return false;
    output=info.rcMonitor;screen={left,top,static_cast<LONG>(right),static_cast<LONG>(bottom)};
    return valid_display_geometry(output,screen);
}
}
