#include "display_geometry.hpp"
#include "windows_desktop.hpp"
#include "latest_task.hpp"
#include <dxgi1_2.h>
#include <wrl/client.h>
#include <iostream>
#include <memory>
#include <stdexcept>
namespace {
void need(bool v,const char* why){if(!v)throw std::runtime_error(why);}
void layouts(){
    using remote::valid_display_geometry;const RECT main{0,0,1920,1080};
    need(valid_display_geometry(main,{0,0,3840,1080}),"right_monitor");
    need(valid_display_geometry(main,{-2560,-1440,1920,1080}),"negative_monitor");
    need(valid_display_geometry({0,0,1080,1920},{-1920,0,1080,1920}),"portrait_primary");
    need(valid_display_geometry({0,0,3840,2160},{0,-2160,3840,2160}),"4K_primary");
    need(!valid_display_geometry(main,{0,0,1280,720}),"DPI_mismatch_accepted");
    need(!valid_display_geometry({0,0,9000,1080},{0,0,9000,1080}),"pixel_bound_lost");
    need(!valid_display_geometry({0,0,0,0},{0,0,1920,1080}),"headless_accepted");
}
}
int main(){try{
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);layouts();
    struct Info {RECT output{},screen{};int awareness=-1,inherited=-1;};
    const auto previous=SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_UNAWARE);need(previous!=nullptr,"fixture_unaware_context");
    // Real capture-task thread boundary, metadata only, no duplication/pixels.
    remote::LatestTask<unsigned,Info> task([]{const int inherited=GetAwarenessFromDpiAwarenessContext(GetThreadDpiAwarenessContext());DWORD session=0;need(ProcessIdToSessionId(GetCurrentProcessId(),&session)!=FALSE,"owned_session_id");
        auto dpi=std::make_shared<remote::WindowsDesktop>(remote::LogonBinding{session,1,1,1,L"owned-noncredential-binding",false});
        return [dpi,inherited](unsigned){Info v;v.inherited=inherited;need(remote::primary_display_geometry(v.output,v.screen),"physical_primary_geometry");
            v.awareness=GetAwarenessFromDpiAwarenessContext(GetThreadDpiAwarenessContext());return v;};});
    task.submit(1);need(WaitForSingleObject(task.ready_event(),5000)==WAIT_OBJECT_0,"metadata_task_timeout");
    auto value=task.take();need(value && value->awareness==DPI_AWARENESS_PER_MONITOR_AWARE,"capture_thread_not_physical");
    need(AreDpiAwarenessContextsEqual(GetThreadDpiAwarenessContext(),DPI_AWARENESS_CONTEXT_UNAWARE)!=FALSE,"caller_DPI_changed");
    need(SetThreadDpiAwarenessContext(previous)!=nullptr,"fixture_DPI_restore");
    remote::PhysicalPixelScope physical;RECT output{},screen{};
    need(remote::primary_display_geometry(output,screen) && EqualRect(&output,&value->output) && EqualRect(&screen,&value->screen),"capture_and_owner_geometry_differ");
    Microsoft::WRL::ComPtr<IDXGIFactory1> factory;need(SUCCEEDED(CreateDXGIFactory1(IID_PPV_ARGS(&factory))),"DXGI_metadata_factory");
    bool found=false;unsigned ai=0,oi=0;
    for(unsigned a=0;a<16 && !found;++a){Microsoft::WRL::ComPtr<IDXGIAdapter1> adapter;if(factory->EnumAdapters1(a,&adapter)==DXGI_ERROR_NOT_FOUND)break;need(adapter!=nullptr,"metadata_adapter");
        for(unsigned o=0;o<32;++o){Microsoft::WRL::ComPtr<IDXGIOutput> candidate;if(adapter->EnumOutputs(o,&candidate)==DXGI_ERROR_NOT_FOUND)break;need(candidate!=nullptr,"metadata_output");DXGI_OUTPUT_DESC d{};need(SUCCEEDED(candidate->GetDesc(&d)),"metadata_description");
            if(d.AttachedToDesktop && EqualRect(&d.DesktopCoordinates,&output)){found=true;ai=a;oi=o;break;}}}
    need(found,"primary_output_not_matched");
    std::cout<<"{\"passed\":true,\"monitor_count\":"<<GetSystemMetrics(SM_CMONITORS)<<",\"primary_width\":"<<output.right-output.left<<",\"primary_height\":"<<output.bottom-output.top
        <<",\"virtual_width\":"<<screen.right-screen.left<<",\"virtual_height\":"<<screen.bottom-screen.top<<",\"adapter\":"<<ai<<",\"output\":"<<oi
        <<",\"inherited_thread_awareness\":"<<value->inherited<<",\"capture_thread_awareness\":"<<value->awareness<<",\"metadata_only\":true,\"desktop_pixels_read\":false,\"OS_input\":false,\"SYSTEM_boundary\":false}\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
