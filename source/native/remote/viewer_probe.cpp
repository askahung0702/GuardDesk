#include "viewer.hpp"
#include <iostream>
#include <stdexcept>
#include <future>
#include <chrono>

namespace remote {
struct OwnedViewerFixture{
    static void hook(NativeViewer& viewer,std::function<void()> callback){viewer.owned_before_gpu_=std::move(callback);}
    static void busy(NativeViewer& viewer){viewer.owned_visible_=true;viewer.owned_present_=[]{return DXGI_ERROR_WAS_STILL_DRAWING;};}
    static bool queued(NativeViewer& viewer,std::uint64_t sequence){return viewer.latest_ && viewer.latest_->ticket.sequence==sequence && viewer.last_presented_==0;}
};
}

int main(){
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    HWND window=nullptr;
    try{
        // Hidden owned window: no employee screen, focus or input. Hidden
        // Present must never yield an ACK. Visible Present remains field work.
        WNDCLASSW kind{};kind.lpfnWndProc=DefWindowProcW;kind.hInstance=GetModuleHandleW(nullptr);kind.lpszClassName=L"GuardDeskOwnedHiddenRenderer";
        if(!RegisterClassW(&kind))throw std::runtime_error("owned_window_class");
        window=CreateWindowExW(0,kind.lpszClassName,L"GuardDesk owned hidden renderer",WS_OVERLAPPED,0,0,320,180,nullptr,nullptr,kind.hInstance,nullptr);
        if(!window)throw std::runtime_error("owned_window");
        remote::ipc::Session session{};session.at(0)=1;
        {
            remote::NativeViewer viewer(window,session,true);
            viewer.state(1,true);
            remote::CursorUpdate cursor;cursor.session=session;cursor.transport=1;cursor.generation=1;cursor.sequence=1;cursor.source_width=320;cursor.source_height=180;
            if(viewer.cursor(cursor) || viewer.present())throw std::runtime_error("hidden_cursor_created_authority_or_ACK");
            auto frame=[&](std::uint64_t generation,std::uint64_t sequence){
                return remote::SharedFrame{{session,generation,sequence,1,0,320,180},{320,180,std::vector<std::uint8_t>(320*180*4,71)}};
            };
            if(!viewer.submit(frame(1,1)) || viewer.present())throw std::runtime_error("hidden_window_acknowledged");
            viewer.state(2,true);
            if(viewer.submit(frame(1,2)) || !viewer.submit(frame(2,3)) || viewer.submit(frame(2,2)))throw std::runtime_error("viewer_epoch_sequence");
            viewer.state(2,false);
            if(viewer.submit(frame(2,4)) || viewer.present())throw std::runtime_error("paused_viewer_acknowledged");
            std::promise<void> entered,updated;auto entered_future=entered.get_future(),updated_future=updated.get_future();
            auto concurrent=std::async(std::launch::async,[&]{entered_future.wait();viewer.state(3,false);updated.set_value();});
            remote::OwnedViewerFixture::hook(viewer,[&]{entered.set_value();
                if(updated_future.wait_for(std::chrono::milliseconds(500))!=std::future_status::ready)throw std::runtime_error("renderer_blocks_epoch_or_stop");});
            if(viewer.present())throw std::runtime_error("paused_concurrent_ACK");concurrent.get();
        }
        {
            // Real WARP draw, injected busy Present only; never synthesize an
            // S_OK/ACK or display/read an employee screen.
            remote::NativeViewer busy(window,session,true);busy.state(1,true);
            remote::OwnedViewerFixture::busy(busy);
            auto frame=[&](std::uint64_t seq){return remote::SharedFrame{{session,1,seq,GetTickCount64(),0,320,180},{320,180,std::vector<std::uint8_t>(320*180*4,77)}};};
            if(!busy.submit(frame(1)) || busy.present() || !remote::OwnedViewerFixture::queued(busy,1))throw std::runtime_error("busy_present_lost_latest_or_ACKed");
            if(!busy.submit(frame(2)) || busy.present() || !remote::OwnedViewerFixture::queued(busy,2))throw std::runtime_error("busy_present_failed_to_coalesce_latest");
            busy.state(2,false);
            if(remote::OwnedViewerFixture::queued(busy,2) || busy.present())throw std::runtime_error("busy_retained_old_epoch_or_ACKed");
            const auto reasons=busy.diagnostics();
            if(reasons[0]!=1 || reasons[1]!=2 || reasons[4]!=2)throw std::runtime_error("display_reasons_conflated");
        }
        DestroyWindow(window);
        std::cout<<"{\"passed\":true,\"native_DXGI_HWND_renderer\":true,\"hidden_window_no_ACK\":true,\"visible_present_tested\":false,\"desktop_capture\":false,\"OS_input\":false}\n";return 0;
    }catch(const std::exception& error){if(window)DestroyWindow(window);std::cerr<<error.what()<<'\n';return 1;}
}
