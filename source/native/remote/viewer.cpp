#include "viewer.hpp"
#include <stdexcept>

namespace remote {
namespace {
void require(bool okay,const char* reason){if(!okay)throw std::runtime_error(reason);}
void check(HRESULT result){require(SUCCEEDED(result),"native_viewer_api");}
void scrub(SharedFrame& frame){if(!frame.pixels.bgra.empty())SecureZeroMemory(frame.pixels.bgra.data(),frame.pixels.bgra.size());}
}
NativeViewer::NativeViewer(HWND window,ipc::Session session,bool software)
    :session_(session),thread_(GetCurrentThreadId()),window_(window){
    DWORD pid=0;require(IsWindow(window) && GetWindowThreadProcessId(window,&pid)==thread_ && pid==GetCurrentProcessId(),"native_viewer_window_owner");
    auto created=D3D11CreateDevice(nullptr,software?D3D_DRIVER_TYPE_WARP:D3D_DRIVER_TYPE_HARDWARE,nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT,nullptr,0,D3D11_SDK_VERSION,&device_,nullptr,&context_);
    if(FAILED(created) && !software){device_.Reset();context_.Reset();
        created=D3D11CreateDevice(nullptr,D3D_DRIVER_TYPE_WARP,nullptr,D3D11_CREATE_DEVICE_BGRA_SUPPORT,nullptr,0,D3D11_SDK_VERSION,&device_,nullptr,&context_);}
    check(created);
    Microsoft::WRL::ComPtr<IDXGIDevice> dxgi;Microsoft::WRL::ComPtr<IDXGIAdapter> adapter;
    Microsoft::WRL::ComPtr<IDXGIFactory2> factory;
    check(device_.As(&dxgi));check(dxgi->GetAdapter(&adapter));check(adapter->GetParent(IID_PPV_ARGS(&factory)));
    DXGI_SWAP_CHAIN_DESC1 description{};description.Width=1;description.Height=1;
    description.Format=DXGI_FORMAT_B8G8R8A8_UNORM;description.SampleDesc.Count=1;description.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;
    description.BufferCount=2;description.SwapEffect=DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;description.AlphaMode=DXGI_ALPHA_MODE_IGNORE;
    check(factory->CreateSwapChainForHwnd(device_.Get(),window_,&description,nullptr,nullptr,&swap_));
    check(factory->MakeWindowAssociation(window_,DXGI_MWA_NO_ALT_ENTER));
    renderer_=std::make_unique<GpuRenderer>(device_.Get(),context_.Get());
    cursor_renderer_=std::make_unique<GpuRenderer>(device_.Get(),context_.Get());
}
NativeViewer::~NativeViewer(){std::lock_guard<std::mutex> lock(mutex_);clear_pixels();context_->ClearState();context_->Flush();}
void NativeViewer::clear_pixels(){if(latest_){scrub(*latest_);latest_.reset();}}
void NativeViewer::state(std::uint64_t generation,bool active){
    std::lock_guard<std::mutex> lock(mutex_);
    if(generation<generation_)return;
    if(active_ && !active)counted(0);if(generation>generation_)counted(1);
    if(generation>generation_ || !active){clear_pixels();last_presented_=0;needs_clear_=true;cursor_.reset();cursor_sequence_=cursor_tick_=0;cursor_dirty_=false;}
    generation_=generation;active_=active && generation!=0;
}
bool NativeViewer::submit(SharedFrame frame){
    std::lock_guard<std::mutex> lock(mutex_);
    const auto& ticket=frame.ticket;
    if(!active_ || ticket.session!=session_ || ticket.generation!=generation_ || ticket.sequence<=last_received_ ||
        ticket.width!=frame.pixels.width || ticket.height!=frame.pixels.height || !ticket.width || !ticket.height ||
        ticket.width>8192 || ticket.height>8192 || std::uint64_t(ticket.width)*ticket.height>16777216 ||
        frame.pixels.bgra.size()!=std::size_t(ticket.width)*ticket.height*4){scrub(frame);return false;}
    clear_pixels();last_received_=ticket.sequence;latest_=std::move(frame);return true;
}
bool NativeViewer::cursor(CursorUpdate value){
    std::lock_guard<std::mutex> lock(mutex_);
    if(!active_ || !last_presented_ || value.session!=session_ || value.generation!=generation_ || value.sequence<=cursor_sequence_ ||
        value.source_width!=displayed_width_ || value.source_height!=displayed_height_)return false;
    if(value.mode==CursorMode::separate && value.bgra.empty()){
        if(!cursor_ || cursor_->mode!=CursorMode::separate || cursor_->shape!=value.shape || cursor_->width!=value.width || cursor_->height!=value.height)return false;
        value.bgra=cursor_->bgra;
    }
    cursor_sequence_=value.sequence;cursor_tick_=GetTickCount64();cursor_=std::move(value);cursor_dirty_=true;return true;
}
std::optional<FrameTicket> NativeViewer::present(){
    require(GetCurrentThreadId()==thread_,"native_viewer_UI_thread");
    // Snapshot/move the latest frame under a short lock. GPU allocation,
    // ResizeBuffers, draw and Present run outside it: a slow driver must never
    // block signaling, epoch invalidation, stop or the decoder's latest slot.
    std::optional<SharedFrame> queued;std::optional<CursorUpdate> pointer;std::uint64_t generation=0;bool active=false,needs_clear=false,pointer_dirty=false;std::uint64_t last_presented=0;
    {
        std::lock_guard<std::mutex> lock(mutex_);generation=generation_;active=active_;needs_clear=needs_clear_;last_presented=last_presented_;
        if(cursor_ && GetTickCount64()-cursor_tick_<=1000)pointer=cursor_;
        else if(cursor_){cursor_.reset();cursor_dirty_=true;}
        pointer_dirty=cursor_dirty_;cursor_dirty_=false;
        if(latest_){queued=std::move(latest_);latest_.reset();}
    }
#ifdef GUARDDESK_OWNED_VIEWER_FIXTURES
    if(owned_before_gpu_)owned_before_gpu_();
#endif
    RECT client{};require(GetClientRect(window_,&client)!=FALSE,"native_viewer_client");
    const auto width=client.right-client.left,height=client.bottom-client.top;
    bool visible=IsWindowVisible(window_) && !IsIconic(window_);
#ifdef GUARDDESK_OWNED_VIEWER_FIXTURES
    visible=visible || owned_visible_; // test-only hidden synthetic GPU surface
#endif
    if(width<=0 || height<=0 || width>8192 || height>8192 || !visible){
        if(last_presented)counted(2);
        if(queued)scrub(*queued);renderer_->clear();
        std::lock_guard<std::mutex> lock(mutex_);clear_pixels();last_presented_=0;needs_clear_=true;cursor_.reset();return std::nullopt;
    }
    if(width_!=static_cast<unsigned>(width) || height_!=static_cast<unsigned>(height)){
        counted(3);
        context_->OMSetRenderTargets(0,nullptr,nullptr);
        const auto resized=swap_->ResizeBuffers(0,static_cast<UINT>(width),static_cast<UINT>(height),DXGI_FORMAT_UNKNOWN,0);
        if(FAILED(resized)){
            if(queued)scrub(*queued);std::lock_guard<std::mutex> lock(mutex_);clear_pixels();last_presented_=0;throw std::runtime_error("native_viewer_resize");
        }
        width_=width;height_=height;
    }
    if(!active || (!queued && (!pointer_dirty || !last_presented))){
        if(!needs_clear)return std::nullopt;
        renderer_->clear();
        Microsoft::WRL::ComPtr<ID3D11Texture2D> back;Microsoft::WRL::ComPtr<ID3D11RenderTargetView> target;
        check(swap_->GetBuffer(0,IID_PPV_ARGS(&back)));check(device_->CreateRenderTargetView(back.Get(),nullptr,&target));
        const float black[]{0,0,0,1};context_->ClearRenderTargetView(target.Get(),black);
        if(swap_->Present(0,DXGI_PRESENT_DO_NOT_WAIT)==S_OK){std::lock_guard<std::mutex> lock(mutex_);
            if(generation==generation_ && active==active_)needs_clear_=false;}
        return std::nullopt;
    }
    const bool actual_frame=queued.has_value();
    SharedFrame frame;if(queued){frame=std::move(*queued);queued.reset();}
    struct Scrub{SharedFrame& frame;~Scrub(){scrub(frame);}} scrub_frame{frame};
    Microsoft::WRL::ComPtr<ID3D11Texture2D> back;Microsoft::WRL::ComPtr<ID3D11RenderTargetView> target;
    check(swap_->GetBuffer(0,IID_PPV_ARGS(&back)));check(device_->CreateRenderTargetView(back.Get(),nullptr,&target));
    if(actual_frame)renderer_->draw(frame.pixels,target.Get(),width_,height_);else renderer_->draw_cached(target.Get(),width_,height_);
    if(pointer && pointer->mode==CursorMode::separate){
        const float scale=std::min(float(width_)/pointer->source_width,float(height_)/pointer->source_height);
        D3D11_VIEWPORT viewport{};viewport.Width=pointer->width*scale;viewport.Height=pointer->height*scale;viewport.MaxDepth=1;
        viewport.TopLeftX=(width_-pointer->source_width*scale)*.5f+(pointer->x-static_cast<int>(pointer->hot_x))*scale;
        viewport.TopLeftY=(height_-pointer->source_height*scale)*.5f+(pointer->y-static_cast<int>(pointer->hot_y))*scale;
        cursor_renderer_->overlay({pointer->width,pointer->height,pointer->bgra},target.Get(),viewport);
    }
    auto result=DXGI_ERROR_WAS_STILL_DRAWING;
#ifdef GUARDDESK_OWNED_VIEWER_FIXTURES
    if(owned_present_)result=owned_present_();else
#endif
    result=swap_->Present(0,DXGI_PRESENT_DO_NOT_WAIT);
    if(result==DXGI_ERROR_WAS_STILL_DRAWING){
        counted(4);
        std::lock_guard<std::mutex> lock(mutex_);
        // Retry only the latest same-epoch pixels; never ACK a failed Present
        // or replace a newer frame that arrived during GPU work.
        if(generation==generation_ && active_){
            if(actual_frame && (!latest_ || latest_->ticket.sequence<frame.ticket.sequence))latest_=std::move(frame);
            cursor_dirty_=true;
        }
        return std::nullopt;
    }
    if(result==DXGI_STATUS_OCCLUDED){counted(5);std::lock_guard<std::mutex> lock(mutex_);last_presented_=0;return std::nullopt;}
    if(FAILED(result))counted(6);
    check(result);
    std::lock_guard<std::mutex> lock(mutex_);
    if(generation!=generation_ || !active_){counted(7);return std::nullopt;}
    needs_clear_=false;
    if(!actual_frame || frame.ticket.generation!=generation_ || !active_)return std::nullopt;
    displayed_width_=frame.ticket.width;displayed_height_=frame.ticket.height;
    last_presented_=frame.ticket.sequence;return frame.ticket;
}
}
