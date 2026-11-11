#pragma once
#include "frame_pool.hpp"
#include "render.hpp"
#include <dxgi1_2.h>
#include <memory>
#include <optional>
#include <functional>
#include <atomic>

namespace remote {
// UI-thread renderer. submit/state may run on the authenticated media callback;
// only one latest frame waits for the UI. No per-frame Tk/Pillow conversion.
class NativeViewer {
#ifdef GUARDDESK_OWNED_VIEWER_FIXTURES
    friend struct OwnedViewerFixture;
    std::function<void()> owned_before_gpu_;
    std::function<HRESULT()> owned_present_;
    bool owned_visible_=false;
#endif
    ipc::Session session_;
    DWORD thread_;
    HWND window_;
    std::uint64_t generation_=0,last_received_=0,last_presented_=0;
    bool active_=false;
    bool needs_clear_=true;
    std::mutex mutex_;
    std::optional<SharedFrame> latest_;
    std::optional<CursorUpdate> cursor_;
    std::uint64_t cursor_sequence_=0,cursor_tick_=0;bool cursor_dirty_=false;
    unsigned displayed_width_=0,displayed_height_=0;
    Microsoft::WRL::ComPtr<ID3D11Device> device_;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> context_;
    Microsoft::WRL::ComPtr<IDXGISwapChain1> swap_;
    std::unique_ptr<GpuRenderer> renderer_,cursor_renderer_;
    unsigned width_=0,height_=0;
    std::array<std::atomic<std::uint32_t>,8> diagnostics_{};
    void counted(unsigned code){auto& value=diagnostics_.at(code);auto old=value.load();while(old!=UINT32_MAX && !value.compare_exchange_weak(old,old+1)){} }
    void clear_pixels();
public:
    NativeViewer(HWND own_window,ipc::Session session,bool software_fallback=false);
    ~NativeViewer();
    void state(std::uint64_t generation,bool active);
    bool submit(SharedFrame frame);
    bool cursor(CursorUpdate cursor);
    // An ACK is returned only after Present succeeds on a visible, non-iconic
    // window and its desktop generation is still current. Occlusion, resize,
    // device loss and pause do not acknowledge an unseen frame.
    std::optional<FrameTicket> present();
    // pause, epoch, hidden, resize, GPU busy, occluded, Present error, stale result
    std::array<std::uint32_t,8> diagnostics()const{std::array<std::uint32_t,8> result{};for(unsigned i=0;i<result.size();++i)result[i]=diagnostics_[i].load();return result;}
};
}
