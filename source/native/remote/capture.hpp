#pragma once
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>
#include <cstdint>
#include <vector>
#include <memory>
#include <optional>
#include <stdexcept>
#include "cursor.hpp"

namespace remote {
class GraphicsFailure:public std::runtime_error {
public:
    HRESULT result;
    explicit GraphicsFailure(HRESULT value):std::runtime_error("native_graphics_api_failed"),result(value){}
};
enum class CaptureStatus { frame, unchanged, reset_required, unavailable };
struct Pixels {
    unsigned width=0, height=0;
    std::vector<std::uint8_t> bgra;
};
CaptureStatus classify_acquire(HRESULT result);
Pixels readback(ID3D11Device* device, ID3D11DeviceContext* context, ID3D11Texture2D* source,
    Microsoft::WRL::ComPtr<ID3D11Texture2D>& cache);
Pixels readback(ID3D11Device* device, ID3D11DeviceContext* context, ID3D11Texture2D* source);

// Construction never accesses a desktop. The consented worker must explicitly
// call open() after checking its session, short lease, stop event and desktop.
// Select the exact guarded monitor across bounded adapters/outputs; never fall
// back to another monitor or user's desktop if that output disappears.
class GpuScale;
class DesktopCapture {
    Microsoft::WRL::ComPtr<ID3D11Device> device_;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> context_;
    Microsoft::WRL::ComPtr<IDXGIOutputDuplication> duplicate_;
    Microsoft::WRL::ComPtr<ID3D11Texture2D> staging_;
    RECT output_{};
    unsigned rotation_=0;
    CursorUpdate cursor_{},cursor_shape_{};bool cursor_dirty_=false;
    std::uint64_t shape_sequence_=0;
    std::unique_ptr<GpuScale> scale_;
    unsigned diagnostic_api_=0;
    HRESULT diagnostic_result_=S_OK;
public:
    DesktopCapture();
    ~DesktopCapture();
    HRESULT open(std::optional<RECT> requested=std::nullopt);
    CaptureStatus poll(Pixels& frame);
    void reset();
    std::optional<CursorUpdate> take_cursor();
    RECT output() const{return output_;}
    unsigned diagnostic_api() const{return diagnostic_api_;}
    HRESULT diagnostic_result() const{return diagnostic_result_;}
};
void capture_owned_texture_test();
}
