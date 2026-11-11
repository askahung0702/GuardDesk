#include "capture.hpp"
#include "gpu_scale.hpp"
#include "display_geometry.hpp"
#include <cstring>
#include <stdexcept>

namespace remote {
using Microsoft::WRL::ComPtr;
namespace {
void check(HRESULT result) {
    if(FAILED(result)) throw GraphicsFailure(result);
}
std::size_t bytes(unsigned width,unsigned height) {
    if(width==0 || height==0 || width>8192 || height>8192 || std::uint64_t(width)*height>16777216)
        throw std::invalid_argument("capture_dimensions");
    return std::size_t(width)*height*4;
}
}

CaptureStatus classify_acquire(HRESULT result) {
    if(result==DXGI_ERROR_WAIT_TIMEOUT) return CaptureStatus::unchanged;
    if(result==DXGI_ERROR_ACCESS_LOST) return CaptureStatus::reset_required;
    if(FAILED(result)) return CaptureStatus::unavailable;
    return CaptureStatus::frame;
}

Pixels readback(ID3D11Device* device,ID3D11DeviceContext* context,ID3D11Texture2D* source,ComPtr<ID3D11Texture2D>& cache) {
    if(!device || !context || !source) throw std::invalid_argument("capture_resource");
    D3D11_TEXTURE2D_DESC desc{};source->GetDesc(&desc);
    const auto length=bytes(desc.Width,desc.Height);
    if(desc.Format!=DXGI_FORMAT_B8G8R8A8_UNORM || desc.SampleDesc.Count!=1 || desc.ArraySize!=1 || desc.MipLevels!=1)
        throw std::invalid_argument("capture_format");
    D3D11_TEXTURE2D_DESC staging_desc=desc;
    staging_desc.Usage=D3D11_USAGE_STAGING;staging_desc.BindFlags=0;
    staging_desc.CPUAccessFlags=D3D11_CPU_ACCESS_READ;staging_desc.MiscFlags=0;
    ComPtr<ID3D11Texture2D> staging;
    if(cache) {
        D3D11_TEXTURE2D_DESC previous{};cache->GetDesc(&previous);
        if(previous.Width==desc.Width && previous.Height==desc.Height && previous.Format==desc.Format) staging=cache;
    }
    if(!staging) {
        check(device->CreateTexture2D(&staging_desc,nullptr,&staging));
        cache=staging;
    }
    context->CopyResource(staging.Get(),source);
    D3D11_MAPPED_SUBRESOURCE mapped{};
    check(context->Map(staging.Get(),0,D3D11_MAP_READ,0,&mapped));
    // Unmap also on allocation failure. Do not expose GPU row padding.
    struct Unmap {
        ID3D11DeviceContext* context;ID3D11Texture2D* texture;
        ~Unmap(){context->Unmap(texture,0);}
    } unmap{context,staging.Get()};
    const std::size_t row=std::size_t(desc.Width)*4;
    if(!mapped.pData || mapped.RowPitch<row) throw std::runtime_error("capture_pitch");
    Pixels result{desc.Width,desc.Height,std::vector<std::uint8_t>(length)};
    for(unsigned y=0;y<desc.Height;++y)
        std::memcpy(result.bgra.data()+y*row,static_cast<const std::uint8_t*>(mapped.pData)+std::size_t(y)*mapped.RowPitch,row);
    return result;
}
Pixels readback(ID3D11Device* device,ID3D11DeviceContext* context,ID3D11Texture2D* source){
    ComPtr<ID3D11Texture2D> cache;return readback(device,context,source,cache);
}

DesktopCapture::DesktopCapture()=default;
DesktopCapture::~DesktopCapture()=default;
HRESULT DesktopCapture::open(std::optional<RECT> requested) {
    reset();diagnostic_result_=S_OK;diagnostic_api_=100;
    ComPtr<IDXGIFactory1> factory;ComPtr<IDXGIAdapter1> adapter;
    ComPtr<IDXGIOutput> output;ComPtr<IDXGIOutput1> output1;
    HRESULT result=CreateDXGIFactory1(IID_PPV_ARGS(&factory));
    if(FAILED(result)){diagnostic_result_=result;return result;}
    RECT wanted{},screen{};
    if(!primary_display_geometry(wanted,screen) || (requested && !EqualRect(&wanted,&*requested))){diagnostic_result_=DXGI_ERROR_NOT_FOUND;return diagnostic_result_;}
    const auto monitor=MonitorFromRect(&wanted,MONITOR_DEFAULTTONULL);DXGI_OUTPUT_DESC desc{};bool found=false;
    for(unsigned a=0;a<16 && !found;++a){
        diagnostic_api_=101;adapter.Reset();result=factory->EnumAdapters1(a,&adapter);
        if(result==DXGI_ERROR_NOT_FOUND)break;
        if(FAILED(result)){diagnostic_result_=result;return result;}
        for(unsigned o=0;o<32;++o){
            diagnostic_api_=102;output.Reset();result=adapter->EnumOutputs(o,&output);
            if(result==DXGI_ERROR_NOT_FOUND)break;
            if(FAILED(result)){diagnostic_result_=result;return result;}
            diagnostic_api_=103;result=output->GetDesc(&desc);
            if(FAILED(result)){diagnostic_result_=result;return result;}
            if(desc.AttachedToDesktop && desc.Monitor==monitor && EqualRect(&desc.DesktopCoordinates,&wanted)){found=true;break;}
        }
    }
    if(!found || desc.Rotation<DXGI_MODE_ROTATION_IDENTITY || desc.Rotation>DXGI_MODE_ROTATION_ROTATE270){diagnostic_result_=DXGI_ERROR_UNSUPPORTED;return diagnostic_result_;}
    rotation_=static_cast<unsigned>(desc.Rotation)-static_cast<unsigned>(DXGI_MODE_ROTATION_IDENTITY);
    output_=desc.DesktopCoordinates;
    diagnostic_api_=104;result=D3D11CreateDevice(adapter.Get(),D3D_DRIVER_TYPE_UNKNOWN,nullptr,D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        nullptr,0,D3D11_SDK_VERSION,&device_,nullptr,&context_);
    if(FAILED(result)) {reset();diagnostic_result_=result;return result;}
    diagnostic_api_=105;result=output.As(&output1);
    if(SUCCEEDED(result)){diagnostic_api_=106;result=output1->DuplicateOutput(device_.Get(),&duplicate_);}
    if(FAILED(result)) reset();
    else {diagnostic_api_=107;scale_=std::make_unique<GpuScale>(device_.Get(),context_.Get());}
    diagnostic_result_=result;return result;
}

CaptureStatus DesktopCapture::poll(Pixels& frame) {
    if(!duplicate_) return CaptureStatus::reset_required;
    DXGI_OUTDUPL_FRAME_INFO info{};ComPtr<IDXGIResource> resource;
    diagnostic_api_=108;const HRESULT result=duplicate_->AcquireNextFrame(0,&info,&resource);
    diagnostic_result_=result;const auto status=classify_acquire(result);
    if(status==CaptureStatus::reset_required) reset();
    if(status!=CaptureStatus::frame) return status;
    // Every successful Acquire, including pointer-only updates and exceptions,
    // releases exactly once. No Acquire is issued while a frame is retained.
    struct Release {
        IDXGIOutputDuplication* duplicate;
        ~Release(){duplicate->ReleaseFrame();}
    } release{duplicate_.Get()};
    diagnostic_api_=109;
    if(info.LastMouseUpdateTime.QuadPart || info.PointerShapeBufferSize){
        cursor_dirty_=true;cursor_=cursor_shape_;cursor_.source_width=output_.right-output_.left;cursor_.source_height=output_.bottom-output_.top;
        cursor_.x=info.PointerPosition.Position.x;cursor_.y=info.PointerPosition.Position.y;
        if(info.PointerShapeBufferSize){
            if(info.PointerShapeBufferSize>cursor_max_pixels*2){cursor_.mode=CursorMode::unsupported;cursor_.bgra.clear();cursor_.xor_mask.clear();cursor_.width=cursor_.height=cursor_.hot_x=cursor_.hot_y=0;cursor_.shape=0;}
            else {std::vector<std::uint8_t> bytes(info.PointerShapeBufferSize);UINT required=0;DXGI_OUTDUPL_POINTER_SHAPE_INFO shape{};
                const auto result_shape=duplicate_->GetFramePointerShape(static_cast<UINT>(bytes.size()),bytes.data(),&required,&shape);
                if(SUCCEEDED(result_shape) && required<=bytes.size()){
                    bytes.resize(required);convert_cursor_shape(cursor_,shape.Type,shape.Width,shape.Height,shape.Pitch,shape.HotSpot.x,shape.HotSpot.y,bytes);
                    if(cursor_.mode==CursorMode::separate)cursor_.shape=++shape_sequence_;
                }else {cursor_.mode=CursorMode::unsupported;cursor_.bgra.clear();cursor_.xor_mask.clear();cursor_.width=cursor_.height=cursor_.hot_x=cursor_.hot_y=0;cursor_.shape=0;}}
        }
        cursor_shape_=cursor_;
        if(!info.PointerPosition.Visible){cursor_.mode=CursorMode::hidden;cursor_.x=cursor_.y=0;cursor_.bgra.clear();cursor_.xor_mask.clear();cursor_.width=cursor_.height=cursor_.hot_x=cursor_.hot_y=0;cursor_.shape=0;}
        else if(cursor_.mode==CursorMode::separate){cursor_.x+=static_cast<int>(cursor_.hot_x);cursor_.y+=static_cast<int>(cursor_.hot_y);}
        else if(cursor_.mode==CursorMode::hidden)cursor_.mode=CursorMode::unsupported;
        if(rotation_){
            // DXGI's pointer position belongs to the unrotated surface. The
            // current desktop cursor hotspot is already physical/oriented.
            CURSORINFO pointer{sizeof(pointer)};
            if(GetCursorInfo(&pointer)){
                cursor_.x=pointer.ptScreenPos.x-output_.left;cursor_.y=pointer.ptScreenPos.y-output_.top;
                if(!(pointer.flags&CURSOR_SHOWING) || cursor_.x<0 || cursor_.y<0 || cursor_.x>=output_.right-output_.left || cursor_.y>=output_.bottom-output_.top){cursor_.mode=CursorMode::hidden;cursor_.x=cursor_.y=0;cursor_.bgra.clear();cursor_.xor_mask.clear();cursor_.width=cursor_.height=cursor_.hot_x=cursor_.hot_y=0;cursor_.shape=0;}
            }else{cursor_.mode=CursorMode::unsupported;cursor_.bgra.clear();cursor_.xor_mask.clear();cursor_.width=cursor_.height=cursor_.hot_x=cursor_.hot_y=0;cursor_.shape=0;}
        }
    }
    if(info.LastPresentTime.QuadPart==0) return CaptureStatus::unchanged;
    diagnostic_api_=110;ComPtr<ID3D11Texture2D> texture;check(resource.As(&texture));
    diagnostic_api_=111;auto scaled=scale_->fit(texture.Get(),rotation_);diagnostic_api_=112;frame=readback(device_.Get(),context_.Get(),scaled.Get(),staging_);
    return CaptureStatus::frame;
}

std::optional<CursorUpdate> DesktopCapture::take_cursor(){if(!cursor_dirty_)return std::nullopt;cursor_dirty_=false;return cursor_;}
void DesktopCapture::reset() {
    cursor_={};cursor_shape_={};cursor_dirty_=false;shape_sequence_=0;
    duplicate_.Reset();scale_.reset();staging_.Reset();context_.Reset();device_.Reset();output_={};rotation_=0;
}

void capture_owned_texture_test() {
    ComPtr<ID3D11Device> device;ComPtr<ID3D11DeviceContext> context;
    check(D3D11CreateDevice(nullptr,D3D_DRIVER_TYPE_WARP,nullptr,0,nullptr,0,D3D11_SDK_VERSION,&device,nullptr,&context));
    // Odd width deliberately exercises real D3D row pitch. Synthetic pixels
    // never come from an output/window/screenshot.
    constexpr unsigned width=319,height=181;
    std::vector<std::uint8_t> pattern(std::size_t(width)*height*4);
    for(std::size_t i=0;i<pattern.size();++i) pattern[i]=static_cast<std::uint8_t>((i*13+7)%256);
    D3D11_TEXTURE2D_DESC desc{};desc.Width=width;desc.Height=height;
    desc.MipLevels=1;desc.ArraySize=1;desc.Format=DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count=1;desc.Usage=D3D11_USAGE_DEFAULT;
    D3D11_SUBRESOURCE_DATA data{pattern.data(),width*4,0};ComPtr<ID3D11Texture2D> texture;
    check(device->CreateTexture2D(&desc,&data,&texture));
    ComPtr<ID3D11Texture2D> cache;
    auto result=readback(device.Get(),context.Get(),texture.Get(),cache);
    // Retain the original resource so allocator address reuse cannot make a
    // newly allocated texture look like a reused cache in this regression.
    ComPtr<ID3D11Texture2D> original=cache;
    result=readback(device.Get(),context.Get(),texture.Get(),cache);
    if(cache.Get()!=original.Get()) throw std::runtime_error("staging_cache_not_reused");
    if(result.width!=width || result.height!=height || result.bgra!=pattern)
        throw std::runtime_error("owned_texture_readback");
    // A display-size change must replace the cache and preserve new pixels.
    constexpr unsigned resized_width=321;
    desc.Width=resized_width;std::vector<std::uint8_t> resized_pattern(std::size_t(resized_width)*height*4,93);
    data.pSysMem=resized_pattern.data();data.SysMemPitch=resized_width*4;
    ComPtr<ID3D11Texture2D> resized;check(device->CreateTexture2D(&desc,&data,&resized));
    result=readback(device.Get(),context.Get(),resized.Get(),cache);
    if(cache.Get()==original.Get() || result.width!=resized_width || result.bgra!=resized_pattern)
        throw std::runtime_error("staging_resize_not_recreated");
    if(classify_acquire(DXGI_ERROR_ACCESS_LOST)!=CaptureStatus::reset_required ||
        classify_acquire(DXGI_ERROR_WAIT_TIMEOUT)!=CaptureStatus::unchanged ||
        classify_acquire(E_ACCESSDENIED)!=CaptureStatus::unavailable)
        throw std::runtime_error("acquire_state");
}
}
