#pragma once
#include "render.hpp"
#include "video_geometry.hpp"
namespace remote {
class GpuScale {
    Microsoft::WRL::ComPtr<ID3D11Device> device_;
    Microsoft::WRL::ComPtr<ID3D11Texture2D> target_;
    Microsoft::WRL::ComPtr<ID3D11RenderTargetView> view_;
    GpuRenderer renderer_;
    unsigned width_=0,height_=0;
public:
    GpuScale(ID3D11Device* device,ID3D11DeviceContext* context):device_(device),renderer_(device,context,true){}
    Microsoft::WRL::ComPtr<ID3D11Texture2D> fit(ID3D11Texture2D* source,unsigned quarter_turns=0);
};
void scale_owned_texture_test();
}
