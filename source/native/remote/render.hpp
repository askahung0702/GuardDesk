#pragma once
#include "capture.hpp"
namespace remote {
class GpuRenderer {
    Microsoft::WRL::ComPtr<ID3D11Device> device_;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> context_;
    Microsoft::WRL::ComPtr<ID3D11VertexShader> vertex_;
    Microsoft::WRL::ComPtr<ID3D11PixelShader> pixel_;
    Microsoft::WRL::ComPtr<ID3D11SamplerState> sampler_;
    Microsoft::WRL::ComPtr<ID3D11RasterizerState> raster_;
    Microsoft::WRL::ComPtr<ID3D11Texture2D> image_;
    Microsoft::WRL::ComPtr<ID3D11ShaderResourceView> view_;
    Microsoft::WRL::ComPtr<ID3D11BlendState> alpha_;
    Microsoft::WRL::ComPtr<ID3D11Buffer> rotation_;
    unsigned width_=0,height_=0;
    void prepare(unsigned width,unsigned height);
    void draw_view(ID3D11RenderTargetView* target,unsigned width,unsigned height,const D3D11_VIEWPORT* overlay=nullptr,unsigned quarter_turns=0);
public:
    GpuRenderer(ID3D11Device* device,ID3D11DeviceContext* context,bool smooth=false);
    void draw(const Pixels& image,ID3D11RenderTargetView* target,unsigned width,unsigned height);
    void draw_texture(ID3D11Texture2D* image,ID3D11RenderTargetView* target,unsigned width,unsigned height,unsigned quarter_turns=0);
    void draw_cached(ID3D11RenderTargetView* target,unsigned width,unsigned height);
    void overlay(const Pixels& image,ID3D11RenderTargetView* target,const D3D11_VIEWPORT& viewport);
    void clear();
};
void render_owned_texture_test();
}
