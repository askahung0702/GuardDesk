#include "render.hpp"
#include <d3dcompiler.h>
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace remote {
using Microsoft::WRL::ComPtr;
namespace {
void check(HRESULT result) {if(FAILED(result)) throw GraphicsFailure(result);}
constexpr char shader[]=
    "struct V { float4 p:SV_Position; float2 uv:TEXCOORD0; };"
    "V vs(uint i:SV_VertexID) {"
    " float2 p[3]={float2(-1,-1),float2(-1,3),float2(3,-1)};"
    " float2 u[3]={float2(0,1),float2(0,-1),float2(2,1)};"
    " V o; o.p=float4(p[i],0,1);o.uv=u[i];return o; }"
    "Texture2D img:register(t0);SamplerState samp:register(s0);"
    "cbuffer Rotation:register(b0){uint turns;uint3 pad;}"
    "float4 ps(V i):SV_Target { float2 uv=i.uv;"
    " if(turns==1)uv=float2(i.uv.y,1-i.uv.x);"
    " else if(turns==2)uv=1-i.uv;"
    " else if(turns==3)uv=float2(1-i.uv.y,i.uv.x);"
    " return img.Sample(samp,uv); }";
}

GpuRenderer::GpuRenderer(ID3D11Device* device,ID3D11DeviceContext* context,bool smooth):device_(device),context_(context) {
    if(!device || !context) throw std::invalid_argument("render_device");
    ComPtr<ID3DBlob> vertex,pixel,error;
    constexpr UINT flags=D3DCOMPILE_ENABLE_STRICTNESS|D3DCOMPILE_WARNINGS_ARE_ERRORS;
    check(D3DCompile(shader,sizeof(shader)-1,nullptr,nullptr,nullptr,"vs","vs_4_0",flags,0,&vertex,&error));
    check(D3DCompile(shader,sizeof(shader)-1,nullptr,nullptr,nullptr,"ps","ps_4_0",flags,0,&pixel,&error));
    check(device_->CreateVertexShader(vertex->GetBufferPointer(),vertex->GetBufferSize(),nullptr,&vertex_));
    check(device_->CreatePixelShader(pixel->GetBufferPointer(),pixel->GetBufferSize(),nullptr,&pixel_));
    D3D11_BUFFER_DESC rotation{};rotation.ByteWidth=16;rotation.Usage=D3D11_USAGE_DEFAULT;rotation.BindFlags=D3D11_BIND_CONSTANT_BUFFER;
    check(device_->CreateBuffer(&rotation,nullptr,&rotation_));
    D3D11_SAMPLER_DESC sampler{};sampler.Filter=smooth?D3D11_FILTER_MIN_MAG_LINEAR_MIP_POINT:D3D11_FILTER_MIN_MAG_MIP_POINT;
    sampler.AddressU=sampler.AddressV=sampler.AddressW=D3D11_TEXTURE_ADDRESS_CLAMP;
    sampler.MaxLOD=D3D11_FLOAT32_MAX;check(device_->CreateSamplerState(&sampler,&sampler_));
    D3D11_RASTERIZER_DESC raster{};raster.FillMode=D3D11_FILL_SOLID;raster.CullMode=D3D11_CULL_NONE;
    D3D11_BLEND_DESC blend{};auto& target=blend.RenderTarget[0];target.BlendEnable=TRUE;
    target.SrcBlend=D3D11_BLEND_ONE;target.DestBlend=D3D11_BLEND_INV_SRC_ALPHA;target.BlendOp=D3D11_BLEND_OP_ADD;
    target.SrcBlendAlpha=D3D11_BLEND_ONE;target.DestBlendAlpha=D3D11_BLEND_INV_SRC_ALPHA;target.BlendOpAlpha=D3D11_BLEND_OP_ADD;target.RenderTargetWriteMask=D3D11_COLOR_WRITE_ENABLE_ALL;
    check(device_->CreateBlendState(&blend,&alpha_));
    raster.DepthClipEnable=TRUE;check(device_->CreateRasterizerState(&raster,&raster_));
}
void GpuRenderer::clear(){view_.Reset();image_.Reset();width_=height_=0;}

void GpuRenderer::draw(const Pixels& image,ID3D11RenderTargetView* target,unsigned width,unsigned height) {
    if(!target || width==0 || height==0 || width>8192 || height>8192 ||
        image.width==0 || image.height==0 || image.width>8192 || image.height>8192 ||
        std::uint64_t(image.width)*image.height>16777216 ||
        image.bgra.size()!=std::size_t(image.width)*image.height*4) throw std::invalid_argument("render_dimensions");
    prepare(image.width,image.height);
    context_->UpdateSubresource(image_.Get(),0,nullptr,image.bgra.data(),image.width*4,0);
    draw_view(target,width,height);
}
void GpuRenderer::prepare(unsigned width,unsigned height){
    if(width!=width_ || height!=height_) {
        image_.Reset();view_.Reset();
        D3D11_TEXTURE2D_DESC desc{};desc.Width=width;desc.Height=height;
        desc.MipLevels=1;desc.ArraySize=1;desc.SampleDesc.Count=1;
        desc.Format=DXGI_FORMAT_B8G8R8A8_UNORM;desc.Usage=D3D11_USAGE_DEFAULT;desc.BindFlags=D3D11_BIND_SHADER_RESOURCE;
        check(device_->CreateTexture2D(&desc,nullptr,&image_));
        check(device_->CreateShaderResourceView(image_.Get(),nullptr,&view_));
        width_=width;height_=height;
    }
}
void GpuRenderer::draw_texture(ID3D11Texture2D* image,ID3D11RenderTargetView* target,unsigned width,unsigned height,unsigned quarter_turns){
    if(!image || !target || width<2 || height<2 || width>8192 || height>8192)throw std::invalid_argument("render_texture_target");
    D3D11_TEXTURE2D_DESC desc{};image->GetDesc(&desc);
    if(desc.Format!=DXGI_FORMAT_B8G8R8A8_UNORM || !desc.Width || !desc.Height || desc.Width>8192 || desc.Height>8192 ||
        std::uint64_t(desc.Width)*desc.Height>16777216 || desc.ArraySize!=1 || desc.MipLevels!=1 || desc.SampleDesc.Count!=1)throw std::invalid_argument("render_texture_source");
    if(quarter_turns>3)throw std::invalid_argument("render_rotation");
    prepare(desc.Width,desc.Height);context_->CopyResource(image_.Get(),image);draw_view(target,width,height,nullptr,quarter_turns);
}
void GpuRenderer::draw_cached(ID3D11RenderTargetView* target,unsigned width,unsigned height){if(!view_)throw std::runtime_error("render_cache_empty");draw_view(target,width,height);}
void GpuRenderer::overlay(const Pixels& image,ID3D11RenderTargetView* target,const D3D11_VIEWPORT& viewport){
    if(!target || !image.width || !image.height || image.width>64 || image.height>64 || image.bgra.size()!=std::size_t(image.width)*image.height*4 || viewport.Width<=0 || viewport.Height<=0)return;
    prepare(image.width,image.height);context_->UpdateSubresource(image_.Get(),0,nullptr,image.bgra.data(),image.width*4,0);draw_view(target,1,1,&viewport);
}
void GpuRenderer::draw_view(ID3D11RenderTargetView* target,unsigned width,unsigned height,const D3D11_VIEWPORT* overlay,unsigned quarter_turns){
    const float black[4]={0,0,0,1};if(!overlay)context_->ClearRenderTargetView(target,black);
    const auto iw=quarter_turns%2?height_:width_,ih=quarter_turns%2?width_:height_;
    const float scale=std::min(float(width)/iw,float(height)/ih);
    D3D11_VIEWPORT viewport{};viewport.Width=iw*scale;viewport.Height=ih*scale;
    viewport.TopLeftX=(width-viewport.Width)*.5f;viewport.TopLeftY=(height-viewport.Height)*.5f;viewport.MaxDepth=1;
    if(overlay)viewport=*overlay;
    context_->RSSetViewports(1,&viewport);context_->RSSetState(raster_.Get());
    context_->OMSetRenderTargets(1,&target,nullptr);context_->OMSetBlendState(overlay?alpha_.Get():nullptr,nullptr,0xffffffff);
    context_->IASetInputLayout(nullptr);context_->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    context_->VSSetShader(vertex_.Get(),nullptr,0);context_->PSSetShader(pixel_.Get(),nullptr,0);
    const unsigned rotation[4]{quarter_turns,0,0,0};context_->UpdateSubresource(rotation_.Get(),0,nullptr,rotation,0,0);
    ID3D11Buffer* cb=rotation_.Get();context_->PSSetConstantBuffers(0,1,&cb);
    ID3D11ShaderResourceView* view=view_.Get();ID3D11SamplerState* sampler=sampler_.Get();
    context_->PSSetShaderResources(0,1,&view);context_->PSSetSamplers(0,1,&sampler);context_->Draw(3,0);
    ID3D11ShaderResourceView* empty=nullptr;context_->PSSetShaderResources(0,1,&empty);
    context_->OMSetRenderTargets(0,nullptr,nullptr);
}

}
