// Owned WARP readback test; not linked into the product media/renderer library.
#include "render.hpp"
#include <stdexcept>
#include <cstdlib>
#include <iostream>
namespace remote {
void render_owned_texture_test(){
    CursorUpdate invert;
    if(!convert_cursor_shape(invert,1,1,2,1,0,0,{128,128}))throw std::runtime_error("cursor_monochrome_invert_unsupported");
    auto need=[](bool okay,const char* reason){if(!okay)throw std::runtime_error(reason);};
    Pixels background{4,2,std::vector<std::uint8_t>(32)};
    for(unsigned i=0;i<8;++i){background.bgra[i*4]=17;background.bgra[i*4+1]=34;background.bgra[i*4+2]=51;background.bgra[i*4+3]=255;}
    CursorUpdate mono;mono.session[0]=1;mono.transport=mono.generation=mono.sequence=mono.shape=1;mono.source_width=4;mono.source_height=2;
    need(convert_cursor_shape(mono,1,4,2,1,0,0,{0xc0,0xa0}),"cursor_mono_decode");
    bool rejected=false;try{encode_cursor(mono);}catch(const std::invalid_argument&){rejected=true;}
    need(rejected,"unresolved_XOR_crossed_wire");
    auto composed=compose_cursor(mono,background,4,2);
    need(composed.bgra==std::vector<std::uint8_t>({238,221,204,255,0,0,0,0,255,255,255,255,0,0,0,255}),"cursor_mono_AND_XOR_truth_table");
    need(decode_cursor(encode_cursor(composed)).bgra==composed.bgra,"cursor_composed_wire_roundtrip");
    background.bgra[0]=99;need(compose_cursor(mono,background,4,2).bgra[0]==156,"cursor_XOR_uses_current_background");
    mono.x=-1;auto clipped=compose_cursor(mono,background,4,2);need(clipped.bgra[3]==0,"cursor_XOR_clipping");
    CursorUpdate masked;need(convert_cursor_shape(masked,4,2,1,8,0,0,{0xa5,0x33,0x77,255,7,8,9,0}),"cursor_masked_decode");
    auto resolved=compose_cursor(masked,background,4,2);
    need(resolved.bgra==std::vector<std::uint8_t>({198,17,68,255,7,8,9,255}),"cursor_masked_XOR_and_copy");
    need(!convert_cursor_shape(masked,4,1,1,4,0,0,{1,2,3,1}),"cursor_invalid_mask_alpha_accepted");
    std::cout<<"cursor_AND_XOR_composition_current_authorized_pixels_and_wire_fence=true\n";
    Microsoft::WRL::ComPtr<ID3D11Device> device;Microsoft::WRL::ComPtr<ID3D11DeviceContext> context;
    auto check=[](HRESULT result){if(FAILED(result))throw std::runtime_error("owned_render_api");};
    check(D3D11CreateDevice(nullptr,D3D_DRIVER_TYPE_WARP,nullptr,0,nullptr,0,D3D11_SDK_VERSION,&device,nullptr,&context));
    GpuRenderer renderer(device.Get(),context.Get());Pixels owned{320,180,std::vector<std::uint8_t>(320*180*4)};
    for(std::size_t i=0;i<owned.bgra.size();++i)owned.bgra[i]=static_cast<std::uint8_t>((i*7+31)%256);
    D3D11_TEXTURE2D_DESC desc{};desc.Width=owned.width;desc.Height=owned.height;desc.MipLevels=1;desc.ArraySize=1;desc.SampleDesc.Count=1;
    desc.Format=DXGI_FORMAT_B8G8R8A8_UNORM;desc.Usage=D3D11_USAGE_DEFAULT;desc.BindFlags=D3D11_BIND_RENDER_TARGET;
    Microsoft::WRL::ComPtr<ID3D11Texture2D> target;Microsoft::WRL::ComPtr<ID3D11RenderTargetView> view;
    check(device->CreateTexture2D(&desc,nullptr,&target));check(device->CreateRenderTargetView(target.Get(),nullptr,&view));
    renderer.draw(owned,view.Get(),owned.width,owned.height);
    if(readback(device.Get(),context.Get(),target.Get()).bgra!=owned.bgra)throw std::runtime_error("gpu_render_roundtrip");
    GpuRenderer cursor(device.Get(),context.Get());Pixels shape{2,2,std::vector<std::uint8_t>(16)};
    for(unsigned i=0;i<4;++i){shape.bgra.at(i*4+2)=128;shape.bgra.at(i*4+3)=128;}
    D3D11_VIEWPORT viewport{4,5,2,2,0,1};cursor.overlay(shape,view.Get(),viewport);
    auto composite=readback(device.Get(),context.Get(),target.Get());
    for(unsigned y=0;y<owned.height;++y)for(unsigned x=0;x<owned.width;++x)for(unsigned c=0;c<3;++c){
        const auto at=(std::size_t(y)*owned.width+x)*4+c;
        const int expected=x>=4 && x<6 && y>=5 && y<7?(c==2?128:0)+int(owned.bgra.at(at))*127/255:owned.bgra.at(at);
        if(std::abs(int(composite.bgra.at(at))-expected)>1)throw std::runtime_error("gpu_cursor_premultiplied_overlay");
    }
    renderer.draw_cached(view.Get(),owned.width,owned.height);
    if(readback(device.Get(),context.Get(),target.Get()).bgra!=owned.bgra)throw std::runtime_error("cursor_redraw_changed_cached_video");
}
}
