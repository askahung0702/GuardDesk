#include "gpu_scale.hpp"
#include <algorithm>
#include <stdexcept>
namespace remote {
void scale_owned_texture_test(){
    Microsoft::WRL::ComPtr<ID3D11Device> device;Microsoft::WRL::ComPtr<ID3D11DeviceContext> context;
    if(FAILED(D3D11CreateDevice(nullptr,D3D_DRIVER_TYPE_WARP,nullptr,0,nullptr,0,D3D11_SDK_VERSION,&device,nullptr,&context)))throw std::runtime_error("scale_owned_device");
    constexpr unsigned width=3840,height=2160;std::vector<std::uint8_t> pattern(std::size_t(width)*height*4,73);
    D3D11_TEXTURE2D_DESC desc{};desc.Width=width;desc.Height=height;desc.MipLevels=desc.ArraySize=1;desc.SampleDesc.Count=1;
    desc.Format=DXGI_FORMAT_B8G8R8A8_UNORM;desc.Usage=D3D11_USAGE_DEFAULT;
    D3D11_SUBRESOURCE_DATA data{pattern.data(),width*4,0};Microsoft::WRL::ComPtr<ID3D11Texture2D> texture;
    if(FAILED(device->CreateTexture2D(&desc,&data,&texture)))throw std::runtime_error("scale_owned_source");
    GpuScale scale(device.Get(),context.Get());auto target=scale.fit(texture.Get());auto original=target;
    auto pixels=readback(device.Get(),context.Get(),target.Get());
    if(pixels.width!=1920 || pixels.height!=1080 || !std::all_of(pixels.bgra.begin(),pixels.bgra.end(),[](auto c){return c==73;}))throw std::runtime_error("scale_4K_pixels");
    target=scale.fit(texture.Get());if(target.Get()!=original.Get())throw std::runtime_error("scale_target_not_reused");
    if(video_size(1920,1200)!=std::make_pair(1728u,1080u) || video_size(319,181)!=std::make_pair(318u,180u))throw std::runtime_error("scale_aspect_even_bound");
    desc.Width=4;desc.Height=2;std::vector<std::uint8_t> owned_pixels(4*2*4);
    for(unsigned i=0;i<8;++i)for(unsigned c=0;c<4;++c)owned_pixels[i*4+c]=static_cast<std::uint8_t>(20+i*20);
    data.pSysMem=owned_pixels.data();data.SysMemPitch=16;texture.Reset();
    if(FAILED(device->CreateTexture2D(&desc,&data,&texture)))throw std::runtime_error("rotation_owned_source");
    for(unsigned turn=0;turn<4;++turn){
        target=scale.fit(texture.Get(),turn);pixels=readback(device.Get(),context.Get(),target.Get());
        const unsigned ow=turn%2?2:4,oh=turn%2?4:2;
        if(pixels.width!=ow || pixels.height!=oh)throw std::runtime_error("rotation_dimensions");
        for(unsigned y=0;y<oh;++y)for(unsigned x=0;x<ow;++x){
            const unsigned sx=turn==0?x:turn==1?y:turn==2?3-x:3-y;
            const unsigned sy=turn==0?y:turn==1?1-x:turn==2?1-y:x;
            for(unsigned c=0;c<4;++c)if(pixels.bgra[(y*ow+x)*4+c]!=owned_pixels[(sy*4+sx)*4+c])throw std::runtime_error("rotation_pixels");
        }
    }
    bool rejected=false;try{scale.fit(texture.Get(),4);}catch(const std::invalid_argument&){rejected=true;}
    if(!rejected)throw std::runtime_error("invalid_rotation_accepted");
}
}
