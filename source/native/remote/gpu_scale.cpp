#include "gpu_scale.hpp"
#include <stdexcept>
namespace remote {
Microsoft::WRL::ComPtr<ID3D11Texture2D> GpuScale::fit(ID3D11Texture2D* source,unsigned quarter_turns){
    if(!source)throw std::invalid_argument("scale_source");D3D11_TEXTURE2D_DESC desc{};source->GetDesc(&desc);
    if(quarter_turns>3)throw std::invalid_argument("scale_rotation");
    const auto size=quarter_turns%2?video_size(desc.Height,desc.Width):video_size(desc.Width,desc.Height);
    if(!quarter_turns && size.first==desc.Width && size.second==desc.Height)return source;
    if(width_!=size.first || height_!=size.second){
        target_.Reset();view_.Reset();desc.Width=size.first;desc.Height=size.second;
        desc.Usage=D3D11_USAGE_DEFAULT;desc.CPUAccessFlags=desc.MiscFlags=0;desc.BindFlags=D3D11_BIND_RENDER_TARGET;
        if(FAILED(device_->CreateTexture2D(&desc,nullptr,&target_)) || FAILED(device_->CreateRenderTargetView(target_.Get(),nullptr,&view_)))throw std::runtime_error("scale_target");
        width_=size.first;height_=size.second;
    }
    renderer_.draw_texture(source,view_.Get(),width_,height_,quarter_turns);return target_;
}
}
