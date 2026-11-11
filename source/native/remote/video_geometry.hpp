#pragma once
#include <utility>
#include <cstdint>
#include <stdexcept>
namespace remote {
// Wire dimensions are independent from physical/DPI coordinates. Never
// upscale; retain aspect ratio within the negotiated 1080p/even NV12 bound.
inline std::pair<unsigned,unsigned> video_size(unsigned width,unsigned height){
    if(width<2 || height<2 || width>8192 || height>8192 || std::uint64_t(width)*height>16777216)throw std::invalid_argument("video_geometry");
    std::uint64_t w=width,h=height;
    if(w>1920){h=h*1920/w;w=1920;}
    if(h>1080){w=w*1080/h;h=1080;}
    w&=~std::uint64_t(1);h&=~std::uint64_t(1);
    if(w<2 || h<2)throw std::invalid_argument("video_geometry_aspect");return {static_cast<unsigned>(w),static_cast<unsigned>(h)};
}
}
