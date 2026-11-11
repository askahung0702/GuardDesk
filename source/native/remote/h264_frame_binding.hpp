#pragma once
#include "frame_binding.hpp"
namespace remote {
// Standard H.264 user_data_unregistered SEI; not a new cipher/transport. It
// keeps capture identity in the SAME encoded access unit as its pixels, across
// WebRTC's randomized RTP timestamp offset. Parsed only in low-privilege media.
std::vector<std::uint8_t> bind_h264_frame(const std::vector<std::uint8_t>& access_unit,const std::vector<std::uint8_t>& metadata);
std::optional<std::vector<std::uint8_t>> h264_frame_metadata(const std::vector<std::uint8_t>& access_unit);
}
