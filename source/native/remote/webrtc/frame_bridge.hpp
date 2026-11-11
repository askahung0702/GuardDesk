#pragma once
#include "frame_binding.hpp"
#include "api/video/adapted_video_track_source.h"
#include "api/video/video_frame.h"
#include <functional>

namespace remote {
class FrameSource : public webrtc::AdaptedVideoTrackSource {
    std::shared_ptr<FrameBindings> bindings_;
    std::uint64_t transport_,last_ntp_=0;
    std::function<bool(const std::vector<std::uint8_t>&)> metadata_;
public:
    FrameSource(std::shared_ptr<FrameBindings> bindings,std::uint64_t transport,std::function<bool(const std::vector<std::uint8_t>&)> metadata);
    SourceState state() const override{return kLive;}
    bool remote() const override{return false;}
    bool is_screencast() const override{return true;}
    std::optional<bool> needs_denoising() const override{return false;}
    bool push(const SharedFrame& frame);
};
class FrameSink : public webrtc::VideoSinkInterface<webrtc::VideoFrame> {
    std::shared_ptr<FrameBindings> bindings_;
    std::function<void(std::uint64_t)> generation_;
    std::function<bool(SharedFrame)> submit_;
public:
    FrameSink(std::shared_ptr<FrameBindings> bindings,std::function<void(std::uint64_t)> generation,std::function<bool(SharedFrame)> submit);
    bool metadata(const std::vector<std::uint8_t>& packet);
    bool encoded_metadata(const std::vector<std::uint8_t>& packet,std::uint32_t received_rtp_timestamp);
    void OnFrame(const webrtc::VideoFrame& frame) override;
};
}
