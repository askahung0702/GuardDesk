#include "frame_bridge.hpp"
#include "api/video/i420_buffer.h"
#include "third_party/libyuv/include/libyuv.h"
#include "system_wrappers/include/clock.h"
#include <span>
#include <stdexcept>

namespace remote {
FrameSource::FrameSource(std::shared_ptr<FrameBindings> bindings,std::uint64_t transport,std::function<bool(const std::vector<std::uint8_t>&)> metadata)
    :bindings_(std::move(bindings)),transport_(transport),metadata_(std::move(metadata)){
    if(!bindings_ || !metadata_ || !transport_)throw std::invalid_argument("frame_source_config");
}
bool FrameSource::push(const SharedFrame& frame){
    const auto& ticket=frame.ticket;const auto& pixels=frame.pixels;
    if(!pixels.width || !pixels.height || pixels.width>1920 || pixels.height>1080 || pixels.width%2 || pixels.height%2 ||
        pixels.width!=ticket.width || pixels.height!=ticket.height || pixels.bgra.size()!=std::size_t(pixels.width)*pixels.height*4)return false;
    const auto tick=GetTickCount64();if(ticket.tick>tick || tick-ticket.tick>1000)return false;
    auto* clock=webrtc::Clock::GetRealTimeClock();
    const auto ntp=static_cast<std::uint64_t>(clock->CurrentNtpInMilliseconds())-(tick-ticket.tick);
    if(ntp<=last_ntp_)return false;last_ntp_=ntp;
    const auto rtp=static_cast<std::uint32_t>(90*static_cast<std::uint32_t>(ntp));
    VideoBinding binding{ticket,transport_,rtp};
    if(!bindings_->record(binding,tick) || !metadata_(encode_video_binding(binding)))return false;
    auto image=webrtc::I420Buffer::Create(pixels.width,pixels.height);
    if(libyuv::ARGBToI420(pixels.bgra.data(),pixels.width*4,image->MutableDataY(),image->StrideY(),image->MutableDataU(),image->StrideU(),
        image->MutableDataV(),image->StrideV(),pixels.width,pixels.height))return false;
    auto video=webrtc::VideoFrame::Builder().set_video_frame_buffer(image).set_timestamp_us(clock->TimeInMicroseconds())
        .set_ntp_time_ms(static_cast<int64_t>(ntp)).set_rtp_timestamp(rtp).build();
    OnFrame(video);return true;
}
FrameSink::FrameSink(std::shared_ptr<FrameBindings> bindings,std::function<void(std::uint64_t)> generation,std::function<bool(SharedFrame)> submit)
    :bindings_(std::move(bindings)),generation_(std::move(generation)),submit_(std::move(submit)){
    if(!bindings_ || !generation_ || !submit_)throw std::invalid_argument("frame_sink_config");
}
bool FrameSink::metadata(const std::vector<std::uint8_t>& packet){
    try{
        const auto binding=decode_video_binding(packet);if(!bindings_->record(binding,GetTickCount64()))return false;
        generation_(binding.frame.generation);return true;
    }catch(const std::invalid_argument&){return false;}
}
bool FrameSink::encoded_metadata(const std::vector<std::uint8_t>& packet,std::uint32_t actual_rtp){
    try{
        auto binding=decode_video_binding(packet);
        // libwebrtc adds a randomized RTP offset. This SEI belongs to the SAME
        // authenticated access unit; never guess/learn the sender's offset.
        binding.rtp_timestamp=actual_rtp;
        if(!bindings_->record(binding,GetTickCount64()))return false;
        generation_(binding.frame.generation);return true;
    }catch(const std::invalid_argument&){return false;}
}
void FrameSink::OnFrame(const webrtc::VideoFrame& frame){
    auto binding=bindings_->find(frame.rtp_timestamp(),GetTickCount64());if(!binding)return;
    if(frame.width()!=static_cast<int>(binding->frame.width) || frame.height()!=static_cast<int>(binding->frame.height))return;
    auto image=frame.video_frame_buffer()->ToI420();if(!image)return;
    SharedFrame output{binding->frame,{binding->frame.width,binding->frame.height,std::vector<std::uint8_t>(std::size_t(binding->frame.width)*binding->frame.height*4)}};
    if(libyuv::I420ToARGB(image->DataY(),image->StrideY(),image->DataU(),image->StrideU(),image->DataV(),image->StrideV(),output.pixels.bgra.data(),output.pixels.width*4,
        output.pixels.width,output.pixels.height)==0)submit_(std::move(output));
}
}
