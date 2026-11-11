// MF <-> libwebrtc video codec boundary. No desktop, input, device enumeration,
// credential, custom crypto or network implementation lives in this adapter.
#include "mf_codec_adapter.hpp"
#include "codec.hpp"
#include "h264_frame_binding.hpp"
#include <algorithm>
#include <cmath>
#include <deque>
#include <cstring>
#include <span>
#include "api/video/i420_buffer.h"
#include "common_video/h264/h264_common.h"
#include "common_video/h264/sps_parser.h"
#include "modules/video_coding/include/video_codec_interface.h"
#include "modules/video_coding/include/video_error_codes.h"
#include "third_party/libyuv/include/libyuv.h"
#include "rtc_base/thread.h"

namespace remote {
namespace {
// MFT lifetime stays on one explicitly owned MTA queue. Factory destruction may
// occur on a different WebRTC thread; no exit-time TLS destructor or leaked COM
// initialization is required. Calls are synchronous: no queued video backlog.
class MfQueue {
  std::unique_ptr<webrtc::Thread> thread_;
 public:
  bool start() {
    if(thread_)return true;
    auto thread=webrtc::Thread::Create();if(!thread->Start())return false;
    const bool ready=thread->BlockingCall([]{return SUCCEEDED(CoInitializeEx(nullptr,COINIT_MULTITHREADED));});
    if(!ready){thread->Stop();return false;}
    thread_=std::move(thread);return true;
  }
  template<class F> auto call(F&& action) {return thread_->BlockingCall(std::forward<F>(action));}
  void close() {
    if(!thread_)return;
    thread_->BlockingCall([]{CoUninitialize();});thread_->Stop();thread_.reset();
  }
  ~MfQueue(){close();}
};
webrtc::SdpVideoFormat format() {
  return webrtc::SdpVideoFormat("H264",{{"profile-level-id","42e028"},
    {"level-asymmetry-allowed","1"},{"packetization-mode","1"}});
}
bool dimensions(unsigned width,unsigned height) {
  return width>0 && height>0 && width<=1920 && height<=1080 && width%2==0 && height%2==0;
}
bool bounded_annex_b(std::span<const std::uint8_t> bytes){
  unsigned count=0;
  // Bound NAL count before calling a helper that allocates an index vector.
  for(std::size_t i=0;i+3<bytes.size();++i)
    if(bytes[i]==0 && bytes[i+1]==0 && bytes[i+2]==1 && ++count>256)return false;
  return count>0;
}
bool is_idr(const std::vector<std::uint8_t>& packet) {
  for(const auto& nalu:webrtc::H264::FindNaluIndices(packet))
    if(nalu.payload_size && webrtc::H264::ParseNaluType(packet[nalu.payload_start_offset])==webrtc::H264::kIdr)return true;
  return false;
}
class Encoder final : public webrtc::VideoEncoder {
  std::shared_ptr<CodecMetrics> metrics_;
  MfQueue queue_;
  std::unique_ptr<H264Encoder> codec_;
  webrtc::EncodedImageCallback* callback_=nullptr;
  unsigned width_=0,height_=0,fps_=30,bitrate_=1000000;
  bool paused_=false,reset_=false;
  bool hardware_disabled_=false;
  std::uint64_t epoch_=0;
  std::vector<std::uint8_t> nv12_;
  std::deque<std::uint32_t> timestamps_; // bounded delayed MFT output, never a frame queue
 public:
  explicit Encoder(std::shared_ptr<CodecMetrics> metrics):metrics_(std::move(metrics)){++metrics_->encoders;}
  ~Encoder() override {Release();}
  int InitEncode(const webrtc::VideoCodec* settings,const Settings&) override {
    Release(); // A rejected reconfiguration must not leave the old codec live.
    if(!settings || settings->codecType!=webrtc::kVideoCodecH264 ||
      !dimensions(settings->width,settings->height) || settings->numberOfSimulcastStreams>1 ||
      settings->maxFramerate<1 || settings->maxFramerate>30 || !queue_.start())return WEBRTC_VIDEO_CODEC_ERR_PARAMETER;
    width_=settings->width;height_=settings->height;fps_=settings->maxFramerate;
    bitrate_=std::clamp(settings->startBitrate,64u,20000u)*1000u;
    const bool created=queue_.call([&]{try{codec_=std::make_unique<H264Encoder>(width_,height_,fps_,bitrate_,hardware_disabled_?EncoderPreference::software_only:EncoderPreference::prefer_hardware);return true;}
      catch(const std::exception&){return false;}});
    if(!created){++metrics_->failures;return WEBRTC_VIDEO_CODEC_ERROR;}
    nv12_.resize(std::size_t(width_)*height_*3/2);
    timestamps_.clear();paused_=false;reset_=false;return WEBRTC_VIDEO_CODEC_OK;
  }
  int32_t RegisterEncodeCompleteCallback(webrtc::EncodedImageCallback* value) override {callback_=value;return WEBRTC_VIDEO_CODEC_OK;}
  int32_t Release() override {if(codec_)queue_.call([&]{codec_.reset();});queue_.close();timestamps_.clear();nv12_.clear();return WEBRTC_VIDEO_CODEC_OK;}
  int32_t Encode(const webrtc::VideoFrame& frame,const std::vector<webrtc::VideoFrameType>* types) override {
    if(!codec_ || !callback_)return WEBRTC_VIDEO_CODEC_UNINITIALIZED;
    if(paused_){callback_->OnFrameDropped(frame.rtp_timestamp(),0,true);return WEBRTC_VIDEO_CODEC_OK;}
    if(frame.width()!=static_cast<int>(width_) || frame.height()!=static_cast<int>(height_))return WEBRTC_VIDEO_CODEC_ERR_PARAMETER;
    try {
      bool key=types && std::find(types->begin(),types->end(),webrtc::VideoFrameType::kVideoFrameKey)!=types->end();
      if(metrics_->epoch_for_frame){
        const auto epoch=metrics_->epoch_for_frame(frame.rtp_timestamp());
        if(!epoch){callback_->OnFrameDropped(frame.rtp_timestamp(),0,true);return WEBRTC_VIDEO_CODEC_OK;}
        if(epoch!=epoch_){epoch_=epoch;reset_=true;}
      }
      if(reset_){timestamps_.clear();key=true;}
      auto image=frame.video_frame_buffer()->ToI420();if(!image)return WEBRTC_VIDEO_CODEC_ERROR;
      auto surface=std::span<std::uint8_t>(nv12_);
      if(libyuv::I420ToNV12(image->DataY(),image->StrideY(),image->DataU(),image->StrideU(),image->DataV(),image->StrideV(),
          surface.data(),width_,surface.subspan(std::size_t(width_)*height_).data(),width_,width_,height_)!=0)return WEBRTC_VIDEO_CODEC_ERROR;
      if(timestamps_.size()>=4){++metrics_->failures;return WEBRTC_VIDEO_CODEC_ERROR;}
      timestamps_.push_back(frame.rtp_timestamp());std::vector<std::uint8_t> packet;
      const bool encode_ok=queue_.call([&]{try{
        if(reset_)codec_=std::make_unique<H264Encoder>(width_,height_,fps_,bitrate_,hardware_disabled_?EncoderPreference::software_only:EncoderPreference::prefer_hardware);
        const auto before=codec_->selection();packet=codec_->encode(nv12_,key);const auto after=codec_->selection();
        if(after.hardware_frames>before.hardware_frames)++metrics_->hardware_frames;
        metrics_->hardware_candidates=std::max(metrics_->hardware_candidates.load(),after.candidates);
        if(after.fallback && !hardware_disabled_){hardware_disabled_=true;++metrics_->hardware_fallbacks;}
        return true;
      }catch(const std::exception&){return false;}});
      reset_=false;
      if(!encode_ok){++metrics_->failures;return WEBRTC_VIDEO_CODEC_ERROR;}
      if(packet.empty())return WEBRTC_VIDEO_CODEC_OK;
      if(packet.size()>4*1024*1024){++metrics_->failures;return WEBRTC_VIDEO_CODEC_ERROR;}
      if(metrics_->frame_metadata){
        const auto metadata=metrics_->frame_metadata(timestamps_.front());
        if(metadata.empty()){
          // Output was produced, but its capture binding expired (or was
          // retired) while MFT encoded it. Never transmit unbound pixels or
          // retain that timestamp at the queue head: doing so rejects every
          // later packet until the bounded queue is full. Discard pending
          // output and restart with an IDR on the next authorized input, so
          // no future delta depends on the access unit we deliberately lost.
          ++metrics_->unknown_frame_timestamps;
          for(const auto stamp:timestamps_)callback_->OnFrameDropped(stamp,0,true);
          timestamps_.clear();reset_=true;return WEBRTC_VIDEO_CODEC_OK;
        }
        packet=bind_h264_frame(packet,metadata);
      }
      webrtc::EncodedImage encoded;encoded.SetEncodedData(webrtc::EncodedImageBuffer::Create(packet.data(),packet.size()));
      encoded.SetRtpTimestamp(timestamps_.front());timestamps_.pop_front();
      if(metrics_->encoded==0)metrics_->first_encoded_timestamp=encoded.RtpTimestamp();
      encoded._encodedWidth=width_;encoded._encodedHeight=height_;
      const bool idr=is_idr(packet);encoded.SetFrameType(idr?webrtc::VideoFrameType::kVideoFrameKey:webrtc::VideoFrameType::kVideoFrameDelta);
      webrtc::CodecSpecificInfo info{};info.codecType=webrtc::kVideoCodecH264;
      info.codecSpecific.H264.packetization_mode=webrtc::H264PacketizationMode::NonInterleaved;
      info.codecSpecific.H264.idr_frame=idr;++metrics_->encoded;
      return callback_->OnEncodedImage(encoded,&info).error==webrtc::EncodedImageCallback::Result::OK?WEBRTC_VIDEO_CODEC_OK:WEBRTC_VIDEO_CODEC_ERROR;
    }catch(const std::exception&){++metrics_->failures;return WEBRTC_VIDEO_CODEC_ERROR;}
  }
  void SetRates(const RateControlParameters& value) override {
    const auto rate=value.bitrate.get_sum_bps();paused_=rate==0;
    if(paused_)return;
    const auto bitrate=std::clamp(rate,64000u,20000000u);
    const auto fps=std::isfinite(value.framerate_fps) && value.framerate_fps>0?static_cast<unsigned>(std::clamp(value.framerate_fps,1.0,30.0)):fps_;
    // Avoid reconstructing for tiny BWE fluctuations. A material change resets
    // the software fallback and forces an IDR; hardware/dynamic MFT is pending.
    if(fps!=fps_ || bitrate>bitrate_+bitrate_/4 || bitrate+bitrate/4<bitrate_){fps_=fps;bitrate_=bitrate;reset_=true;}
  }
  EncoderInfo GetEncoderInfo() const override {
    EncoderInfo info;info.implementation_name="GuardDesk-MF-H264-software";
    info.is_hardware_accelerated=false;info.supports_native_handle=false;
    info.requested_resolution_alignment=2;info.scaling_settings=ScalingSettings::kOff;return info;
  }
};
class Decoder final : public webrtc::VideoDecoder {
  std::shared_ptr<CodecMetrics> metrics_;
  MfQueue queue_;
  std::unique_ptr<H264Decoder> codec_;
  webrtc::DecodedImageCallback* callback_=nullptr;
  bool configured_=false;
  std::uint64_t epoch_=0;
  unsigned width_=0,height_=0,max_width_=1920,max_height_=1080;
  std::deque<std::uint32_t> timestamps_;
 public:
  explicit Decoder(std::shared_ptr<CodecMetrics> metrics):metrics_(std::move(metrics)){++metrics_->decoders;}
  ~Decoder() override {Release();}
  bool Configure(const Settings& settings) override {
    Release();
    if(settings.codec_type()!=webrtc::kVideoCodecH264 || !queue_.start())return false;
    const auto limit=settings.max_render_resolution();
    max_width_=limit.Valid()?std::min(1920,limit.Width()):1920;
    max_height_=limit.Valid()?std::min(1080,limit.Height()):1080;
    timestamps_.clear();width_=height_=0;configured_=true;return true;
  }
  int32_t RegisterDecodeCompleteCallback(webrtc::DecodedImageCallback* value) override {callback_=value;return WEBRTC_VIDEO_CODEC_OK;}
  int32_t Release() override {configured_=false;if(codec_)queue_.call([&]{codec_.reset();});queue_.close();timestamps_.clear();return WEBRTC_VIDEO_CODEC_OK;}
  int32_t Decode(const webrtc::EncodedImage& input,int64_t) override {
    if(!configured_)return WEBRTC_VIDEO_CODEC_UNINITIALIZED;
    if(!callback_ || input.size()==0 || input.size()>4*1024*1024)return WEBRTC_VIDEO_CODEC_ERR_PARAMETER;
    try {
      if(!input.data())return WEBRTC_VIDEO_CODEC_ERR_PARAMETER;
      if(metrics_->received_packets.fetch_add(1)==0)metrics_->first_received_timestamp=input.RtpTimestamp();
      std::vector<std::uint8_t> packet(input.size());std::memcpy(packet.data(),input.data(),input.size());
      if(metrics_->receive_metadata){
        const auto metadata=h264_frame_metadata(packet);
        if(!metadata || !metrics_->receive_metadata(*metadata,input.RtpTimestamp()))return WEBRTC_VIDEO_CODEC_ERROR;
      }
      if(metrics_->epoch_for_frame){
        const auto epoch=metrics_->epoch_for_frame(input.RtpTimestamp());if(!epoch){++metrics_->unknown_frame_timestamps;return WEBRTC_VIDEO_CODEC_ERROR;}
        if(epoch!=epoch_){
          epoch_=epoch;if(codec_)queue_.call([&]{codec_.reset();});width_=height_=0;timestamps_.clear();
        }
      }
      auto data=std::span<const std::uint8_t>(packet);
      if(!bounded_annex_b(data))return WEBRTC_VIDEO_CODEC_ERR_PARAMETER;
      const auto nalus=webrtc::H264::FindNaluIndices(packet);
      if(nalus.size()>256)return WEBRTC_VIDEO_CODEC_ERR_PARAMETER;
      unsigned sps_count=0;
      for(const auto& nalu:nalus)
        if(nalu.payload_size && webrtc::H264::ParseNaluType(packet[nalu.payload_start_offset])==webrtc::H264::kSps){
          if(nalu.payload_size>4096)return WEBRTC_VIDEO_CODEC_ERR_PARAMETER;
          ++sps_count;
        }
      if(sps_count>1)return WEBRTC_VIDEO_CODEC_ERR_PARAMETER;
      for(const auto& nalu:nalus) {
        if(nalu.payload_size>1 && webrtc::H264::ParseNaluType(packet[nalu.payload_start_offset])==webrtc::H264::kSps) {
          if(nalu.payload_start_offset>data.size() || nalu.payload_size>data.size()-nalu.payload_start_offset)return WEBRTC_VIDEO_CODEC_ERR_PARAMETER;
          const auto parsed=webrtc::SpsParser::ParseSps(data.subspan(nalu.payload_start_offset+1,nalu.payload_size-1));
          if(!parsed || !dimensions(parsed->width,parsed->height) || parsed->width>max_width_ || parsed->height>max_height_)
            return WEBRTC_VIDEO_CODEC_ERR_PARAMETER;
          if(parsed->width!=width_ || parsed->height!=height_) {
            if(!is_idr(packet))return WEBRTC_VIDEO_CODEC_ERROR;
            width_=parsed->width;height_=parsed->height;timestamps_.clear();
            const bool created=queue_.call([&]{try{codec_=std::make_unique<H264Decoder>(width_,height_);return true;}
              catch(const std::exception&){return false;}});
            if(!created){++metrics_->failures;return WEBRTC_VIDEO_CODEC_ERROR;}
          }
        }
      }
      if(!codec_ || timestamps_.size()>=4)return WEBRTC_VIDEO_CODEC_UNINITIALIZED;
      timestamps_.push_back(input.RtpTimestamp());std::vector<std::uint8_t> nv12;
      const bool decoded=queue_.call([&]{try{nv12=codec_->decode(packet);return true;}
        catch(const std::exception&){return false;}});
      if(!decoded){++metrics_->failures;return WEBRTC_VIDEO_CODEC_ERROR;}
      if(nv12.empty())return WEBRTC_VIDEO_CODEC_OK;
      auto i420=webrtc::I420Buffer::Create(width_,height_);
      auto surface=std::span<const std::uint8_t>(nv12);
      if(libyuv::NV12ToI420(surface.data(),width_,surface.subspan(std::size_t(width_)*height_).data(),width_,i420->MutableDataY(),i420->StrideY(),
          i420->MutableDataU(),i420->StrideU(),i420->MutableDataV(),i420->StrideV(),width_,height_)!=0)return WEBRTC_VIDEO_CODEC_ERROR;
      auto frame=webrtc::VideoFrame::Builder().set_video_frame_buffer(i420).set_rtp_timestamp(timestamps_.front()).build();
      timestamps_.pop_front();++metrics_->decoded;callback_->Decoded(frame);return WEBRTC_VIDEO_CODEC_OK;
    }catch(const std::exception&){++metrics_->failures;return WEBRTC_VIDEO_CODEC_ERROR;}
  }
  DecoderInfo GetDecoderInfo() const override {return {"GuardDesk-MF-H264-software",false};}
};
}
std::vector<webrtc::SdpVideoFormat> MfEncoderFactory::GetSupportedFormats() const{return {format()};}
std::vector<webrtc::SdpVideoFormat> MfDecoderFactory::GetSupportedFormats() const{return {format()};}
std::unique_ptr<webrtc::VideoEncoder> MfEncoderFactory::Create(const webrtc::Environment&,const webrtc::SdpVideoFormat& value) {
  return format().IsSameCodec(value)?std::make_unique<Encoder>(metrics_):nullptr;
}
std::unique_ptr<webrtc::VideoDecoder> MfDecoderFactory::Create(const webrtc::Environment&,const webrtc::SdpVideoFormat& value) {
  return format().IsSameCodec(value)?std::make_unique<Decoder>(metrics_):nullptr;
}
}
