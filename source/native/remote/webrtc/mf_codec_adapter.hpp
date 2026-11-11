#pragma once
#include <atomic>
#include <memory>
#include <functional>
#include "api/video_codecs/video_encoder_factory.h"
#include "api/video_codecs/video_decoder_factory.h"

namespace remote {
// Bounded 1080p adapter with explicit hardware preference and software fallback.
// Caller owns MFStartup/MFShutdown around all factories and codec instances.
struct CodecMetrics {
  std::atomic<unsigned> encoders{0},decoders{0},encoded{0},decoded{0},failures{0};
  std::atomic<std::uint32_t> first_encoded_timestamp{0},first_received_timestamp{0};
  std::atomic<unsigned> received_packets{0},unknown_frame_timestamps{0};
  std::atomic<unsigned> hardware_candidates{0},hardware_frames{0},hardware_fallbacks{0};
  // Fixed before factory creation, never changed while codecs are running.
  // Unknown/old RTP timestamps are dropped; epochs force an actual new IDR.
  std::function<std::uint64_t(std::uint32_t)> epoch_for_frame;
  std::function<std::vector<std::uint8_t>(std::uint32_t)> frame_metadata;
  std::function<bool(const std::vector<std::uint8_t>&,std::uint32_t)> receive_metadata;
};
class MfEncoderFactory final : public webrtc::VideoEncoderFactory {
  std::shared_ptr<CodecMetrics> metrics_;
 public:
  explicit MfEncoderFactory(std::shared_ptr<CodecMetrics> metrics):metrics_(std::move(metrics)){}
  std::vector<webrtc::SdpVideoFormat> GetSupportedFormats() const override;
  std::unique_ptr<webrtc::VideoEncoder> Create(const webrtc::Environment&,const webrtc::SdpVideoFormat&) override;
};
class MfDecoderFactory final : public webrtc::VideoDecoderFactory {
  std::shared_ptr<CodecMetrics> metrics_;
 public:
  explicit MfDecoderFactory(std::shared_ptr<CodecMetrics> metrics):metrics_(std::move(metrics)){}
  std::vector<webrtc::SdpVideoFormat> GetSupportedFormats() const override;
  std::unique_ptr<webrtc::VideoDecoder> Create(const webrtc::Environment&,const webrtc::SdpVideoFormat&) override;
};
}
