// Actual WebRTC codec callbacks using only own I420 frames. Not RTP acceptance.
#include "mf_codec_adapter.hpp"
#include "codec.hpp"
#include "h264_frame_binding.hpp"
#include <windows.h>
#include <mfapi.h>
#include <algorithm>
#include <cstring>
#include <iostream>
#include "api/environment/environment_factory.h"
#include "api/video/i420_buffer.h"
#include "modules/video_coding/include/video_error_codes.h"

namespace {
class Callback final : public webrtc::EncodedImageCallback,public webrtc::DecodedImageCallback {
 public:
  webrtc::VideoDecoder* decoder=nullptr;
  unsigned encoded=0,decoded=0,dropped=0;
  webrtc::EncodedImage last;
  bool valid=true;
  bool inspect_binding=false;
  std::vector<uint32_t> stamps;
  std::vector<bool> keyframes;
  Result OnEncodedImage(const webrtc::EncodedImage& image,const webrtc::CodecSpecificInfo*) override {
    ++encoded;last=image;
    stamps.push_back(image.RtpTimestamp());keyframes.push_back(image.FrameType()==webrtc::VideoFrameType::kVideoFrameKey);
    if(inspect_binding){
      if(!image.data() || image.size()>4*1024*1024){valid=false;return Result(Result::ERROR_SEND_FAILED);}
      std::vector<uint8_t> packet(image.size());std::memcpy(packet.data(),image.data(),packet.size());
      const auto metadata=remote::h264_frame_metadata(packet);
      if(!metadata || remote::decode_video_binding(*metadata).rtp_timestamp!=image.RtpTimestamp())valid=false;
    }
    if(image._encodedWidth!=320 || image._encodedHeight!=180 || decoder->Decode(image,0)!=WEBRTC_VIDEO_CODEC_OK)valid=false;
    return Result(Result::OK,image.RtpTimestamp());
  }
  void OnFrameDropped(uint32_t,int,bool) override {++dropped;}
  int32_t Decoded(webrtc::VideoFrame& frame) override {
    ++decoded;auto image=frame.video_frame_buffer()->ToI420();
    if(!image || image->width()!=320 || image->height()!=180 || *image->DataY()<100)valid=false;
    return 0;
  }
};
bool expired_binding_recovery(unsigned retired_begin,unsigned retired_count){
  auto metrics=std::make_shared<remote::CodecMetrics>();
  // Fault injected at the real post-MFT metadata lookup: the epoch was valid
  // before encoding, but the 1s binding has expired when output is ready.
  // The expired stamp MUST stay unavailable; never extend its lifetime.
  metrics->epoch_for_frame=[](uint32_t){return std::uint64_t(1);};
  metrics->frame_metadata=[=](uint32_t stamp){
    const auto index=(stamp-1000)/3000;
    if(index>=retired_begin && index<retired_begin+retired_count)return std::vector<uint8_t>();
    remote::ipc::Session id{};id[0]=1;
    return remote::encode_video_binding({{id,1,(stamp-1000)/3000+1,GetTickCount64(),0,320,180},1,stamp});
  };
  auto env=webrtc::CreateEnvironment();remote::MfEncoderFactory encoders(metrics);remote::MfDecoderFactory decoders(metrics);
  auto encoder=encoders.Create(env,encoders.GetSupportedFormats()[0]);auto decoder=decoders.Create(env,decoders.GetSupportedFormats()[0]);
  if(!encoder || !decoder)return false;
  Callback callback;callback.decoder=decoder.get();callback.inspect_binding=true;
  encoder->RegisterEncodeCompleteCallback(&callback);decoder->RegisterDecodeCompleteCallback(&callback);
  webrtc::VideoCodec settings{};settings.codecType=webrtc::kVideoCodecH264;settings.width=320;settings.height=180;settings.maxFramerate=30;settings.startBitrate=1000;
  webrtc::VideoEncoder::Settings options(webrtc::VideoEncoder::Capabilities(false),2,1200);
  webrtc::VideoDecoder::Settings decode;decode.set_codec_type(webrtc::kVideoCodecH264);decode.set_max_render_resolution(webrtc::RenderResolution(1920,1080));
  if(encoder->InitEncode(&settings,options)!=0 || !decoder->Configure(decode))return false;
  auto pixels=webrtc::I420Buffer::Create(320,180);
  std::memset(pixels->MutableDataY(),160,pixels->StrideY()*180);std::memset(pixels->MutableDataU(),128,pixels->StrideU()*90);std::memset(pixels->MutableDataV(),128,pixels->StrideV()*90);
  unsigned errors=0;
  for(unsigned i=0;i<12;++i){
    const std::vector<webrtc::VideoFrameType> types={i==0?webrtc::VideoFrameType::kVideoFrameKey:webrtc::VideoFrameType::kVideoFrameDelta};
    auto frame=webrtc::VideoFrame::Builder().set_video_frame_buffer(pixels).set_rtp_timestamp(1000+i*3000).build();
    if(encoder->Encode(frame,&types)!=0)++errors;
  }
  std::vector<uint32_t> expected;
  for(unsigned i=0;i<12;++i)if(i<retired_begin || i>=retired_begin+retired_count)expected.push_back(1000+i*3000);
  const bool identity=callback.stamps==expected;
  const bool idr=retired_begin+retired_count==12 || (callback.keyframes.size()>retired_begin && callback.keyframes.at(retired_begin));
  const bool passed=callback.valid && identity && idr && callback.decoded==12-retired_count && callback.dropped==retired_count && errors==0 && metrics->failures==0 && metrics->unknown_frame_timestamps==retired_count;
  encoder->Release();decoder->Release();
  std::cout<<"{\"expired_binding_recovery\":"<<(passed?"true":"false")<<",\"retired_begin\":"<<retired_begin<<",\"retired_count\":"<<retired_count<<",\"encoded\":"<<callback.encoded
    <<",\"decoded\":"<<callback.decoded<<",\"dropped\":"<<callback.dropped<<",\"encode_errors\":"<<errors
    <<",\"next_frame_IDR\":"<<(idr?"true":"false")<<",\"stamp_identity\":"<<(identity?"true":"false")
    <<",\"codec_failures\":"<<metrics->failures.load()<<",\"desktop_capture\":false,\"OS_input\":false}\n";
  return passed;
}
}
bool dynamic_rate_test(){
  const auto fail=[](const char* stage){std::cerr<<"dynamic_rate_failure:"<<stage<<"\n";return false;};
  std::vector<std::uint8_t> nv12(320*180*3/2,128);std::fill_n(nv12.begin(),320*180,160);
  {
    remote::H264Encoder software(320,180,30,1000000,remote::EncoderPreference::software_only);unsigned step=0;
    for(unsigned bitrate:{900000u,700000u,400000u,600000u}){
      if(!software.set_bitrate(bitrate)){const auto diagnostic=software.selection();
        std::cerr<<"live_rate_hresult:"<<diagnostic.rejected_hresult<<" line:"<<diagnostic.rejected_line<<"\n";return fail("software_live_rate");}
      if(software.encode(nv12,step==0,1000000+step*50000).empty())return fail("software_encode");++step;
    }
    if(software.set_bitrate(0) || software.set_bitrate(20000001))return fail("invalid_rate_accepted");
  }
  auto metrics=std::make_shared<remote::CodecMetrics>();std::uint64_t epoch=1;metrics->epoch_for_frame=[&](std::uint32_t){return epoch;};
  auto env=webrtc::CreateEnvironment();remote::MfEncoderFactory encoders(metrics);remote::MfDecoderFactory decoders(metrics);
  auto encoder=encoders.Create(env,encoders.GetSupportedFormats()[0]);auto decoder=decoders.Create(env,decoders.GetSupportedFormats()[0]);
  if(!encoder || !decoder)return fail("factory");Callback callback;callback.decoder=decoder.get();encoder->RegisterEncodeCompleteCallback(&callback);decoder->RegisterDecodeCompleteCallback(&callback);
  webrtc::VideoCodec settings{};settings.codecType=webrtc::kVideoCodecH264;settings.width=320;settings.height=180;settings.maxFramerate=30;settings.startBitrate=1000;
  webrtc::VideoEncoder::Settings options(webrtc::VideoEncoder::Capabilities(false),2,1200);webrtc::VideoDecoder::Settings decode;decode.set_codec_type(webrtc::kVideoCodecH264);decode.set_max_render_resolution(webrtc::RenderResolution(1920,1080));
  if(encoder->InitEncode(&settings,options)!=0 || !decoder->Configure(decode))return fail("initialize");
  auto pixels=webrtc::I420Buffer::Create(320,180);std::memset(pixels->MutableDataY(),160,pixels->StrideY()*180);
  std::memset(pixels->MutableDataU(),128,pixels->StrideU()*90);std::memset(pixels->MutableDataV(),128,pixels->StrideV()*90);
  unsigned settled=0,initial=0;
  for(unsigned i=0;i<13;++i){
    if(i){webrtc::VideoBitrateAllocation rate;if(i!=2)rate.SetBitrate(0,0,i==1?800000:600000);
      encoder->SetRates(webrtc::VideoEncoder::RateControlParameters(rate,i%2?15:20));
      if(i==1 && metrics->target_bitrate!=800000)return fail("immediate_reduction");
      if(i==3 && metrics->target_bitrate!=600000)return fail("resume_reduction");
    }
    const std::vector<webrtc::VideoFrameType> types={i==0?webrtc::VideoFrameType::kVideoFrameKey:webrtc::VideoFrameType::kVideoFrameDelta};
    auto frame=webrtc::VideoFrame::Builder().set_video_frame_buffer(pixels).set_timestamp_us(1000000+i*50000).set_rtp_timestamp(1000+i*4500).build();
    if(encoder->Encode(frame,&types)!=0)return fail("encode");
    if(i==0)initial=metrics->codec_rebuilds.load();if(i==3)settled=metrics->codec_rebuilds.load();
    if(i>3 && (metrics->codec_rebuilds!=settled || callback.keyframes.empty() || callback.keyframes.back()))return fail("fps_only_rebuild_or_IDR");
  }
  const bool initial_rates=metrics->bitrate_failures>0 || (metrics->bitrate_updates>=2 && initial==settled);
  const auto rate=[&](unsigned bitrate){webrtc::VideoBitrateAllocation value;value.SetBitrate(0,0,bitrate);
    encoder->SetRates(webrtc::VideoEncoder::RateControlParameters(value,15));};
  const auto submit=[&](unsigned i){
    const std::vector<webrtc::VideoFrameType> delta{webrtc::VideoFrameType::kVideoFrameDelta};
    auto frame=webrtc::VideoFrame::Builder().set_video_frame_buffer(pixels).set_timestamp_us(1000000+i*50000).set_rtp_timestamp(1000+i*4500).build();
    return encoder->Encode(frame,&delta)==0;};
  rate(500000);if(metrics->target_bitrate!=500000)return fail("second_reduction");
  rate(900000);rate(1000000);if(metrics->target_bitrate!=500000 || !submit(13) || metrics->target_bitrate!=500000)return fail("increase_coalescing");
  Sleep(1050);if(!submit(14) || metrics->target_bitrate!=1000000)return fail("pending_increase");
  rate(1010000);Sleep(1050);if(!submit(15) || metrics->target_bitrate!=1000000)return fail("small_increase");
  const auto before_epoch=metrics->codec_rebuilds.load();epoch=2;
  if(!submit(16) || metrics->codec_rebuilds!=before_epoch+1 || !callback.keyframes.back())return fail("epoch_rebuild_and_IDR");
  const bool passed=callback.valid && callback.encoded==16 && callback.decoded==16 && callback.dropped==1 && metrics->failures==0 &&
    metrics->target_bitrate==1000000 && metrics->encode_us.snapshot()[0]==16 && initial_rates;
  std::cout<<"{\"dynamic_rates_passed\":"<<(passed?"true":"false")<<",\"software_live_bitrate_updates\":4,\"fps_change_rebuilds\":0,\"target_bitrate\":"<<metrics->target_bitrate.load()
    <<",\"live_updates\":"<<metrics->bitrate_updates.load()<<",\"update_fallbacks\":"<<metrics->bitrate_failures.load()<<",\"pause_dropped\":"<<callback.dropped
    <<",\"increase_coalescing\":true,\"small_increase_ignored\":true,\"desktop_epoch_rebuild_and_IDR\":true,\"desktop_capture\":false,\"OS_input\":false}\n";
  encoder->Release();decoder->Release();return passed;
}
int main(int argc,char** argv) {
  if(FAILED(CoInitializeEx(nullptr,COINIT_MULTITHREADED)))return 2;
  if(FAILED(MFStartup(MF_VERSION))){CoUninitialize();return 3;}
  if(argc==2){
#pragma clang unsafe_buffer_usage begin
    const std::string mode(argv[1]);
#pragma clang unsafe_buffer_usage end
    if(mode=="--dynamic-rates"){const bool passed=dynamic_rate_test();MFShutdown();CoUninitialize();return passed?0:6;}
    if(mode!="--expired-binding"){MFShutdown();CoUninitialize();return 2;}
    const bool passed=expired_binding_recovery(2,1) && expired_binding_recovery(2,3) && expired_binding_recovery(0,1) && expired_binding_recovery(0,12);MFShutdown();CoUninitialize();return passed?0:6;
  }
  if(argc!=1){MFShutdown();CoUninitialize();return 2;}
  auto metrics=std::make_shared<remote::CodecMetrics>();auto env=webrtc::CreateEnvironment();
  remote::MfEncoderFactory encoders(metrics);remote::MfDecoderFactory decoders(metrics);
  auto encoder=encoders.Create(env,encoders.GetSupportedFormats()[0]);
  auto decoder=decoders.Create(env,decoders.GetSupportedFormats()[0]);
  if(!encoder || !decoder)return 4;
  Callback callback;callback.decoder=decoder.get();encoder->RegisterEncodeCompleteCallback(&callback);decoder->RegisterDecodeCompleteCallback(&callback);
  webrtc::VideoCodec settings{};settings.codecType=webrtc::kVideoCodecH264;
  settings.width=320;settings.height=180;settings.maxFramerate=30;settings.startBitrate=1000;
  webrtc::VideoEncoder::Settings options(webrtc::VideoEncoder::Capabilities(false),2,1200);
  webrtc::VideoDecoder::Settings decode;decode.set_codec_type(webrtc::kVideoCodecH264);
  decode.set_max_render_resolution(webrtc::RenderResolution(1920,1080));
  if(encoder->InitEncode(&settings,options)!=0 || !decoder->Configure(decode))return 5;
  auto pixels=webrtc::I420Buffer::Create(320,180);
  std::memset(pixels->MutableDataY(),160,pixels->StrideY()*180);
  std::memset(pixels->MutableDataU(),128,pixels->StrideU()*90);std::memset(pixels->MutableDataV(),128,pixels->StrideV()*90);
  bool valid=true;
  for(unsigned i=0;i<20;++i) {
    if(i==5)encoder->SetRates(webrtc::VideoEncoder::RateControlParameters(webrtc::VideoBitrateAllocation(),30));
    if(i==6){webrtc::VideoBitrateAllocation rate;rate.SetBitrate(0,0,300000);encoder->SetRates(webrtc::VideoEncoder::RateControlParameters(rate,30));}
    const std::vector<webrtc::VideoFrameType> types={i==0?webrtc::VideoFrameType::kVideoFrameKey:webrtc::VideoFrameType::kVideoFrameDelta};
    auto frame=webrtc::VideoFrame::Builder().set_video_frame_buffer(pixels).set_rtp_timestamp(1000+i*3000).build();
    if(encoder->Encode(frame,&types)!=0)valid=false;
  }
  settings.width=4096;settings.height=4096;
  const bool oversized_rejected=encoder->InitEncode(&settings,options)!=0;
  auto invalid_frame=webrtc::VideoFrame::Builder().set_video_frame_buffer(pixels).set_rtp_timestamp(999999).build();
  const bool old_encoder_disabled=encoder->Encode(invalid_frame,nullptr)==WEBRTC_VIDEO_CODEC_UNINITIALIZED;
  const bool empty_rejected=decoder->Decode(webrtc::EncodedImage(),0)!=0;
  std::vector<uint8_t> fragmented;fragmented.reserve(257*5);
  for(unsigned i=0;i<257;++i)fragmented.insert(fragmented.end(),{0,0,0,1,9});
  webrtc::EncodedImage excessive_nalus;
  excessive_nalus.SetEncodedData(webrtc::EncodedImageBuffer::Create(fragmented.data(),fragmented.size()));
  const bool excessive_nalus_rejected=decoder->Decode(excessive_nalus,0)==WEBRTC_VIDEO_CODEC_ERR_PARAMETER;
  decoder->Release();
  const bool released_decoder_rejected=decoder->Decode(callback.last,0)==WEBRTC_VIDEO_CODEC_UNINITIALIZED;
  decode.set_codec_type(webrtc::kVideoCodecVP8);
  const bool failed_configuration_rejected=!decoder->Configure(decode) && decoder->Decode(callback.last,0)==WEBRTC_VIDEO_CODEC_UNINITIALIZED;
  const bool passed=valid && callback.valid && callback.encoded==19 && callback.decoded==19 && callback.dropped==1 &&
    metrics->failures==0 && oversized_rejected && empty_rejected && excessive_nalus_rejected && old_encoder_disabled && released_decoder_rejected && failed_configuration_rejected;
  encoder->Release();decoder->Release();encoder.reset();decoder.reset();
  MFShutdown();CoUninitialize();
  std::cout<<"{\"passed\":"<<(passed?"true":"false")<<",\"owned_frames\":20,\"encoded\":"<<callback.encoded
    <<",\"decoded\":"<<callback.decoded<<",\"paused_dropped\":"<<callback.dropped
    <<",\"codec_failures\":"<<metrics->failures.load()<<",\"oversized_rejected\":"<<(oversized_rejected?"true":"false")
    <<",\"empty_rejected\":"<<(empty_rejected?"true":"false")
    <<",\"excessive_nalus_rejected\":"<<(excessive_nalus_rejected?"true":"false")
    <<",\"old_encoder_disabled\":"<<(old_encoder_disabled?"true":"false")
    <<",\"released_decoder_rejected\":"<<(released_decoder_rejected?"true":"false")
    <<",\"failed_configuration_rejected\":"<<(failed_configuration_rejected?"true":"false")
    <<",\"RTP_tested\":false,\"desktop_capture\":false,\"os_input\":false}\n";
  return passed?0:6;
}
