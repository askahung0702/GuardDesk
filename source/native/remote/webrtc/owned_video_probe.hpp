#pragma once
// Synthetic test harness only: no screen, camera, microphone or OS input.
#include <windows.h>
#include <mfapi.h>
#include <algorithm>
#include <array>
#include <mutex>
#include <span>
#include "mf_codec_adapter.hpp"
#include "api/enable_media.h"
#include "api/audio/create_audio_device_module.h"
#include "api/audio_codecs/audio_encoder_factory.h"
#include "api/audio_codecs/audio_decoder_factory.h"
#include "api/rtp_transceiver_interface.h"
#include "api/video/adapted_video_track_source.h"
#include "api/video/i420_buffer.h"
#ifdef GD_OWNED_PIPELINE_PROBE
#include "frame_bridge.hpp"
#include "viewer.hpp"
#endif

namespace owned {
inline int64_t steady_us(){return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();}
struct VideoStats {
  std::array<std::atomic<int64_t>,100> sent{};
  std::array<bool,100> seen{};
  std::mutex lock;
  std::vector<double> latency_ms;
  int64_t first_us=0,last_us=0;
  double p95(){std::lock_guard<std::mutex> guard(lock);auto values=latency_ms;if(values.empty())return -1;std::sort(values.begin(),values.end());return values[(values.size()*95-1)/100];}
  double fps(){std::lock_guard<std::mutex> guard(lock);return latency_ms.size()>1 && last_us>first_us?(latency_ms.size()-1)*1000000.0/(last_us-first_us):0;}
};
class MediaRuntime {
  bool com_=false,mf_=false;
 public:
  MediaRuntime(){com_=SUCCEEDED(CoInitializeEx(nullptr,COINIT_MULTITHREADED));if(com_)mf_=SUCCEEDED(MFStartup(MF_VERSION));}
  bool ready() const{return mf_;}
  ~MediaRuntime(){if(mf_)MFShutdown();if(com_)CoUninitialize();}
};
class NoAudioEncoder : public webrtc::AudioEncoderFactory {
 public:
  std::vector<webrtc::AudioCodecSpec> GetSupportedEncoders() override{return {};}
  std::optional<webrtc::AudioCodecInfo> QueryAudioEncoder(const webrtc::SdpAudioFormat&) override{return std::nullopt;}
  std::unique_ptr<webrtc::AudioEncoder> Create(const webrtc::Environment&,const webrtc::SdpAudioFormat&,Options) override{return nullptr;}
};
class NoAudioDecoder : public webrtc::AudioDecoderFactory {
 public:
  std::vector<webrtc::AudioCodecSpec> GetSupportedDecoders() override{return {};}
  bool IsSupportedDecoder(const webrtc::SdpAudioFormat&) override{return false;}
  std::unique_ptr<webrtc::AudioDecoder> Create(const webrtc::Environment&,const webrtc::SdpAudioFormat&) override{return nullptr;}
};
inline bool configure(webrtc::PeerConnectionFactoryDependencies& deps,std::shared_ptr<remote::CodecMetrics> metrics){
  if(!deps.env)return false;
  deps.adm=webrtc::CreateAudioDeviceModule(*deps.env,webrtc::AudioDeviceModule::kDummyAudio);
  if(!deps.adm)return false; // Never fall back to a real audio device.
  deps.audio_encoder_factory=webrtc::make_ref_counted<NoAudioEncoder>();
  deps.audio_decoder_factory=webrtc::make_ref_counted<NoAudioDecoder>();
  deps.video_encoder_factory=std::make_unique<remote::MfEncoderFactory>(metrics);
  deps.video_decoder_factory=std::make_unique<remote::MfDecoderFactory>(metrics);
  webrtc::EnableMedia(deps);return true;
}
class Source : public webrtc::AdaptedVideoTrackSource {
  std::shared_ptr<VideoStats> stats_;
  unsigned width_,height_;
 public:
  Source(std::shared_ptr<VideoStats> stats,unsigned width,unsigned height):stats_(std::move(stats)),width_(width),height_(height){}
  SourceState state() const override{return kLive;}
  bool remote() const override{return false;}
  bool is_screencast() const override{return true;}
  std::optional<bool> needs_denoising() const override{return false;}
  void push(unsigned index){
    if(index>=stats_->sent.size())return;
    auto pixels=webrtc::I420Buffer::Create(width_,height_);
    std::memset(pixels->MutableDataY(),140+index%30,pixels->StrideY()*height_);
    std::memset(pixels->MutableDataU(),128,pixels->StrideU()*(height_/2));
    std::memset(pixels->MutableDataV(),128,pixels->StrideV()*(height_/2));
    // Own frame ID survives lossy encoding; no cross-machine wall-clock math.
    auto luma=std::span<uint8_t>(pixels->MutableDataY(),pixels->StrideY()*height_);
    for(unsigned bit=0;bit<7;++bit)for(unsigned row=20;row<36;++row){
      auto block=luma.subspan(row*pixels->StrideY()+20+bit*24,16);
      std::fill(block.begin(),block.end(),index&(1u<<bit)?224:32);
    }
    const auto us=steady_us();stats_->sent[index].store(us,std::memory_order_release);
    OnFrame(webrtc::VideoFrame::Builder().set_video_frame_buffer(pixels).set_timestamp_us(us).build());
  }
};
class Sink : public webrtc::VideoSinkInterface<webrtc::VideoFrame> {
 public:
#ifdef GD_OWNED_PIPELINE_PROBE
  std::shared_ptr<remote::FrameSink> native;
#endif
  std::shared_ptr<VideoStats> stats;
  unsigned width=320,height=180;
  std::atomic<unsigned> frames{0};std::atomic<bool> valid{true};
  void OnFrame(const webrtc::VideoFrame& frame) override{
#ifdef GD_OWNED_PIPELINE_PROBE
    if(native)native->OnFrame(frame);
#endif
    auto pixels=frame.video_frame_buffer()->ToI420();
    if(!pixels || pixels->width()!=static_cast<int>(width) || pixels->height()!=static_cast<int>(height) || *pixels->DataY()<130 || *pixels->DataY()>180)valid=false;
    else if(stats){
      const auto luma=std::span<const uint8_t>(pixels->DataY(),pixels->StrideY()*height);
      unsigned index=0;for(unsigned bit=0;bit<7;++bit)if(luma[28*pixels->StrideY()+28+bit*24]>128)index|=1u<<bit;
      if(index>=stats->sent.size())valid=false;
      else{
        const auto sent=stats->sent[index].load(std::memory_order_acquire),now=steady_us();
        std::lock_guard<std::mutex> guard(stats->lock);
        if(!sent || now<sent)valid=false;
        else if(!stats->seen[index]){stats->seen[index]=true;if(!stats->first_us)stats->first_us=now;stats->last_us=now;stats->latency_ms.push_back((now-sent)/1000.0);}
      }
    }else valid=false;
    ++frames;
  }
};
#ifdef GD_OWNED_PIPELINE_PROBE
inline remote::ipc::Session pipeline_session(){remote::ipc::Session value{};value.at(0)=7;return value;}
class PipelineWindow {
  HWND window_=nullptr;
 public:
  std::unique_ptr<remote::NativeViewer> viewer;
  std::atomic<unsigned> submitted{0};
  PipelineWindow(){
    WNDCLASSW kind{};kind.lpfnWndProc=DefWindowProcW;kind.hInstance=GetModuleHandleW(nullptr);kind.lpszClassName=L"GuardDeskOwnedPipelineHidden";
    if(!RegisterClassW(&kind))throw std::runtime_error("pipeline_window_class");
    window_=CreateWindowExW(0,kind.lpszClassName,L"GuardDesk owned hidden media pipeline",WS_OVERLAPPED,0,0,320,180,nullptr,nullptr,kind.hInstance,nullptr);
    if(!window_)throw std::runtime_error("pipeline_window");
    viewer=std::make_unique<remote::NativeViewer>(window_,pipeline_session(),true);
  }
  ~PipelineWindow(){viewer.reset();if(window_)DestroyWindow(window_);}
};
class PipelineSource : public remote::FrameSource {
  std::shared_ptr<VideoStats> stats_;
  unsigned width_,height_;
  remote::FramePool pool_;
  HANDLE read_=nullptr;
 public:
  PipelineSource(std::shared_ptr<VideoStats> stats,unsigned width,unsigned height,std::shared_ptr<remote::FrameBindings> bindings,
    std::function<bool(const std::vector<std::uint8_t>&)> metadata)
    :remote::FrameSource(std::move(bindings),1,std::move(metadata)),stats_(std::move(stats)),width_(width),height_(height),pool_(pipeline_session(),width,height){
    read_=pool_.duplicate_read(0,GetCurrentProcess());
  }
  ~PipelineSource() override{if(read_)CloseHandle(read_);}
  void push(unsigned index){
    const auto generation=index<50?1ull:2ull;
    remote::Pixels pixels{width_,height_,std::vector<std::uint8_t>(std::size_t(width_)*height_*4)};
    const auto grey=static_cast<std::uint8_t>((140+index%30-16)*255/219);
    for(std::size_t i=0;i<pixels.bgra.size();i+=4){pixels.bgra.at(i)=grey;pixels.bgra.at(i+1)=grey;pixels.bgra.at(i+2)=grey;pixels.bgra.at(i+3)=255;}
    for(unsigned bit=0;bit<7;++bit)for(unsigned y=20;y<36;++y)for(unsigned x=20+bit*24;x<36+bit*24;++x){
      const auto at=(std::size_t(y)*width_+x)*4;const auto color=static_cast<std::uint8_t>(index&(1u<<bit)?242:19);
      pixels.bgra.at(at)=pixels.bgra.at(at+1)=pixels.bgra.at(at+2)=color;
    }
    remote::FrameTicket ticket{};const auto tick=GetTickCount64();
    if(!pool_.publish(pixels,generation,index+1,tick,ticket))throw std::runtime_error("pipeline_publish");
    auto shared=remote::read_shared_frame(read_,pool_.mapping_bytes(),pipeline_session(),generation,tick);
    if(!pool_.release(ticket))throw std::runtime_error("pipeline_consumed");
    stats_->sent.at(index).store(steady_us(),std::memory_order_release);
    if(!remote::FrameSource::push(shared))throw std::runtime_error("pipeline_source_push");
  }
};
#endif
}
