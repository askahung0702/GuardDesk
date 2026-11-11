// Owned loopback transport probe. No desktop, media device, UAC or OS input.
// SDP/ICE stay in RAM; sockets use a synthetic 127.0.0.1-only network manager.
#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include "api/create_modular_peer_connection_factory.h"
#include "api/data_channel_interface.h"
#include "api/environment/environment_factory.h"
#include "api/jsep.h"
#include "api/make_ref_counted.h"
#include "api/peer_connection_interface.h"
#include "api/set_local_description_observer_interface.h"
#include "api/set_remote_description_observer_interface.h"
#include "p2p/base/basic_packet_socket_factory.h"
#include "rtc_base/network.h"
#include "rtc_base/logging.h"
#include "rtc_base/ssl_adapter.h"
#include "rtc_base/thread.h"
#include "rtc_base/win32_socket_init.h"
#ifdef GD_OWNED_VIDEO_PROBE
#include "owned_video_probe.hpp"
#endif
#ifdef GD_OWNED_WIRE_PROBE
#include "owned_control_probe.hpp"
#endif

namespace {
using namespace std::chrono_literals;
class LoopbackNetwork final : public webrtc::NetworkManagerBase {
 public:
  void StartUpdating() override {
    webrtc::IPAddress ip;webrtc::IPFromString("127.0.0.1",&ip);
    auto network=std::make_unique<webrtc::Network>("owned-loopback","owned-loopback",ip,8,webrtc::ADAPTER_TYPE_LOOPBACK);
    network->AddIP(ip);
    std::vector<std::unique_ptr<webrtc::Network>> networks;networks.push_back(std::move(network));
    bool changed=false;MergeNetworkList(std::move(networks),&changed);NotifyNetworksChanged();
  }
  void StopUpdating() override {}
  std::vector<const webrtc::Network*> GetAnyAddressNetworks() override {return {};}
};
class Created : public webrtc::CreateSessionDescriptionObserver {
 public:
  std::promise<std::unique_ptr<webrtc::SessionDescriptionInterface>> result;
  void OnSuccess(webrtc::SessionDescriptionInterface* description) override {result.set_value(std::unique_ptr<webrtc::SessionDescriptionInterface>(description));}
  void OnFailure(webrtc::RTCError) override {result.set_value(nullptr);}
};
class LocalSet : public webrtc::SetLocalDescriptionObserverInterface {
 public:
  std::promise<bool> result;
  void OnSetLocalDescriptionComplete(webrtc::RTCError error) override {result.set_value(error.ok());}
};
class RemoteSet : public webrtc::SetRemoteDescriptionObserverInterface {
 public:
  std::promise<bool> result;
  void OnSetRemoteDescriptionComplete(webrtc::RTCError error) override {result.set_value(error.ok());}
};
class Observer final : public webrtc::PeerConnectionObserver,public webrtc::DataChannelObserver {
 public:
  std::atomic<bool> gathered=false,open=false,received=false,invalid=false;
  std::atomic<unsigned> candidates{0};
  std::atomic<int> ice_state{0},connection_state{0},candidate_error{0};
  std::atomic<unsigned> sdp_candidates{0};
  std::atomic<bool> application{false},fingerprint{false},rejected{false};
  webrtc::scoped_refptr<webrtc::DataChannelInterface> channel;
#ifdef GD_OWNED_WIRE_PROBE
  owned_control::Wire wire;
#endif
#ifdef GD_OWNED_VIDEO_PROBE
  owned::Sink video_sink;
  webrtc::scoped_refptr<webrtc::VideoTrackInterface> video_track;
  void OnTrack(webrtc::scoped_refptr<webrtc::RtpTransceiverInterface> transceiver) override{
    auto track=transceiver->receiver()->track();
    if(track && track->kind()==webrtc::MediaStreamTrackInterface::kVideoKind){
      video_track=static_cast<webrtc::VideoTrackInterface*>(track.get());
      video_track->AddOrUpdateSink(&video_sink,webrtc::VideoSinkWants());
    }else invalid=true;
  }
  void detach_video(){if(video_track){video_track->RemoveSink(&video_sink);video_track=nullptr;}}
#endif
  void OnSignalingChange(webrtc::PeerConnectionInterface::SignalingState) override {}
  void OnIceGatheringChange(webrtc::PeerConnectionInterface::IceGatheringState state) override {
    gathered=state==webrtc::PeerConnectionInterface::kIceGatheringComplete;
  }
  void OnIceCandidate(const webrtc::IceCandidate*) override {++candidates;}
  void OnStandardizedIceConnectionChange(webrtc::PeerConnectionInterface::IceConnectionState state) override {ice_state=static_cast<int>(state);}
  void OnConnectionChange(webrtc::PeerConnectionInterface::PeerConnectionState state) override {connection_state=static_cast<int>(state);}
  void OnIceCandidateError(const std::string&,int,const std::string&,int code,const std::string&) override {candidate_error=code;}
  void OnDataChannel(webrtc::scoped_refptr<webrtc::DataChannelInterface> value) override {
    channel=std::move(value);channel->RegisterObserver(this);
    OnStateChange(); // The remote channel may already be open at registration.
  }
  void OnStateChange() override {open=channel && channel->state()==webrtc::DataChannelInterface::kOpen;}
  void OnMessage(const webrtc::DataBuffer& value) override {
#ifdef GD_OWNED_PIPELINE_PROBE
    if(value.binary){
      if(value.size()!=88 || !video_sink.native){invalid=true;return;}
      std::vector<std::uint8_t> packet(value.size());std::memcpy(packet.data(),value.data.cdata(),value.size());
      if(!video_sink.native->metadata(packet))invalid=true;return;
    }
#endif
#ifdef GD_OWNED_WIRE_PROBE
    wire.receive(value);
#else
    // One fixed, non-sensitive payload. Never log the remote packet.
    constexpr char expected[]="owned-control-epoch";
    if(value.binary || value.size()!=sizeof(expected)-1 ||
        std::memcmp(value.data.cdata(),expected,sizeof(expected)-1)!=0) invalid=true;
    else received=true;
#endif
  }
};
bool await(std::atomic<bool>& flag) {
  const auto end=std::chrono::steady_clock::now()+12s;
  while(!flag && std::chrono::steady_clock::now()<end) std::this_thread::sleep_for(10ms);
  return flag;
}
bool negotiate(webrtc::PeerConnectionInterface* sender,webrtc::PeerConnectionInterface* receiver,
               Observer& observed,bool offer) {
  auto created=webrtc::make_ref_counted<Created>();auto description=created->result.get_future();
  webrtc::PeerConnectionInterface::RTCOfferAnswerOptions options;
  if(offer) sender->CreateOffer(created.get(),options);else sender->CreateAnswer(created.get(),options);
  if(description.wait_for(12s)!=std::future_status::ready) return false;
  auto value=description.get();if(!value) return false;
  auto local=webrtc::make_ref_counted<LocalSet>();auto local_done=local->result.get_future();
  sender->SetLocalDescription(std::move(value),local);
  if(local_done.wait_for(12s)!=std::future_status::ready || !local_done.get() || !await(observed.gathered)) return false;
  std::string text;
  if(!sender->local_description() || !sender->local_description()->ToString(&text) || text.size()>65536) return false;
  for(size_t at=0;(at=text.find("a=candidate:",at))!=std::string::npos;++at) ++observed.sdp_candidates;
  observed.application=text.find("m=application ")!=std::string::npos;
  observed.rejected=text.find("m=application 0 ")!=std::string::npos;
  observed.fingerprint=text.find("a=fingerprint:sha-256 ")!=std::string::npos;
  auto remote_value=webrtc::CreateSessionDescription(offer?webrtc::SdpType::kOffer:webrtc::SdpType::kAnswer,text);
  if(!remote_value) return false;
  auto remote=webrtc::make_ref_counted<RemoteSet>();auto remote_done=remote->result.get_future();
  receiver->SetRemoteDescription(std::move(remote_value),remote);
  return remote_done.wait_for(12s)==std::future_status::ready && remote_done.get();
}
}

int main(int argc,char** argv) {
#ifdef GD_OWNED_VIDEO_PROBE
  const bool full_hd=argc==2 && std::strcmp(argv[1],"--owned-1080p")==0;
  if(argc!=1 && !full_hd)return 2;
  const unsigned video_width=full_hd?1920:320,video_height=full_hd?1080:180;
#else
  (void)argv;if(argc!=1)return 2;
#endif
  webrtc::WinsockInitializer winsock;if(winsock.error())return 2;
#ifdef GD_OWNED_VIDEO_PROBE
  owned::MediaRuntime media_runtime;if(!media_runtime.ready())return 2;
  auto codec_metrics=std::make_shared<remote::CodecMetrics>();
  auto decoder_metrics=codec_metrics;
#ifdef GD_OWNED_PIPELINE_PROBE
  auto tx_bindings=std::make_shared<remote::FrameBindings>(owned::pipeline_session(),1);
  auto rx_bindings=std::make_shared<remote::FrameBindings>(owned::pipeline_session(),1);
  decoder_metrics=std::make_shared<remote::CodecMetrics>();
  codec_metrics->epoch_for_frame=[tx_bindings](std::uint32_t stamp){auto binding=tx_bindings->find(stamp,GetTickCount64());return binding?binding->frame.generation:0;};
  codec_metrics->frame_metadata=[tx_bindings](std::uint32_t stamp){auto binding=tx_bindings->find(stamp,GetTickCount64());return binding?remote::encode_video_binding(*binding):std::vector<std::uint8_t>();};
  decoder_metrics->epoch_for_frame=[rx_bindings](std::uint32_t stamp){auto binding=rx_bindings->find(stamp,GetTickCount64());return binding?binding->frame.generation:0;};
#endif
#endif
  // No SDP, ICE credentials, packet content or peer certificate dumps in logs.
  webrtc::LogMessage::LogToDebug(webrtc::LS_NONE);
  webrtc::LogMessage::SetLogToStderr(false);
  if(!webrtc::InitializeSSL()) return 2;
  auto network=webrtc::Thread::CreateWithSocketServer();auto signaling=webrtc::Thread::Create();
  if(!network->Start() || !signaling->Start()) return 3;
  auto make_factory=[&](bool receiver) {
    (void)receiver;
    webrtc::PeerConnectionFactoryDependencies dependencies;
    dependencies.env=webrtc::CreateEnvironment();dependencies.network_thread=network.get();dependencies.signaling_thread=signaling.get();
    dependencies.network_manager=std::make_unique<LoopbackNetwork>();
    dependencies.packet_socket_factory=std::make_unique<webrtc::BasicPacketSocketFactory>(network->socketserver());
#ifdef GD_OWNED_VIDEO_PROBE
    if(!owned::configure(dependencies,receiver?decoder_metrics:codec_metrics))return webrtc::scoped_refptr<webrtc::PeerConnectionFactoryInterface>();
#endif
    auto factory=webrtc::CreateModularPeerConnectionFactory(std::move(dependencies));
    if(factory) {
      webrtc::PeerConnectionFactoryInterface::Options options;options.network_ignore_mask=0;
      factory->SetOptions(options); // encryption stays enabled by default
    }
    return factory;
  };
  auto first=make_factory(false),second=make_factory(true);if(!first || !second) return 4;
  Observer a,b;webrtc::PeerConnectionInterface::RTCConfiguration configuration;
#ifdef GD_OWNED_VIDEO_PROBE
  auto video_stats=std::make_shared<owned::VideoStats>();b.video_sink.stats=video_stats;
  b.video_sink.width=video_width;b.video_sink.height=video_height;
#ifdef GD_OWNED_PIPELINE_PROBE
  owned::PipelineWindow pipeline;
  b.video_sink.native=std::make_shared<remote::FrameSink>(rx_bindings,
    [&](std::uint64_t generation){pipeline.viewer->state(generation,true);},
    [&](remote::SharedFrame frame){const auto accepted=pipeline.viewer->submit(std::move(frame));if(accepted)++pipeline.submitted;return accepted;});
  std::atomic<unsigned> sei_received{0};std::atomic<std::uint32_t> sei_rtp_offset{0};std::atomic<bool> sei_offset_consistent{true};
  decoder_metrics->receive_metadata=[&](const std::vector<std::uint8_t>& packet,std::uint32_t actual_rtp){
    const auto value=remote::decode_video_binding(packet);const auto offset=actual_rtp-value.rtp_timestamp;
    if(sei_received.fetch_add(1)==0)sei_rtp_offset=offset;else if(sei_rtp_offset!=offset)sei_offset_consistent=false;
    return b.video_sink.native->encoded_metadata(packet,actual_rtp);
  };
#endif
#endif
  auto a_result=first->CreatePeerConnectionOrError(configuration,webrtc::PeerConnectionDependencies(&a));
  auto b_result=second->CreatePeerConnectionOrError(configuration,webrtc::PeerConnectionDependencies(&b));
  if(!a_result.ok() || !b_result.ok()) return 5;
  auto ap=std::move(a_result.value()),bp=std::move(b_result.value());
#ifdef GD_OWNED_VIDEO_PROBE
#ifdef GD_OWNED_PIPELINE_PROBE
  auto video_source=webrtc::make_ref_counted<owned::PipelineSource>(video_stats,video_width,video_height,tx_bindings,
    [](const std::vector<std::uint8_t>&){return true;}); // Metadata travels with pixels in H264 SEI.
#else
  auto video_source=webrtc::make_ref_counted<owned::Source>(video_stats,video_width,video_height);
#endif
  auto video_track=first->CreateVideoTrack(video_source,"owned-synthetic-video");
  auto sender=ap->AddTrack(video_track,{"owned-synthetic-stream"});if(!sender.ok())return 6;
  auto parameters=sender.value()->GetParameters();
  for(auto& encoding:parameters.encodings)encoding.max_framerate=30;
  if(!sender.value()->SetParameters(parameters).ok())return 6;
#endif
  webrtc::DataChannelInit init;init.ordered=true;
  auto data=ap->CreateDataChannelOrError("owned-control",&init);if(!data.ok()) return 6;
  a.channel=std::move(data.value());a.channel->RegisterObserver(&a);
  const bool offered=negotiate(ap.get(),bp.get(),a,true);
  const bool answered=offered && negotiate(bp.get(),ap.get(),b,false);
  const bool connected=answered
      && await(a.open) && await(b.open);
#ifdef GD_OWNED_WIRE_PROBE
  const bool control_passed=connected && owned_control::run(a,b,*signaling);
#else
  const bool sent=connected && a.channel->buffered_amount()<=65536 && a.channel->Send(webrtc::DataBuffer("owned-control-epoch"));
  const bool control_passed=sent && await(b.received) && !a.invalid && !b.invalid;
#endif
  bool passed=control_passed;
#ifdef GD_OWNED_VIDEO_PROBE
  if(passed)for(unsigned i=0;i<100;++i){video_source->push(i);std::this_thread::sleep_for(33ms);}
  const auto video_end=std::chrono::steady_clock::now()+5s;
  while(b.video_sink.frames<10 && std::chrono::steady_clock::now()<video_end)std::this_thread::sleep_for(10ms);
  const bool video_passed=b.video_sink.frames>=10 && b.video_sink.valid && codec_metrics->encoded>=10 && decoder_metrics->decoded>=10 && codec_metrics->failures==0 && decoder_metrics->failures==0;
  passed=passed && video_passed;
#ifdef GD_OWNED_PIPELINE_PROBE
  passed=passed && pipeline.submitted>=10 && !pipeline.viewer->present() && !b.invalid;
#endif
#endif
  const bool first_open=a.open.load(),second_open=b.open.load();
  const int ai=a.ice_state.load(),bi=b.ice_state.load(),ac=a.connection_state.load(),bc=b.connection_state.load();
  const int direct_ai=static_cast<int>(ap->ice_connection_state()),direct_bi=static_cast<int>(bp->ice_connection_state());
  signaling->BlockingCall([&] {
#ifdef GD_OWNED_VIDEO_PROBE
    a.detach_video();b.detach_video();video_track=nullptr;video_source=nullptr;
    sender.value()=nullptr;
#endif
    if(a.channel) a.channel->UnregisterObserver();if(b.channel) b.channel->UnregisterObserver();
    ap->Close();bp->Close();a.channel=nullptr;b.channel=nullptr;ap=nullptr;bp=nullptr;
    first=nullptr;second=nullptr;
  });
  signaling->Stop();network->Stop();webrtc::CleanupSSL();
  std::cout<<"{\"passed\":"<<(passed?"true":"false")
    <<",\"loopback_only\":true,\"dtls_sctp_control\":"<<(control_passed?"true":"false")
    <<",\"offered\":"<<(offered?"true":"false")<<",\"answered\":"<<(answered?"true":"false")
    <<",\"first_candidates\":"<<a.candidates.load()<<",\"second_candidates\":"<<b.candidates.load()
    <<",\"first_open\":"<<(first_open?"true":"false")<<",\"second_open\":"<<(second_open?"true":"false")
    <<",\"first_ice_state\":"<<ai<<",\"second_ice_state\":"<<bi<<",\"first_connection_state\":"<<ac<<",\"second_connection_state\":"<<bc
    <<",\"first_sdp_candidates\":"<<a.sdp_candidates.load()<<",\"second_sdp_candidates\":"<<b.sdp_candidates.load()
    <<",\"first_candidate_error\":"<<a.candidate_error.load()<<",\"second_candidate_error\":"<<b.candidate_error.load()
    <<",\"direct_first_ice\":"<<direct_ai<<",\"direct_second_ice\":"<<direct_bi
    <<",\"first_application\":"<<a.application<<",\"second_application\":"<<b.application
    <<",\"first_rejected\":"<<a.rejected<<",\"second_rejected\":"<<b.rejected
    <<",\"first_fingerprint\":"<<a.fingerprint<<",\"second_fingerprint\":"<<b.fingerprint
#ifdef GD_OWNED_WIRE_PROBE
    <<",\"native_wire2_control\":true,\"binary_roundtrips\":"<<a.wire.replies.load()
    <<",\"network_lease_refused\":"<<(control_passed?"true":"false")<<",\"malformed_terminal\":"<<(b.wire.failed?"true":"false")
    <<",\"center_authorization\":false,\"SYSTEM_IPC_bridge\":false"
#endif
#ifdef GD_OWNED_VIDEO_PROBE
    <<",\"video_tested\":true,\"MF_H264_RTP_SRTP\":"<<(video_passed?"true":"false")
    <<",\"encoded\":"<<codec_metrics->encoded.load()<<",\"decoded\":"<<decoder_metrics->decoded.load()
    <<",\"sink_frames\":"<<b.video_sink.frames.load()<<",\"sink_valid\":"<<b.video_sink.valid.load()
    <<",\"codec_failures\":"<<codec_metrics->failures.load()<<",\"audio_devices\":false"
    <<",\"synthetic_source_to_decoded_sink_p95_ms\":"<<video_stats->p95()<<",\"actual_present_tested\":false"
    <<",\"decoded_sink_fps\":"<<video_stats->fps()<<",\"width\":"<<video_width<<",\"height\":"<<video_height
#ifdef GD_OWNED_PIPELINE_PROBE
    <<",\"production_frame_bridge\":true,\"readonly_shared_frame_source\":true,\"native_viewer_submitted\":"<<pipeline.submitted.load()
    <<",\"two_capture_generations\":true,\"hidden_viewer_no_ACK\":true"
    <<",\"owned_first_encoded_rtp\":"<<codec_metrics->first_encoded_timestamp.load()
    <<",\"owned_first_received_rtp\":"<<decoder_metrics->first_received_timestamp.load()
    <<",\"unknown_received_frame_timestamps\":"<<decoder_metrics->unknown_frame_timestamps.load()
    <<",\"SEI_frame_bindings_received\":"<<sei_received.load()<<",\"owned_rtp_offset\":"<<sei_rtp_offset.load()
    <<",\"owned_rtp_offset_consistent\":"<<(sei_offset_consistent?"true":"false")
#endif
#else
    <<",\"video_tested\":false"
#endif
    <<",\"desktop_capture\":false,\"os_input\":false}\n";
  return passed?0:7;
}
