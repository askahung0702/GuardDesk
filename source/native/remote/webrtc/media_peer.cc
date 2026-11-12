#include "media_peer.hpp"
#include "network_guard.hpp"
#include "mf_codec_adapter.hpp"
#include <winsock2.h>
#include <iphlpapi.h>
#include <mfapi.h>
#include <atomic>
#include <chrono>
#include <deque>
#include <future>
#include <set>
#include <sstream>
#include <thread>
#include <span>
#include <stdexcept>
#include "api/create_modular_peer_connection_factory.h"
#include "api/environment/environment_factory.h"
#include "api/enable_media.h"
#include "api/make_ref_counted.h"
#include "api/peer_connection_interface.h"
#include "api/set_local_description_observer_interface.h"
#include "api/set_remote_description_observer_interface.h"
#include "api/audio/create_audio_device_module.h"
#include "api/audio_codecs/audio_encoder_factory.h"
#include "api/audio_codecs/audio_decoder_factory.h"
#include "api/rtp_transceiver_interface.h"
#include "p2p/base/basic_packet_socket_factory.h"
#include "rtc_base/network.h"
#include "rtc_base/thread.h"
#include "rtc_base/ssl_adapter.h"
#include "rtc_base/logging.h"
#include "rtc_base/win32_socket_init.h"

namespace remote {
namespace {
using namespace std::chrono_literals;
void require(bool okay){if(!okay)throw std::runtime_error("native_media_peer_rejected");}
struct PlatformState{std::mutex lock;unsigned users=0;};
PlatformState& platform(){static auto* value=new PlatformState;return *value;}
class Platform {
    bool com_=false,ready_=false;
public:
    Platform(){
        const auto initialized=CoInitializeEx(nullptr,COINIT_MULTITHREADED);com_=SUCCEEDED(initialized);
        require(com_ || initialized==RPC_E_CHANGED_MODE);
        try {auto& value=platform();std::lock_guard<std::mutex> guard(value.lock);
        if(value.users==0){require(webrtc::InitializeSSL());if(FAILED(MFStartup(MF_VERSION))){webrtc::CleanupSSL();throw std::runtime_error("native_media_platform");}}
        ++value.users;ready_=true;} catch(...) {if(com_)CoUninitialize();com_=false;throw;}
    }
    ~Platform(){if(ready_){auto& value=platform();std::lock_guard<std::mutex> guard(value.lock);if(--value.users==0){MFShutdown();webrtc::CleanupSSL();}}if(com_)CoUninitialize();}
};
MediaPeerOptions standard_options(MediaPeerOptions value){
    HANDLE token=nullptr;require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)!=FALSE);
    struct Close{HANDLE value;~Close(){CloseHandle(value);}} close{token};
    TOKEN_ELEVATION elevation{};DWORD bytes=0;
    require(GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&bytes)!=FALSE && !elevation.TokenIsElevated);
    alignas(TOKEN_USER) std::array<std::uint8_t,512> user{};
    require(GetTokenInformation(token,TokenUser,user.data(),static_cast<DWORD>(user.size()),&bytes)!=FALSE);
    require(!IsWellKnownSid(reinterpret_cast<TOKEN_USER*>(&user.at(0))->User.Sid,WinLocalSystemSid));
    require(std::any_of(value.session.begin(),value.session.end(),[](auto byte){return byte!=0;}));
    return value;
}
class NoAudioEncoder:public webrtc::AudioEncoderFactory {
public:
    std::vector<webrtc::AudioCodecSpec> GetSupportedEncoders() override{return {};}
    std::optional<webrtc::AudioCodecInfo> QueryAudioEncoder(const webrtc::SdpAudioFormat&) override{return std::nullopt;}
    std::unique_ptr<webrtc::AudioEncoder> Create(const webrtc::Environment&,const webrtc::SdpAudioFormat&,Options) override{return nullptr;}
};
class NoAudioDecoder:public webrtc::AudioDecoderFactory {
public:
    std::vector<webrtc::AudioCodecSpec> GetSupportedDecoders() override{return {};}
    bool IsSupportedDecoder(const webrtc::SdpAudioFormat&) override{return false;}
    std::unique_ptr<webrtc::AudioDecoder> Create(const webrtc::Environment&,const webrtc::SdpAudioFormat&) override{return nullptr;}
};
std::vector<webrtc::IPAddress> approved(const std::vector<std::string>& addresses,bool loopback){
    require(!addresses.empty() && addresses.size()<=16);std::vector<webrtc::IPAddress> result;
    for(const auto& value:addresses){webrtc::IPAddress ip;require(value.size()<=15 && webrtc::IPFromString(value,&ip) && ip.family()==AF_INET &&
        (webrtc::IPIsPrivateNetwork(ip) || (loopback && webrtc::IPIsLoopback(ip))));
        if(std::find(result.begin(),result.end(),ip)==result.end())result.push_back(ip);
    }return result;
}
void require_local(const std::vector<webrtc::IPAddress>& addresses,bool loopback){
    ULONG size=16384;std::vector<std::uint8_t> buffer(size);ULONG result=ERROR_BUFFER_OVERFLOW;
    for(unsigned i=0;i<3 && result==ERROR_BUFFER_OVERFLOW;++i){
        require(size<=262144);buffer.resize(size);result=GetAdaptersAddresses(AF_INET,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER,nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(&buffer.at(0)),&size);
    }
    require(result==NO_ERROR);std::vector<webrtc::IPAddress> actual;
    auto* adapter=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(&buffer.at(0));unsigned count=0;
    for(;adapter;adapter=adapter->Next){require(++count<=128);if(adapter->OperStatus!=IfOperStatusUp)continue;unsigned n=0;
        for(auto* entry=adapter->FirstUnicastAddress;entry;entry=entry->Next){require(++n<=128);
            if(entry->Address.iSockaddrLength>=static_cast<int>(sizeof(sockaddr_in)) && entry->Address.lpSockaddr->sa_family==AF_INET){
                sockaddr_in address{};std::memcpy(&address,entry->Address.lpSockaddr,sizeof(address));actual.emplace_back(address.sin_addr);
            }
        }
    }
    for(const auto& ip:addresses)require((loopback && webrtc::IPIsLoopback(ip)) || std::find(actual.begin(),actual.end(),ip)!=actual.end());
}
class BoundNetworks final:public webrtc::NetworkManagerBase {
    std::vector<webrtc::IPAddress> addresses_;
public:
    explicit BoundNetworks(std::vector<webrtc::IPAddress> addresses):addresses_(std::move(addresses)){}
    void StartUpdating() override{
        std::vector<std::unique_ptr<webrtc::Network>> list;unsigned index=0;
        for(const auto& ip:addresses_){auto network=std::make_unique<webrtc::Network>("guarddesk-bound-"+std::to_string(index++),"guarddesk-authorized-interface",ip,32,
            webrtc::IPIsLoopback(ip)?webrtc::ADAPTER_TYPE_LOOPBACK:webrtc::ADAPTER_TYPE_ETHERNET);network->AddIP(ip);list.push_back(std::move(network));}
        bool changed=false;MergeNetworkList(std::move(list),&changed);NotifyNetworksChanged();
    }
    void StopUpdating() override{}
    std::vector<const webrtc::Network*> GetAnyAddressNetworks() override{return {};}
};
class Created:public webrtc::CreateSessionDescriptionObserver {
public:
    std::promise<std::unique_ptr<webrtc::SessionDescriptionInterface>> result;
    void OnSuccess(webrtc::SessionDescriptionInterface* value) override{result.set_value(std::unique_ptr<webrtc::SessionDescriptionInterface>(value));}
    void OnFailure(webrtc::RTCError) override{result.set_value(nullptr);}
};
class LocalSet:public webrtc::SetLocalDescriptionObserverInterface {
public:std::promise<bool> result;void OnSetLocalDescriptionComplete(webrtc::RTCError error) override{result.set_value(error.ok());}
};
class RemoteSet:public webrtc::SetRemoteDescriptionObserverInterface {
public:std::promise<bool> result;void OnSetRemoteDescriptionComplete(webrtc::RTCError error) override{result.set_value(error.ok());}
};
}
class MediaPeer::Impl final:public webrtc::PeerConnectionObserver,public webrtc::DataChannelObserver {
public:
    MediaPeerOptions options;
    Platform media;
    webrtc::WinsockInitializer winsock;
    DWORD owner=GetCurrentThreadId();
    std::unique_ptr<webrtc::Thread> network,signaling;
    std::shared_ptr<NetworkGuard> network_guard;std::unique_ptr<GuardedSocketFactory> socket_factory;
    webrtc::scoped_refptr<webrtc::PeerConnectionFactoryInterface> factory;
    webrtc::scoped_refptr<webrtc::PeerConnectionInterface> peer;
    webrtc::scoped_refptr<webrtc::DataChannelInterface> channel,cursor_channel;
    struct CursorObserver:webrtc::DataChannelObserver {Impl* owner;explicit CursorObserver(Impl* value):owner(value){}
        void OnStateChange() override{}
        void OnMessage(const webrtc::DataBuffer& buffer) override{owner->receive_cursor(buffer);}
    } cursor_observer{this};
    std::function<bool(CursorUpdate)> cursor_output;
    std::uint64_t cursor_sequence=0;
    std::atomic<std::uint64_t> cursor_dropped{0},cursor_sent{0},cursor_received{0},cursor_unsupported{0};
    std::uint64_t cursor_rate_start=0;unsigned cursor_rate=0;
    webrtc::scoped_refptr<webrtc::VideoTrackInterface> track;
    webrtc::scoped_refptr<FrameSource> source;
    std::shared_ptr<FrameBindings> bindings;
    std::shared_ptr<CodecMetrics> metrics=std::make_shared<CodecMetrics>();
    std::shared_ptr<FrameSink> sink;
    std::function<void(std::uint64_t,bool)> state;
    std::function<bool(SharedFrame)> submit;
    std::vector<webrtc::IPAddress> remote_ips;
    std::mutex mutex,callbacks;
    std::uint64_t paused_epoch=0;
    std::optional<MediaSignal> outgoing;
    struct Pending{ipc::Message message;std::uint64_t tick;std::uint64_t started_us=0;};
    std::deque<Pending> controls;
    // One bounded native mailbox. UI callbacks never wait on signaling.
    std::mutex outbound_mutex;
    std::deque<Pending> outbound;
    std::atomic<bool> outbound_scheduled{false};
    std::atomic<std::uint32_t> first_reason{0};
    std::mutex send_metrics_mutex;
    LatencyHistogram send_queue_wait;
    std::uint32_t send_queued=0,send_transmitted=0,send_discarded=0,send_busy=0,send_high_water=0;
    InputDiagnostics input_metrics;
    std::uint64_t wire_ack_generation=0,wire_ack_sequence=0; // signaling owner only
    std::set<unsigned> wire_held; // conservative sent-down ledger, no key logging
    std::optional<FrameTicket> ack;
    std::uint64_t ack_tick=0,generation=0,local_sequence=0,remote_sequence=0,state_sequence=0;
    std::uint64_t rate_start=0;unsigned rate_count=0;
    std::optional<RelayPolicy> relay_policy;bool relay_attempted=false;
    std::atomic<std::uint64_t> lease{0},relay_deadline{0};
    std::atomic<bool> terminal{false},gathered{false},dirty{true},open{false},pc_connected{false};
    std::atomic<bool> ever_granted{false};
    bool closed=false,offered=false,answered=false,signaling_started=false;
    struct Delivered { FrameTicket frame;std::uint64_t tick; };
    std::deque<Delivered> delivered;
    std::uint64_t created=GetTickCount64();
    explicit Impl(MediaPeerOptions value,std::function<void(std::uint64_t,bool)> status,std::function<bool(SharedFrame)> output,std::function<bool(CursorUpdate)> cursor)
        :options(std::move(value)),cursor_output(std::move(cursor)),state(std::move(status)),submit(std::move(output)){
        try {
        require(winsock.error()==0 && options.transport>0 && ipc::valid_consent(options.consent_deadline,created) && state && submit);
        auto local=approved(options.local_ipv4,options.owned_loopback);remote_ips=approved(options.peer_ipv4,options.owned_loopback);require_local(local,options.owned_loopback);
        bindings=std::make_shared<FrameBindings>(options.session,options.transport);
        metrics->epoch_for_frame=[this](std::uint32_t stamp){if(!authorized())return std::uint64_t(0);auto binding=bindings->find(stamp,GetTickCount64());return binding?binding->frame.generation:0;};
        if(options.endpoint)metrics->frame_metadata=[this](std::uint32_t stamp){if(!authorized())return std::vector<std::uint8_t>();auto binding=bindings->find(stamp,GetTickCount64());return binding?encode_video_binding(*binding):std::vector<std::uint8_t>();};
        else{
            sink=std::make_shared<FrameSink>(bindings,[this](std::uint64_t epoch){
                std::lock_guard<std::mutex> callback(callbacks);
                {std::lock_guard<std::mutex> lock(mutex);if(!authorized() || epoch<=paused_epoch)return;if(epoch>generation){generation=epoch;ack.reset();}}
                try {state(epoch,true);}catch(...){fail(MediaEndReason::callback_failed);}
            },[this](SharedFrame frame){
                std::lock_guard<std::mutex> callback(callbacks);
                if(!authorized())return false;
                const auto ticket=frame.ticket;
                {std::lock_guard<std::mutex> lock(mutex);if(ticket.generation<=paused_epoch)return false;if(delivered.size()==64)delivered.pop_front();delivered.push_back({ticket,GetTickCount64()});}
                try {return authorized() && submit(std::move(frame));}catch(...){fail(MediaEndReason::callback_failed);return false;}
            });
            metrics->receive_metadata=[this](const auto& packet,std::uint32_t stamp){return authorized() && sink->encoded_metadata(packet,stamp);};
        }
        webrtc::LogMessage::LogToDebug(webrtc::LS_NONE);webrtc::LogMessage::SetLogToStderr(false);
        network=webrtc::Thread::CreateWithSocketServer();signaling=webrtc::Thread::Create();require(network->Start());require(signaling->Start());signaling_started=true;
        webrtc::PeerConnectionFactoryDependencies dependencies;dependencies.env=webrtc::CreateEnvironment();dependencies.network_thread=network.get();dependencies.signaling_thread=signaling.get();
        dependencies.network_manager=std::make_unique<BoundNetworks>(std::move(local));network_guard=std::make_shared<NetworkGuard>(remote_ips,[this]{return live() && (!ever_granted || authorized());});socket_factory=std::make_unique<GuardedSocketFactory>(network->socketserver(),network_guard);
        dependencies.packet_socket_factory=std::make_unique<webrtc::BasicPacketSocketFactory>(socket_factory.get());
        dependencies.adm=webrtc::CreateAudioDeviceModule(*dependencies.env,webrtc::AudioDeviceModule::kDummyAudio);require(dependencies.adm!=nullptr);
        dependencies.audio_encoder_factory=webrtc::make_ref_counted<NoAudioEncoder>();dependencies.audio_decoder_factory=webrtc::make_ref_counted<NoAudioDecoder>();
        dependencies.video_encoder_factory=std::make_unique<MfEncoderFactory>(metrics);dependencies.video_decoder_factory=std::make_unique<MfDecoderFactory>(metrics);
        webrtc::EnableMedia(dependencies);factory=webrtc::CreateModularPeerConnectionFactory(std::move(dependencies));require(factory!=nullptr);
        webrtc::PeerConnectionFactoryInterface::Options factory_options;factory_options.network_ignore_mask=0;factory->SetOptions(factory_options);
        webrtc::PeerConnectionInterface::RTCConfiguration configuration;configuration.max_sctp_streams=4;
        configuration.tcp_candidate_policy=webrtc::PeerConnectionInterface::kTcpCandidatePolicyDisabled;
        auto result=factory->CreatePeerConnectionOrError(configuration,webrtc::PeerConnectionDependencies(this));require(result.ok());peer=std::move(result.value());
        if(options.endpoint){
            source=webrtc::make_ref_counted<FrameSource>(bindings,options.transport,[](const auto&){return true;});
            track=factory->CreateVideoTrack(source,"guarddesk-consented-screen");
            auto sender=peer->AddTrack(track,{"guarddesk-remote"});require(sender.ok());
            auto parameters=sender.value()->GetParameters();
            for(auto& encoding:parameters.encodings){encoding.max_framerate=30;encoding.min_bitrate_bps=64000;encoding.max_bitrate_bps=8000000;}
            require(sender.value()->SetParameters(parameters).ok());
            webrtc::BitrateSettings rates;rates.min_bitrate_bps=64000;rates.start_bitrate_bps=3000000;rates.max_bitrate_bps=8000000;
            require(peer->SetBitrate(rates).ok());
        }
        } catch(...) {close();throw;}
    }
    ~Impl(){close();}
    bool live() const{const auto now=GetTickCount64();return !terminal && now<options.consent_deadline && (!relay_deadline.load() || now<relay_deadline.load());}
    bool authorized() const{return live() && GetTickCount64()<lease.load();}
    void fail(MediaEndReason reason){std::uint32_t empty=0;first_reason.compare_exchange_strong(empty,static_cast<std::uint32_t>(reason));terminal=true;lease=0;}
    void own() const{require(GetCurrentThreadId()==owner && !closed);}
    void pause(){std::lock_guard<std::mutex> callback(callbacks);if(bindings)bindings->clear();std::uint64_t epoch=0;{std::lock_guard<std::mutex> lock(mutex);controls.clear();ack.reset();delivered.clear();epoch=generation;paused_epoch=std::max(paused_epoch,generation);}try{if(state)state(epoch,false);}catch(...){fail(MediaEndReason::callback_failed);}}
    void pause_epoch(std::uint64_t epoch){
        // Video and SCTP are independently ordered. Fence the sender's exact
        // retired epoch; never infer it from whichever video arrived last.
        std::lock_guard<std::mutex> callback(callbacks);
        {std::lock_guard<std::mutex> lock(mutex);
            paused_epoch=std::max(paused_epoch,epoch);
            if(generation>epoch)return;
            controls.clear();ack.reset();delivered.clear();}
        if(bindings)bindings->clear();
        try{if(state)state(epoch,false);}catch(...){fail(MediaEndReason::callback_failed);}
    }
    void close(){
        if(closed)return;terminal=true;pause();
        if(signaling && signaling_started)signaling->BlockingCall([&]{
            if(channel)channel->UnregisterObserver();if(cursor_channel)cursor_channel->UnregisterObserver();if(track && sink)track->RemoveSink(sink.get());
            if(peer)peer->Close();channel=nullptr;cursor_channel=nullptr;track=nullptr;source=nullptr;peer=nullptr;factory=nullptr;
        });
        if(signaling)signaling->Stop();if(network)network->Stop();closed=true;
    }
    void OnSignalingChange(webrtc::PeerConnectionInterface::SignalingState) override{}
    void OnIceGatheringChange(webrtc::PeerConnectionInterface::IceGatheringState value) override{gathered=value==webrtc::PeerConnectionInterface::kIceGatheringComplete;}
    void OnIceCandidate(const webrtc::IceCandidate*) override{}
    void OnConnectionChange(webrtc::PeerConnectionInterface::PeerConnectionState value) override{
        pc_connected=value==webrtc::PeerConnectionInterface::PeerConnectionState::kConnected;
        if(value==webrtc::PeerConnectionInterface::PeerConnectionState::kFailed || value==webrtc::PeerConnectionInterface::PeerConnectionState::kClosed)fail(MediaEndReason::connection_closed);
    }
    void OnDataChannel(webrtc::scoped_refptr<webrtc::DataChannelInterface> value) override{
        if(options.endpoint && !cursor_channel && value->label()=="guarddesk-cursor-v1" && !value->ordered() && !value->reliable() && value->maxRetransmitsOpt()==0 && !value->maxPacketLifeTime()){
            cursor_channel=std::move(value);cursor_channel->RegisterObserver(&cursor_observer);return;}
        if(!options.endpoint || channel || value->label()!="guarddesk-control-v1" || !value->ordered() || !value->reliable()){fail(MediaEndReason::protocol_rejected);return;}
        channel=std::move(value);channel->RegisterObserver(this);dirty=true;
    }
    void OnTrack(webrtc::scoped_refptr<webrtc::RtpTransceiverInterface> transceiver) override{
        const auto received=transceiver->receiver()->track();
        if(options.endpoint || !received || received->kind()!=webrtc::MediaStreamTrackInterface::kVideoKind || track){fail(MediaEndReason::protocol_rejected);return;}
        track=static_cast<webrtc::VideoTrackInterface*>(received.get());track->AddOrUpdateSink(sink.get(),webrtc::VideoSinkWants());
    }
    void OnStateChange() override{dirty=true;if(options.activity)options.activity();} // Never call WebRTC reentrantly.
    void OnBufferedAmountChange(std::uint64_t) override{schedule_outbound();}
    void OnMessage(const webrtc::DataBuffer& buffer) override{
        if(!buffer.binary || buffer.size()<64 || buffer.size()>88){fail(MediaEndReason::protocol_rejected);pause();return;}
        try{
            std::vector<std::uint8_t> bytes(buffer.size());std::memcpy(bytes.data(),buffer.data.cdata(),buffer.size());
            auto message=ipc::control_message(bytes,options.endpoint?ipc::Direction::broker_to_worker:ipc::Direction::worker_to_broker);
            require(message.header.session==options.session && message.header.transport_generation==options.transport);
            std::unique_lock<std::mutex> lock(mutex);require(message.header.sequence>remote_sequence);remote_sequence=message.header.sequence;
            const auto now=GetTickCount64();require(authorized());
            if(now-rate_start>=1000){rate_start=now;rate_count=0;}require(++rate_count<=240);
            if(!options.endpoint){require(message.header.kind==ipc::Kind::desktop_state && message.payload.at(0)==4 && message.header.desktop_generation>0);
                const auto epoch=message.header.desktop_generation;lock.unlock();pause_epoch(epoch);return;
            }
            const auto kind=message.header.kind;require(kind==ipc::Kind::input || kind==ipc::Kind::presented || kind==ipc::Kind::release_all || kind==ipc::Kind::stop);
            require(controls.size()<32);controls.push_back({std::move(message),now});
            lock.unlock();if(options.activity)options.activity();
        }catch(...){fail(MediaEndReason::protocol_rejected);pause();}
    }
    void receive_cursor(const webrtc::DataBuffer& buffer){
        if(options.endpoint || !authorized() || !cursor_output || !buffer.binary || buffer.size()<cursor_wire_header || buffer.size()>cursor_wire_header+cursor_max_pixels){++cursor_dropped;return;}
        const auto now=GetTickCount64();if(now-cursor_rate_start>=1000){cursor_rate_start=now;cursor_rate=0;}if(++cursor_rate>120){++cursor_dropped;return;}
        try {std::vector<std::uint8_t> packet(buffer.size());std::memcpy(packet.data(),buffer.data.cdata(),buffer.size());auto value=decode_cursor(packet);
            std::lock_guard<std::mutex> callback(callbacks);
            {std::lock_guard<std::mutex> lock(mutex);
                if(!authorized() || value.session!=options.session || value.transport!=options.transport || value.generation!=generation || value.generation<=paused_epoch ||
                    value.sequence<=cursor_sequence || delivered.empty() || delivered.back().frame.generation!=value.generation || GetTickCount64()-delivered.back().tick>1000){++cursor_dropped;return;}
                }
            const auto sequence=value.sequence;const bool unsupported=value.mode==CursorMode::unsupported;
            if(!cursor_output(std::move(value)))++cursor_dropped;
            else {++cursor_received;if(unsupported)++cursor_unsupported;std::lock_guard<std::mutex> lock(mutex);cursor_sequence=sequence;}
        }catch(...){++cursor_dropped;}
    }
    enum class SendResult {queued,not_ready,backpressure,closed,rejected};
    void discarded(const ipc::Message& message,InputFailure reason){
        std::lock_guard<std::mutex> lock(send_metrics_mutex);LatencyHistogram::add(send_discarded);
        if(message.header.kind==ipc::Kind::input)input_metrics.rejected(input_category(message.payload),reason,true);
    }
    void schedule_outbound(){
        if(terminal || !signaling_started || outbound_scheduled.exchange(true))return;
        signaling->PostTask([this]{
            bool drained=false;
            try{drained=drain_outbound();}catch(...){fail(MediaEndReason::protocol_rejected);pause();}
            outbound_scheduled=false;
            // An enqueue racing with the last pop must not wait for UI pump.
            // Backpressure instead waits for buffered-amount notification/pump.
            bool pending=false;{std::lock_guard<std::mutex> lock(outbound_mutex);pending=!outbound.empty();}
            if(drained && pending)schedule_outbound();
        });
    }
    bool drain_outbound(){
        // WebRTC observer callbacks only schedule this task. All channel calls
        // happen on its owning thread, outside an observer and outside WndProc.
        for(unsigned budget=0;budget<16;++budget){
            if(!authorized())return false;
            if(!channel || channel->state()!=webrtc::DataChannelInterface::kOpen)return false;
            Pending entry;
            {std::lock_guard<std::mutex> lock(outbound_mutex);
                if(outbound.empty())return true;
                if(channel->buffered_amount()>4096){
                    const auto now=GetTickCount64();
                    if(now<outbound.front().tick || now-outbound.front().tick>100){
                        // No sent down: discard stale work and require a new
                        // ACK, without turning mere congestion into revocation.
                        // A possibly held remote key/button needs safe cleanup;
                        // if it cannot be sent in this bound, fail closed.
                        if(!wire_held.empty())fail(MediaEndReason::cleanup_timeout);
                        for(const auto& value:outbound)discarded(value.message,InputFailure::expired);
                        outbound.clear();wire_ack_generation=wire_ack_sequence=0;
                        std::lock_guard<std::mutex> input_lock(mutex);ack.reset();
                    }
                    return false;
                }
                entry=std::move(outbound.front());outbound.pop_front();}
            auto& message=entry.message;const auto now=GetTickCount64();
            {std::lock_guard<std::mutex> lock(send_metrics_mutex);send_queue_wait.record(monotonic_us()-entry.started_us);}
            const bool stale=now<entry.tick || now-entry.tick>100;
            if(stale && message.header.kind==ipc::Kind::presented){discarded(message,InputFailure::expired);continue;}
            if(stale && message.header.kind==ipc::Kind::input){
                discarded(message,InputFailure::expired);
                message.header.kind=ipc::Kind::release_all;message.header.payload_bytes=0;
                message.header.desktop_generation=0;message.header.frame_sequence=0;message.payload.clear();
                std::lock_guard<std::mutex> lock(mutex);ack.reset();
            }
            if(message.header.kind==ipc::Kind::input || message.header.kind==ipc::Kind::presented){
                std::lock_guard<std::mutex> lock(mutex);
                if(message.header.desktop_generation!=generation || generation<=paused_epoch){discarded(message,InputFailure::ack_changed);continue;}
                // An ACK merely queued by the UI is not a wire ACK. If it was
                // dropped/cleaned, dependent input must not cross that barrier.
                if(message.header.kind==ipc::Kind::input &&
                    (wire_ack_generation!=message.header.desktop_generation || wire_ack_sequence!=message.header.frame_sequence)){discarded(message,InputFailure::ack_changed);continue;}
            }
            const auto packet=ipc::encode_control(message,options.endpoint?ipc::Direction::worker_to_broker:ipc::Direction::broker_to_worker);
            if(!authorized())return false;
            if(!channel->Send(webrtc::DataBuffer(webrtc::CopyOnWriteBuffer(std::span<const std::uint8_t>(packet)),true))){fail(MediaEndReason::send_failed);pause();return false;}
            {std::lock_guard<std::mutex> lock(send_metrics_mutex);LatencyHistogram::add(send_transmitted);
                if(message.header.kind==ipc::Kind::input)input_metrics.count(input_category(message.payload),2);}
            if(message.header.kind==ipc::Kind::presented){wire_ack_generation=message.header.desktop_generation;wire_ack_sequence=message.header.frame_sequence;}
            else if(message.header.kind==ipc::Kind::input && (message.payload[0]==1 || message.payload[0]==2) && message.payload[1])
                wire_held.insert((unsigned(message.payload[0])<<16)|unsigned(message.payload[2])|(unsigned(message.payload[3])<<8));
            else if(message.header.kind==ipc::Kind::release_all){
                if(message.payload.empty()){wire_ack_generation=wire_ack_sequence=0;wire_held.clear();}
                else wire_held.erase((unsigned(message.payload[0])<<16)|unsigned(message.payload[2])|(unsigned(message.payload[3])<<8));
            }
        }
        return true;
    }
    SendResult enqueue(const ipc::Message& message){
        if(terminal)return SendResult::closed;
        if(!authorized())return SendResult::rejected;
        // No offer/open channel is a normal startup state. Never enqueue old
        // input to replay after negotiation, and never turn focus loss into stop.
        if(!open || !pc_connected)return SendResult::not_ready;
        ipc::encode_control(message,options.endpoint?ipc::Direction::worker_to_broker:ipc::Direction::broker_to_worker);
        {std::lock_guard<std::mutex> lock(outbound_mutex);
            if(message.header.kind==ipc::Kind::release_all && message.payload.empty()){
                for(const auto& value:outbound)discarded(value.message,InputFailure::cleanup);outbound.clear();}
            else if(outbound.size()>=32){std::lock_guard<std::mutex> metrics_guard(send_metrics_mutex);LatencyHistogram::add(send_busy);return SendResult::backpressure;}
            outbound.push_back({message,GetTickCount64(),monotonic_us()});
            std::lock_guard<std::mutex> metrics_guard(send_metrics_mutex);LatencyHistogram::add(send_queued);send_high_water=std::max(send_high_water,static_cast<std::uint32_t>(outbound.size()));}
        schedule_outbound();return SendResult::queued;
    }
    bool send(const ipc::Message& message){return enqueue(message)==SendResult::queued;}
    bool remote_sdp(const std::string& text){
        if(text.empty() || text.size()>65536 || text.find('\0')!=std::string::npos || text.rfind("v=0\r\n",0)!=0)return false;
        unsigned candidates=0,lines=0;bool fingerprint=false,size_limit=false;std::istringstream input(text);std::string line;
        while(std::getline(input,line)){
            if(++lines>1024 || line.size()>2048)return false;if(!line.empty() && line.back()=='\r')line.pop_back();
            if(line.rfind("a=fingerprint:sha-256 ",0)==0)fingerprint=true;
            if(line.rfind("a=max-message-size:",0)==0){if(line!="a=max-message-size:20480")return false;size_limit=true;}
            if(line.rfind("a=remote-candidates:",0)==0)return false;
            if(line.rfind("a=candidate:",0)==0){
                std::istringstream fields(line.substr(12));std::string foundation,protocol,address,typ,type;unsigned component=0,priority=0,port=0;
                if(!(fields>>foundation>>component>>protocol>>priority>>address>>port>>typ>>type) || foundation.size()>64 || ++candidates>32 ||
                    (component!=1 && component!=2) || (protocol!="udp" && protocol!="UDP") || typ!="typ" || !port || port>65535)return false;
                webrtc::IPAddress ip;if(!webrtc::IPFromString(address,&ip) || ip.family()!=AF_INET)return false;
                if(relay_policy){const auto& relay=*relay_policy;if(type!="relay" || port<relay.allocation_min || port>relay.allocation_max ||
                    std::find(relay.allocation_ipv4.begin(),relay.allocation_ipv4.end(),ip.ipv4_address().s_addr)==relay.allocation_ipv4.end())return false;}
                else if(type!="host" || std::find(remote_ips.begin(),remote_ips.end(),ip)==remote_ips.end())return false;
            }
        }
        return fingerprint && size_limit && candidates>0;
    }
    template<class T> bool ready(std::future<T>& future){
        const auto until=GetTickCount64()+5000;
        while(!terminal && GetTickCount64()<until){
            if(!live() || (ever_granted && !authorized())){fail(MediaEndReason::authority_expired);return false;}
            if(future.wait_for(5ms)==std::future_status::ready)return true;
        }return false;
    }
    bool local_description(bool offer){
        if(!live())return false;
        auto observer=webrtc::make_ref_counted<Created>();auto future=observer->result.get_future();
        webrtc::PeerConnectionInterface::RTCOfferAnswerOptions arguments;
        if(offer)peer->CreateOffer(observer.get(),arguments);else peer->CreateAnswer(observer.get(),arguments);
        if(!ready(future))return false;auto description=future.get();if(!description)return false;
        std::string text;require(description->ToString(&text) && text.size()<=65536);
        const auto at=text.find("a=max-message-size:");require(at!=std::string::npos);const auto end=text.find("\r\n",at);require(end!=std::string::npos);
        text.replace(at,end-at,"a=max-message-size:20480");description=webrtc::CreateSessionDescription(offer?webrtc::SdpType::kOffer:webrtc::SdpType::kAnswer,text);require(description!=nullptr);
        if(!live())return false;
        auto set=webrtc::make_ref_counted<LocalSet>();auto done=set->result.get_future();peer->SetLocalDescription(std::move(description),set);
        if(!ready(done) || !done.get())return false;
        const auto until=GetTickCount64()+5000;
        while(!gathered && !terminal && GetTickCount64()<until)std::this_thread::sleep_for(5ms);
        if(!gathered || terminal)return false;
        bool serialized=false;signaling->BlockingCall([&]{const auto* description=peer->local_description();serialized=description && description->ToString(&text);});
        if(!serialized || text.size()>65536)return false;
        std::lock_guard<std::mutex> lock(mutex);if(!live() || outgoing)return false;outgoing=MediaSignal{offer,std::move(text)};return true;
    }
};
MediaPeer::MediaPeer(MediaPeerOptions options,std::function<void(std::uint64_t,bool)> state,std::function<bool(SharedFrame)> submit,std::function<bool(CursorUpdate)> cursor)
    :impl_(std::make_unique<Impl>(standard_options(std::move(options)),std::move(state),std::move(submit),std::move(cursor))){}
MediaPeer::~MediaPeer()=default;
bool MediaPeer::relay(const std::vector<std::uint8_t>& bytes){try{auto& p=*impl_;p.own();require(p.live() && !p.offered && !p.answered && !p.relay_attempted);p.relay_attempted=true;
    auto relay=parse_relay(bytes);require_relay(relay,GetTickCount64(),p.options.consent_deadline,p.options.owned_loopback);
    auto configuration=p.peer->GetConfiguration();webrtc::PeerConnectionInterface::IceServer server;
    const auto ip=std::to_string(relay.turn_ipv4&255)+"."+std::to_string((relay.turn_ipv4>>8)&255)+"."+std::to_string((relay.turn_ipv4>>16)&255)+"."+std::to_string(relay.turn_ipv4>>24);
    server.urls={std::string(relay.owned_udp?"turn:":"turns:")+ip+":"+std::to_string(relay.turn_port)+(relay.owned_udp?"?transport=udp":"?transport=tcp")};
    server.username=relay.username;server.password=relay.password;server.hostname=relay.hostname;server.tls_cert_policy=webrtc::PeerConnectionInterface::kTlsCertPolicySecure;
    configuration.servers={server};configuration.type=webrtc::PeerConnectionInterface::kRelay;
    p.network_guard->relay(relay);
    require(p.peer->SetConfiguration(configuration).ok());p.relay_deadline=relay.expires;
    if(p.options.endpoint){
        for(const auto& sender:p.peer->GetSenders()){auto parameters=sender->GetParameters();
            for(auto& encoding:parameters.encodings){encoding.min_bitrate_bps=64000;encoding.max_bitrate_bps=4000000;}
            require(sender->SetParameters(parameters).ok());}
        webrtc::BitrateSettings rates;rates.min_bitrate_bps=64000;rates.start_bitrate_bps=1500000;rates.max_bitrate_bps=4000000;
        require(p.peer->SetBitrate(rates).ok());
    }
    std::fill(relay.password.begin(),relay.password.end(),'\0');relay.password.clear();relay.username.clear();p.relay_policy=std::move(relay);return true;
}catch(...){request_stop();return false;}}
bool MediaPeer::make_offer(){try{auto& p=*impl_;p.own();require(p.live() && !p.options.endpoint && !p.offered);p.offered=true;
    webrtc::DataChannelInit configuration;configuration.ordered=true;auto result=p.peer->CreateDataChannelOrError("guarddesk-control-v1",&configuration);require(result.ok());
    p.signaling->BlockingCall([&]{p.channel=std::move(result.value());p.channel->RegisterObserver(&p);
    webrtc::DataChannelInit cursor_configuration;cursor_configuration.ordered=false;cursor_configuration.maxRetransmits=0;
    auto cursor_result=p.peer->CreateDataChannelOrError("guarddesk-cursor-v1",&cursor_configuration);require(cursor_result.ok());
    p.cursor_channel=std::move(cursor_result.value());p.cursor_channel->RegisterObserver(&p.cursor_observer);});p.dirty=true;
    auto receiver=p.peer->AddTransceiver(webrtc::MediaType::VIDEO);require(receiver.ok());require(receiver.value()->SetDirectionWithError(webrtc::RtpTransceiverDirection::kRecvOnly).ok());
    return p.local_description(true);
}catch(...){request_stop();return false;}}
bool MediaPeer::signal(const MediaSignal& signal){try{auto& p=*impl_;p.own();require(p.live() && !p.answered && signal.offer==p.options.endpoint && p.remote_sdp(signal.sdp));
    auto description=webrtc::CreateSessionDescription(signal.offer?webrtc::SdpType::kOffer:webrtc::SdpType::kAnswer,signal.sdp);require(description!=nullptr);
    auto observer=webrtc::make_ref_counted<RemoteSet>();auto done=observer->result.get_future();p.peer->SetRemoteDescription(std::move(description),observer);
    require(p.ready(done) && done.get());p.answered=true;
    return !signal.offer || p.local_description(false);
}catch(...){request_stop();return false;}}
std::optional<MediaSignal> MediaPeer::take_signal(){std::lock_guard<std::mutex> lock(impl_->mutex);auto result=std::move(impl_->outgoing);impl_->outgoing.reset();return result;}
bool MediaPeer::grant(std::uint64_t deadline){auto& p=*impl_;const auto now=GetTickCount64();if(p.terminal || deadline<=now || deadline-now>5000 || deadline>p.options.consent_deadline){p.fail(MediaEndReason::authority_expired);p.pause();return false;}
    const auto previous=p.lease.load();if(previous && now>=previous){p.fail(MediaEndReason::authority_expired);p.pause();return false;}p.lease=deadline;p.ever_granted=true;return true;}
bool MediaPeer::frame(const SharedFrame& frame){auto& p=*impl_;p.own();if(!(p.options.endpoint && p.authorized() && p.pc_connected && p.source->push(frame)))return false;
    std::lock_guard<std::mutex> lock(p.mutex);p.generation=frame.ticket.generation;return true;}
bool MediaPeer::cursor(const CursorUpdate& value){auto& p=*impl_;p.own();
    if(!p.options.endpoint || !p.authorized() || value.session!=p.options.session || value.transport!=p.options.transport)return false;
    {std::lock_guard<std::mutex> lock(p.mutex);if(value.generation!=p.generation || value.generation<=p.paused_epoch)return false;}
    auto packet=encode_cursor(value);bool sent=false;
    p.signaling->BlockingCall([&]{if(p.authorized() && p.cursor_channel && p.cursor_channel->state()==webrtc::DataChannelInterface::kOpen && p.cursor_channel->buffered_amount()<=20480)
        sent=p.cursor_channel->Send(webrtc::DataBuffer(webrtc::CopyOnWriteBuffer(std::span<const std::uint8_t>(packet)),true));});
    if(!sent)++p.cursor_dropped;else ++p.cursor_sent;return sent;
}
bool MediaPeer::presented(const FrameTicket& frame){auto& p=*impl_;p.own();if(p.options.endpoint || !p.authorized())return false;
    {std::lock_guard<std::mutex> lock(p.mutex);const auto now=GetTickCount64();
        const auto same=[&](const auto& item){const auto& f=item.frame;return now>=item.tick && now-item.tick<=1000 &&
            f.session==frame.session && f.generation==frame.generation && f.sequence==frame.sequence && f.tick==frame.tick &&
            f.slot==frame.slot && f.width==frame.width && f.height==frame.height;};
        if(frame.generation!=p.generation || std::none_of(p.delivered.begin(),p.delivered.end(),same))return false;
    }
    ipc::Message message{{ipc::Kind::presented,0,p.options.session,frame.generation,++p.local_sequence,frame.sequence,p.options.transport},{}};
    if(!p.send(message))return false;std::lock_guard<std::mutex> lock(p.mutex);p.ack=frame;p.ack_tick=GetTickCount64();return true;}
bool MediaPeer::input(const std::vector<std::uint8_t>& payload){auto& p=*impl_;p.own();const auto category=input_category(payload);
    {std::lock_guard<std::mutex> lock(p.send_metrics_mutex);p.input_metrics.count(category,0);}
    auto reject=[&](InputFailure reason){std::lock_guard<std::mutex> lock(p.send_metrics_mutex);p.input_metrics.rejected(category,reason);return false;};
    if(payload.size()!=24)return reject(InputFailure::invalid);
    if(p.options.endpoint || !p.options.can_control)return reject(InputFailure::view_only);
    if(p.terminal)return reject(InputFailure::closed);
    if(!p.authorized())return reject(InputFailure::authority);
    std::optional<FrameTicket> ack;{std::lock_guard<std::mutex> lock(p.mutex);const auto now=GetTickCount64();if(now>=p.ack_tick && now-p.ack_tick<=1000)ack=p.ack;}
    if(!ack)return reject(InputFailure::no_frame);
    const auto result=p.enqueue({{ipc::Kind::input,24,p.options.session,ack->generation,++p.local_sequence,ack->sequence,p.options.transport},payload});
    if(result==Impl::SendResult::backpressure)release_all(); // bounded cleanup barrier, never replay input
    if(result==Impl::SendResult::queued){std::lock_guard<std::mutex> lock(p.send_metrics_mutex);p.input_metrics.count(category,1);return true;}
    return reject(result==Impl::SendResult::backpressure?InputFailure::backpressure:result==Impl::SendResult::not_ready?InputFailure::not_ready:result==Impl::SendResult::closed?InputFailure::closed:InputFailure::authority);}
void MediaPeer::release_all(){auto& p=*impl_;p.own();if(!p.options.endpoint)p.send({{ipc::Kind::release_all,0,p.options.session,0,++p.local_sequence,0,p.options.transport},{}});
    std::lock_guard<std::mutex> lock(p.mutex);p.ack.reset();}
bool MediaPeer::release_up(unsigned type,unsigned code){
    auto& p=*impl_;p.own();if(p.options.endpoint || !p.options.can_control ||
        !((type==1 && code>=1 && code<=254 && code!=231) || (type==2 && code>=1 && code<=3)))return false;
    std::optional<FrameTicket> ack;{std::lock_guard<std::mutex> lock(p.mutex);ack=p.ack;}
    if(!ack)return false;std::vector<std::uint8_t> payload(8);payload.at(0)=static_cast<std::uint8_t>(type);
    payload.at(2)=static_cast<std::uint8_t>(code);
    return p.send({{ipc::Kind::release_all,8,p.options.session,ack->generation,++p.local_sequence,0,p.options.transport},payload});
}
void MediaPeer::pause_source(std::uint64_t generation){auto& p=*impl_;p.own();if(p.options.endpoint){std::vector<std::uint8_t> body(16);body.at(0)=4;
    {std::lock_guard<std::mutex> lock(p.mutex);require(generation>0 && generation<=p.generation);}
    if(!p.send({{ipc::Kind::desktop_state,16,p.options.session,generation,++p.state_sequence,0,p.options.transport},body}))p.fail(MediaEndReason::send_failed);}p.pause_epoch(generation);}
std::optional<ipc::Message> MediaPeer::take_control(){auto& p=*impl_;p.own();std::lock_guard<std::mutex> lock(p.mutex);
    if(!p.authorized())return std::nullopt;
    // A scheduler/GPU stall is not a revocation. Never replay expired input:
    // send cleanup in its original sequence slot instead. SessionRuntime
    // releases only its own ledger, validates the current desktop and fences
    // further input behind a newly published/presented frame. No lease or
    // identity field is extended. Stale ACKs cannot re-authorize old frames.
    for(unsigned count=0;count<32 && !p.controls.empty();++count){
        auto entry=std::move(p.controls.front());p.controls.pop_front();
        const auto now=GetTickCount64();
        if(now<entry.tick || now-entry.tick>100){
            if(entry.message.header.kind==ipc::Kind::presented)continue;
            if(entry.message.header.kind==ipc::Kind::input){
                entry.message.header.kind=ipc::Kind::release_all;
                entry.message.header.payload_bytes=0;
                entry.message.header.desktop_generation=0;
                entry.message.header.frame_sequence=0;
                entry.message.payload.clear();
            }
            // Stop and cleanup remain effective even after a scheduling stall.
        }
        return entry.message;
    }
    return std::nullopt;}
void MediaPeer::pump(){auto& p=*impl_;p.own();if(p.dirty.exchange(false))p.signaling->BlockingCall([&]{p.open=p.channel && p.channel->state()==webrtc::DataChannelInterface::kOpen;});
    p.schedule_outbound();
    if((p.ever_granted && !p.authorized()) || GetTickCount64()>=p.options.consent_deadline)p.fail(MediaEndReason::authority_expired);
    if(p.terminal)p.close();}
void MediaPeer::request_stop(MediaEndReason reason){impl_->fail(reason);impl_->pause();}
bool MediaPeer::connected() const{return impl_->open && impl_->pc_connected && !impl_->terminal;}
bool MediaPeer::ended() const{return impl_->terminal;}
MediaEndReason MediaPeer::end_reason() const{return static_cast<MediaEndReason>(impl_->first_reason.load());}
std::array<std::uint32_t,20> MediaPeer::send_diagnostics()const{auto& p=*impl_;std::lock_guard<std::mutex> lock(p.send_metrics_mutex);
    std::array<std::uint32_t,20> v{};v[0]=1;v[1]=p.send_queued;v[2]=p.send_transmitted;v[3]=p.send_discarded;v[4]=p.send_busy;v[5]=p.send_high_water;
    v[6]=p.send_queue_wait.count;v[7]=p.send_queue_wait.max_us;std::copy(p.send_queue_wait.bins.begin(),p.send_queue_wait.bins.end(),v.begin()+8);return v;}
std::array<std::uint32_t,64> MediaPeer::input_diagnostics()const{auto& p=*impl_;std::lock_guard<std::mutex> lock(p.send_metrics_mutex);return p.input_metrics.values;}
MediaPeerStats MediaPeer::stats() const{auto& p=*impl_;MediaPeerStats result{p.metrics->encoded.load(),p.metrics->decoded.load(),p.metrics->failures.load(),p.metrics->unknown_frame_timestamps.load(),p.open.load(),p.pc_connected.load(),p.cursor_sent.load(),p.cursor_received.load(),p.cursor_dropped.load(),p.cursor_unsupported.load()};
    result.codec_rebuilds=p.metrics->codec_rebuilds.load();result.hardware_frames=p.metrics->hardware_frames.load();result.hardware_fallbacks=p.metrics->hardware_fallbacks.load();
    result.hardware_candidates=p.metrics->hardware_candidates.load();result.bitrate_updates=p.metrics->bitrate_updates.load();result.bitrate_failures=p.metrics->bitrate_failures.load();
    result.target_bitrate=p.metrics->target_bitrate.load();result.encode_latency=p.metrics->encode_us.snapshot();return result;}
}
