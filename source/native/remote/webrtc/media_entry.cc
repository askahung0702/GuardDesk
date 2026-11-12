// Private low-integrity product process. SDP/ICE is never parsed in SYSTEM.
#include "media_peer.hpp"
#include "media_entry_token.hpp"
#include "cohort.hpp"
#include "ipc_channel.hpp"
#include "launch_capsule.hpp"
#include "media_wire.hpp"
#include <atomic>
#include <algorithm>
#include <iostream>
#include <thread>

namespace {
using namespace remote;
void require(bool value){if(!value)throw std::runtime_error("private_media_rejected");}
struct Handle{HANDLE value=nullptr;~Handle(){if(value && value!=INVALID_HANDLE_VALUE)CloseHandle(value);}};
std::uint64_t le(const std::vector<std::uint8_t>& b,unsigned at,unsigned bytes){std::uint64_t result=0;for(unsigned i=0;i<bytes;++i)result|=std::uint64_t(b.at(at+i))<<(8*i);return result;}
void put(std::vector<std::uint8_t>& b,unsigned at,std::uint64_t value,unsigned bytes){for(unsigned i=0;i<bytes;++i)b.at(at+i)=static_cast<std::uint8_t>(value>>(8*i));}
std::string ipv4(const std::vector<std::uint8_t>& b,unsigned at){return std::to_string(b.at(at))+"."+std::to_string(b.at(at+1))+"."+std::to_string(b.at(at+2))+"."+std::to_string(b.at(at+3));}
void restricted_identity(){
    Handle token;require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value)!=FALSE);
    require_media_token(token.value);
}
int run(int argc,wchar_t** argv){
    require(argc==3);
    // CRT guarantees argc argv elements. Bound count above before these two
    // accesses; no user-selected path or handle value is accepted here.
#pragma clang unsafe_buffer_usage begin
    require(std::wstring(argv[1])==L"--broker-media");
    const std::wstring nonce(argv[2]);
#pragma clang unsafe_buffer_usage end
    require(nonce.size()==32 && std::all_of(nonce.begin(),nonce.end(),[](auto c){return (c>=L'0' && c<=L'9') || (c>=L'a' && c<=L'f');}));
    restricted_identity();
    Handle bootstrap{OpenFileMappingW(FILE_MAP_READ|READ_CONTROL,FALSE,(L"Global\\GuardDesk-Remote-Launch-"+nonce).c_str())};
    require(bootstrap.value && ipc::pipe_owner(bootstrap.value)==L"S-1-5-18");
    const void* view=MapViewOfFile(bootstrap.value,FILE_MAP_READ,0,0,sizeof(LaunchCapsule));require(view!=nullptr);
    LaunchCapsule capsule{};std::memcpy(&capsule,view,sizeof(capsule));UnmapViewOfFile(view);validate_launch_capsule(capsule,GetTickCount64());require(capsule.role==2);
    const auto& spec=capsule.spec;ipc::Session id{};std::copy_n(spec.session,id.size(),id.begin());
    const auto paths=installed_cohort();ipc::Peer self(GetCurrentProcessId());
    auto parent=std::make_unique<ipc::Peer>(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(capsule.parent_process)),reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(capsule.parent_query_token)));
    require_fixed_peer(*parent,paths.broker,L"S-1-5-18",0);require(parent->identity().pid==capsule.parent_pid && parent->identity().created==capsule.parent_created);
    require_fixed_peer(self,paths.media,spec.user_sid,spec.wts_session);
    Handle image{pin_program_image(paths.media)},broker_image{pin_program_image(paths.broker)};
    Handle activity{CreateEventW(nullptr,FALSE,FALSE,nullptr)};require(activity.value!=nullptr);
    Handle stop{reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(capsule.stop))};require(stop.value && ipc::pipe_owner(stop.value)==L"S-1-5-18");
    Handle cancel{CreateEventW(nullptr,TRUE,FALSE,nullptr)};require(cancel.value!=nullptr);
    const auto parent_identity=parent->identity();const auto parent_wait=parent->wait_handle();
    auto channel=ipc::Channel::open(nonce,parent_identity,L"S-1-5-18",cancel.value,5000,std::move(parent));
    std::array<Handle,2> mapping;for(unsigned i=0;i<2;++i)mapping.at(i).value=reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(capsule.frames.at(i)));
    const std::size_t capacity=FramePool::shared_mapping_bytes(1920,1080);
    std::atomic<bool> finished{false},failed{false};std::atomic<std::uint64_t> lease{0};
    std::mutex peer_mutex;std::unique_ptr<MediaPeer> media;
    std::thread watchdog([&]{while(!finished){const auto now=GetTickCount64();const auto deadline=lease.load();
        if(now>=spec.consent_tick_deadline || (deadline && now>=deadline) ||
            WaitForSingleObject(stop.value,0)!=WAIT_TIMEOUT || WaitForSingleObject(parent_wait,0)!=WAIT_TIMEOUT){
            failed=true;SetEvent(cancel.value);std::lock_guard<std::mutex> lock(peer_mutex);if(media)media->request_stop();break;
        }std::this_thread::sleep_for(std::chrono::milliseconds(5));}});
    bool passed=false;std::uint64_t incoming=0,outgoing=0,last_generation=0,last_cursor=0,cursor_poll=0,stats_tick=0;std::array<std::uint64_t,2> consumed{};
    auto write=[&](ipc::MediaKind kind,std::vector<std::uint8_t> payload){channel->write_media(ipc::encode_media({kind,id,spec.transport,++outgoing,std::move(payload)},ipc::MediaDirection::media_to_broker),100);};
    try{
        while(!channel->available() && !failed && GetTickCount64()<spec.consent_tick_deadline)WaitForSingleObject(cancel.value,5);
        require(!failed);auto config=channel->read_media(100);require(config.kind==ipc::MediaKind::configuration && config.session==id && config.transport==spec.transport);incoming=config.sequence;
        MediaPeerOptions options;options.endpoint=true;options.can_control=spec.can_control==1;options.session=id;options.transport=spec.transport;options.consent_deadline=spec.consent_tick_deadline;
        options.activity=[event=activity.value]{SetEvent(event);};
        options.owned_loopback=le(config.payload,8,4)==1;
        for(unsigned i=0;i<le(config.payload,0,4);++i)options.local_ipv4.push_back(ipv4(config.payload,16+i*4));
        for(unsigned i=0;i<le(config.payload,4,4);++i)options.peer_ipv4.push_back(ipv4(config.payload,48+i*4));
        auto created=std::make_unique<MediaPeer>(std::move(options),[](auto,bool){},[](auto){return false;});
        {std::lock_guard<std::mutex> lock(peer_mutex);media=std::move(created);if(failed)media->request_stop();}
        write(ipc::MediaKind::stats,ipc::media_stats_payload());
        while(!failed && !media->ended()){
            unsigned count=0;
            while(channel->available() && count++<8){auto message=channel->read_media(100);require(message.session==id && message.transport==spec.transport && message.sequence>incoming);incoming=message.sequence;
                if(message.kind==ipc::MediaKind::grant){const auto deadline=le(message.payload,0,8);require(le(message.payload,8,4)==spec.can_control && media->grant(deadline));lease=deadline;}
                else if(message.kind==ipc::MediaKind::relay_configuration){require(media->relay(message.payload));SecureZeroMemory(message.payload.data(),message.payload.size());}
                else if(message.kind==ipc::MediaKind::signal){require(media->signal({message.payload.at(0)==1,std::string(message.payload.begin()+8,message.payload.end())}));}
                else if(message.kind==ipc::MediaKind::stop){media->request_stop();break;}
                else require(false);
            }
            media->pump();if(media->ended())break;
            if(auto signal=media->take_signal()){std::vector<std::uint8_t> payload(8+signal->sdp.size());payload.at(0)=signal->offer?1:2;
                std::copy(signal->sdp.begin(),signal->sdp.end(),payload.begin()+8);write(ipc::MediaKind::signal,std::move(payload));}
            for(unsigned i=0;i<8;++i){auto control=media->take_control();if(!control)break;write(ipc::MediaKind::network_control,ipc::encode_control(*control,ipc::Direction::broker_to_worker));}
            // One fixed scalar snapshot per second. No pixels, cursor, SDP,
            // key events, addresses or credential material leave this path.
            if(GetTickCount64()-stats_tick>=1000){stats_tick=GetTickCount64();
                const auto stats=media->stats();std::uint64_t captured=0;bool stale=false;
                try{for(const auto& item:mapping){const auto ticket=peek_shared_frame(item.value,capacity,id);
                    captured=std::max(captured,ticket.sequence);
                    stale|=ticket.sequence && stats_tick>=ticket.tick && stats_tick-ticket.tick>1000;
                }}catch(const FrameRetry&){} // Normal producer invalidation; next bounded sample.
                std::array<std::uint32_t,22> values{(stats.peer_connected?1u:0u)|(stats.channel_open?2u:0u)|(stats.codec_failures?4u:0u)|(stale?8u:0u),
                    static_cast<std::uint32_t>(std::min<std::uint64_t>(captured,UINT32_MAX)),static_cast<std::uint32_t>(std::min<std::uint64_t>(stats.encoded,UINT32_MAX)),
                    stats.codec_rebuilds,stats.hardware_frames,stats.hardware_fallbacks,stats.hardware_candidates,stats.bitrate_updates,stats.bitrate_failures,stats.target_bitrate,
                    static_cast<std::uint32_t>(std::min<std::uint64_t>(stats.unknown_timestamps,UINT32_MAX))};
                std::copy(stats.encode_latency.begin(),stats.encode_latency.end(),values.begin()+11);
                values[21]=static_cast<std::uint32_t>(std::min<std::uint64_t>(stats.codec_failures,UINT32_MAX));
                write(ipc::MediaKind::stats,ipc::media_stats_payload(values));
            }
            try {if(media->connected()){
              const std::array<FrameTicket,2> snapshots{peek_shared_frame(mapping.at(0).value,capacity,id),peek_shared_frame(mapping.at(1).value,capacity,id)};
              if(!snapshots.at(0).generation && !snapshots.at(1).generation && last_generation){media->pause_source(last_generation);last_generation=0;}
              for(unsigned i=0;i<2;++i){auto ticket=snapshots.at(i);
                if(!ticket.generation)continue;
                if(!ticket.sequence || ticket.sequence<=consumed.at(i))continue;
                auto frame=read_shared_frame(mapping.at(i).value,capacity,id,ticket.generation,GetTickCount64());
                if(frame.ticket.sequence<=consumed.at(i))continue;
                media->frame(frame);last_generation=frame.ticket.generation;consumed.at(i)=frame.ticket.sequence;
                std::vector<std::uint8_t> body(24);put(body,0,frame.ticket.generation,8);put(body,8,frame.ticket.sequence,8);put(body,16,i,4);write(ipc::MediaKind::consumed,std::move(body));
                SecureZeroMemory(frame.pixels.bgra.data(),frame.pixels.bgra.size());
              }
              if(last_generation && GetTickCount64()-cursor_poll>=20){cursor_poll=GetTickCount64();if(auto cursor=read_shared_cursor(mapping.at(0).value,capacity,id,spec.transport,last_generation,GetTickCount64());cursor && cursor->sequence>last_cursor){if(media->cursor(*cursor))last_cursor=cursor->sequence;}}
            }}catch(const FrameRetry&){ /* expected clear/reuse race: read latest next bounded poll */ }
            HANDLE waits[]{cancel.value,activity.value};WaitForMultipleObjects(2,waits,FALSE,5);
        }
        passed=true;
    }catch(...){failed=true;}
    {std::lock_guard<std::mutex> lock(peer_mutex);if(media)media->request_stop();}
    finished=true;watchdog.join();media.reset();return passed?0:1;
}
}
int wmain(int argc,wchar_t** argv){if(!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32))return 1;
    try{return run(argc,argv);}catch(...){std::cerr<<"private_media_rejected\n";return 1;}}
