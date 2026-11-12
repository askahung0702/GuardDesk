#include "media_wire.hpp"
#include "broker_api.hpp"
#include <iostream>
#include <functional>
#include <stdexcept>

namespace {
using namespace remote::ipc;
void require(bool okay,const char* reason){if(!okay)throw std::runtime_error(reason);}
void reject(const std::function<void()>& fn){bool refused=false;try{fn();}catch(const std::invalid_argument&){refused=true;}require(refused,"media_invalid_accepted");}
MediaMessage make(MediaKind kind,std::vector<std::uint8_t> payload){Session id{};id.at(0)=1;return {kind,id,1,1,std::move(payload)};}
void test(){
    // Exercise the same producer used by the private media entry before SDP.
    const auto startup=make(MediaKind::stats,media_stats_payload());
    const auto startup_wire=encode_media(startup,MediaDirection::media_to_broker);
    require(media_message(startup_wire,MediaDirection::media_to_broker).payload==startup.payload,"media_startup_status_roundtrip");
    require(startup.payload.size()==96 && startup.payload.at(0)==2,"media_startup_status_schema");
    for(std::size_t i=1;i<startup.payload.size();++i)require(startup.payload.at(i)==0,"media_startup_status_not_connected");
    std::array<std::uint32_t,22> counters{};counters.at(0)=15;
    for(std::size_t i=1;i<counters.size();++i)counters.at(i)=static_cast<std::uint32_t>(i*65537);
    const auto periodic=make(MediaKind::stats,media_stats_payload(counters));
    require(media_message(encode_media(periodic,MediaDirection::media_to_broker),MediaDirection::media_to_broker).payload==periodic.payload,"media_periodic_status_roundtrip");
    for(std::size_t i=0;i<counters.size();++i)for(unsigned j=0;j<4;++j)
        require(periodic.payload.at(4+i*4+j)==static_cast<std::uint8_t>(counters.at(i)>>(8*j)),"media_periodic_status_counter_offsets");
    for(unsigned i=92;i<96;++i)require(periodic.payload.at(i)==0,"media_periodic_status_reserved");
    reject([&]{encode_media(startup,MediaDirection::broker_to_media);});
    std::cout<<"media_entry_startup_and_periodic_share_v2_status_producer=true\n";
    auto grant=make(MediaKind::grant,std::vector<std::uint8_t>(16));grant.payload.at(0)=1;
    const auto valid=encode_media(grant,MediaDirection::broker_to_media);
    require(media_message(valid,MediaDirection::broker_to_media).kind==MediaKind::grant,"grant_roundtrip");
    reject([&]{media_message(valid,MediaDirection::media_to_broker);});
    for(std::size_t n=0;n<64;++n)reject([&]{media_message(std::vector<std::uint8_t>(valid.begin(),valid.begin()+n),MediaDirection::broker_to_media);});
    for(unsigned offset:{0u,4u,12u,48u,63u}){auto bad=valid;bad.at(offset)^=255;reject([&]{media_message(bad,MediaDirection::broker_to_media);});}
    auto wrong=valid;wrong.at(8)=255;wrong.at(9)=255;wrong.at(10)=255;reject([&]{media_message(wrong,MediaDirection::broker_to_media);});
    auto signal=make(MediaKind::signal,std::vector<std::uint8_t>(65536,'x'));signal.payload.at(0)=1;
    for(unsigned i=1;i<8;++i)signal.payload.at(i)=0;
    require(encode_media(signal,MediaDirection::broker_to_media).size()==65600,"sdp_max");
    signal.payload.push_back(0);reject([&]{encode_media(signal,MediaDirection::broker_to_media);});
    auto consumed=make(MediaKind::consumed,std::vector<std::uint8_t>(24));consumed.payload.at(0)=consumed.payload.at(8)=1;
    encode_media(consumed,MediaDirection::media_to_broker);reject([&]{encode_media(consumed,MediaDirection::broker_to_media);});
    auto stats=make(MediaKind::stats,std::vector<std::uint8_t>(96));stats.payload[0]=2;
    const auto stats_wire=encode_media(stats,MediaDirection::media_to_broker);
    require(media_message(stats_wire,MediaDirection::media_to_broker).payload.size()==96,"media_stats_v2_roundtrip");
    reject([&]{media_message(stats_wire,MediaDirection::broker_to_media);});
    for(unsigned offset:{0u,4u,92u}){auto bad=stats;bad.payload[offset]=255;reject([&]{encode_media(bad,MediaDirection::media_to_broker);});}
    stats.payload.resize(16);stats.payload[0]=1;reject([&]{encode_media(stats,MediaDirection::media_to_broker);});
    Message lease{{Kind::lease,24,grant.session,0,1,0,1},std::vector<std::uint8_t>(24)};lease.payload.at(0)=lease.payload.at(8)=1;
    auto forged=make(MediaKind::network_control,encode_control(lease,Direction::broker_to_worker));reject([&]{encode_media(forged,MediaDirection::media_to_broker);});
    Message release{{Kind::release_all,0,grant.session,0,1,0,1},{}};
    auto cleanup=make(MediaKind::network_control,encode_control(release,Direction::broker_to_worker));encode_media(cleanup,MediaDirection::media_to_broker);
    Message targeted{{Kind::release_all,8,grant.session,2,2,0,1},std::vector<std::uint8_t>(8)};targeted.payload[0]=2;targeted.payload[2]=1;
    auto precise=make(MediaKind::network_control,encode_control(targeted,Direction::broker_to_worker));
    const auto precise_wire=encode_media(precise,MediaDirection::media_to_broker);
    require(control_message(media_message(precise_wire,MediaDirection::media_to_broker).payload,Direction::broker_to_worker).payload==targeted.payload,"targeted_cleanup_roundtrip");
    reject([&]{media_message(precise_wire,MediaDirection::broker_to_media);});
    for(unsigned offset:{6u,16u,56u,64u,65u,67u}){auto bad=precise;bad.payload.at(offset)^=255;reject([&]{encode_media(bad,MediaDirection::media_to_broker);});}
    for(unsigned n=65;n<88;++n){if(n==72)continue;auto bad=precise;bad.payload.resize(n);reject([&]{encode_media(bad,MediaDirection::media_to_broker);});}
    cleanup.session.at(1)=1;reject([&]{encode_media(cleanup,MediaDirection::media_to_broker);});
    auto config=make(MediaKind::configuration,std::vector<std::uint8_t>(80));config.payload.at(0)=config.payload.at(4)=1;config.payload.at(16)=config.payload.at(48)=127;
    encode_media(config,MediaDirection::broker_to_media);config.payload.at(47)=1;reject([&]{encode_media(config,MediaDirection::broker_to_media);});
    std::cout<<"media_wire_fixed_schema_direction_bounds_no_network_grants=true\n";
}
}
int main(){try{test();return 0;}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
