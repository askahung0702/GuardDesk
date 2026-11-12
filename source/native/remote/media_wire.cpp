#include "media_wire.hpp"
#include "relay_policy.hpp"
#include <algorithm>
#include <stdexcept>

namespace remote::ipc {
namespace {
void require(bool okay){if(!okay)throw std::invalid_argument("media_wire_rejected");}
std::uint64_t get(const std::vector<std::uint8_t>& b,std::size_t offset,unsigned count){
    require(offset+count<=b.size());std::uint64_t result=0;
    for(unsigned i=0;i<count;++i)result|=std::uint64_t(b.at(offset+i))<<(i*8);return result;
}
void put(std::vector<std::uint8_t>& b,std::size_t offset,std::uint64_t value,unsigned count){
    for(unsigned i=0;i<count;++i)b.at(offset+i)=static_cast<std::uint8_t>(value>>(i*8));
}
void zero(const std::vector<std::uint8_t>& b,std::size_t start,std::size_t end){for(auto i=start;i<end;++i)require(b.at(i)==0);}
bool parent(MediaDirection d){return d==MediaDirection::broker_to_media;}
void body(const MediaMessage& m,MediaDirection d){
    const auto& p=m.payload;
    switch(m.kind){
    case MediaKind::grant:require(parent(d) && p.size()==16 && get(p,0,8)>0 && get(p,8,4)<=1);zero(p,12,16);break;
    case MediaKind::signal:
        require(p.size()>8 && p.size()<=media_max_payload && (p.at(0)==1 || p.at(0)==2));zero(p,1,8);
        for(std::size_t i=8;i<p.size();++i)require(p.at(i)==9 || p.at(i)==10 || p.at(i)==13 || (p.at(i)>=32 && p.at(i)<=126));break;
    case MediaKind::network_control:{
        require(!parent(d) && p.size()>=64 && p.size()<=88);
        const auto v=control_message(p,Direction::broker_to_worker);
        require(v.header.session==m.session && v.header.transport_generation==m.transport &&
            (v.header.kind==Kind::input || v.header.kind==Kind::presented || v.header.kind==Kind::release_all || v.header.kind==Kind::stop));break;}
    case MediaKind::consumed:require(!parent(d) && p.size()==24 && get(p,0,8)>0 && get(p,8,8)>0 && get(p,16,4)<2);zero(p,20,24);break;
    case MediaKind::stop:require(parent(d) && p.empty());break;
    case MediaKind::stats:require(!parent(d) && p.size()==media_stats_bytes && get(p,0,4)==media_stats_version && (get(p,4,4)&~15u)==0 && get(p,40,4)<=20000000);zero(p,92,media_stats_bytes);break;
    case MediaKind::configuration:
        require(parent(d) && p.size()==80 && get(p,0,4)>=1 && get(p,0,4)<=8 && get(p,4,4)>=1 && get(p,4,4)<=8 && get(p,8,4)<=1);
        zero(p,12,16);zero(p,16+static_cast<std::size_t>(get(p,0,4))*4,48);zero(p,48+static_cast<std::size_t>(get(p,4,4))*4,80);break;
    case MediaKind::relay_configuration:require(parent(d));remote::parse_relay(p);break;
    default:require(false);
    }
}
}
std::vector<std::uint8_t> media_stats_payload(const std::array<std::uint32_t,22>& counters){
    std::vector<std::uint8_t> payload(media_stats_bytes);put(payload,0,media_stats_version,4);
    for(std::size_t i=0;i<counters.size();++i)put(payload,4+i*4,counters.at(i),4);
    return payload;
}
MediaHeader media_header(const std::array<std::uint8_t,64>& bytes,MediaDirection d){
    const std::vector<std::uint8_t> b(bytes.begin(),bytes.end());
    require(b.at(0)=='G' && b.at(1)=='D' && b.at(2)=='M' && b.at(3)=='3' && get(b,4,2)==1);
    zero(b,12,16);zero(b,48,64);
    const auto kind=static_cast<MediaKind>(get(b,6,2));const auto n=get(b,8,4);
    require(n<=media_max_payload);
    bool allowed=false;
    switch(kind){
    case MediaKind::grant:allowed=parent(d) && n==16;break;
    case MediaKind::signal:allowed=n>8;break;
    // Empty controls, targeted ledger cleanup, and fixed input respectively.
    // The inner parser still verifies the exact kind/body/direction contract.
    case MediaKind::network_control:allowed=!parent(d) && (n==64 || n==72 || n==88);break;
    case MediaKind::consumed:allowed=!parent(d) && n==24;break;
    case MediaKind::stop:allowed=parent(d) && n==0;break;
    case MediaKind::stats:allowed=!parent(d) && n==media_stats_bytes;break;
    case MediaKind::configuration:allowed=parent(d) && n==80;break;
    case MediaKind::relay_configuration:allowed=parent(d) && n>=128 && n<=1152;break;
    default:break;
    }require(allowed);
    MediaMessage m;m.kind=kind;std::copy_n(b.begin()+16,16,m.session.begin());m.transport=get(b,32,8);m.sequence=get(b,40,8);
    require(m.transport && m.sequence && std::any_of(m.session.begin(),m.session.end(),[](auto c){return c!=0;}));
    return {std::move(m),static_cast<std::uint32_t>(n)};
}
MediaMessage media_message(const std::vector<std::uint8_t>& b,MediaDirection d){
    require(b.size()>=64 && b.size()<=64+media_max_payload);std::array<std::uint8_t,64> h{};std::copy_n(b.begin(),64,h.begin());
    auto decoded=media_header(h,d);require(b.size()==64+decoded.payload_bytes);
    decoded.message.payload.assign(b.begin()+64,b.end());body(decoded.message,d);return std::move(decoded.message);
}
std::vector<std::uint8_t> encode_media(const MediaMessage& m,MediaDirection d){
    require(m.payload.size()<=media_max_payload);std::vector<std::uint8_t> b(64+m.payload.size());
    b.at(0)='G';b.at(1)='D';b.at(2)='M';b.at(3)='3';put(b,4,1,2);put(b,6,static_cast<unsigned>(m.kind),2);put(b,8,m.payload.size(),4);
    std::copy(m.session.begin(),m.session.end(),b.begin()+16);put(b,32,m.transport,8);put(b,40,m.sequence,8);
    std::copy(m.payload.begin(),m.payload.end(),b.begin()+64);media_message(b,d);return b;
}
}
