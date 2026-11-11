#include "frame_binding.hpp"
#include <algorithm>
#include <stdexcept>

namespace remote {
namespace {
void require(bool okay){if(!okay)throw std::invalid_argument("video_binding_rejected");}
std::uint64_t get(const std::vector<std::uint8_t>& packet,std::size_t at,unsigned count){std::uint64_t value=0;for(unsigned i=0;i<count;++i)value|=std::uint64_t(packet.at(at+i))<<(8*i);return value;}
void valid(const VideoBinding& value){
    bool nonzero=false;for(auto byte:value.frame.session)nonzero|=byte!=0;
    const auto& f=value.frame;require(nonzero && value.transport && f.generation && f.sequence && f.tick && f.slot<2 &&
        f.width && f.height && f.width<=1920 && f.height<=1080 && f.width%2==0 && f.height%2==0);
}
}
std::vector<std::uint8_t> encode_video_binding(const VideoBinding& value){
    valid(value);std::vector<std::uint8_t> packet(88);
    auto put=[&](std::size_t at,std::uint64_t number,unsigned count){for(unsigned i=0;i<count;++i)packet.at(at+i)=static_cast<std::uint8_t>(number>>(8*i));};
    packet.at(0)='G';packet.at(1)='D';packet.at(2)='M';packet.at(3)='1';put(4,1,2);put(6,1,2);put(8,88,4);
    std::copy(value.frame.session.begin(),value.frame.session.end(),packet.begin()+16);
    put(32,value.transport,8);put(40,value.frame.generation,8);put(48,value.frame.sequence,8);put(56,value.frame.tick,8);
    put(64,value.rtp_timestamp,4);put(68,value.frame.width,4);put(72,value.frame.height,4);put(80,value.frame.slot,4);return packet;
}
VideoBinding decode_video_binding(const std::vector<std::uint8_t>& packet){
    require(packet.size()==88 && packet.at(0)=='G' && packet.at(1)=='D' && packet.at(2)=='M' && packet.at(3)=='1' &&
        get(packet,4,2)==1 && get(packet,6,2)==1 && get(packet,8,4)==88 && get(packet,12,4)==0 && get(packet,76,4)==0 && get(packet,84,4)==0);
    VideoBinding value{};std::copy_n(packet.begin()+16,16,value.frame.session.begin());value.transport=get(packet,32,8);
    value.frame.generation=get(packet,40,8);value.frame.sequence=get(packet,48,8);value.frame.tick=get(packet,56,8);
    value.rtp_timestamp=static_cast<std::uint32_t>(get(packet,64,4));value.frame.width=static_cast<unsigned>(get(packet,68,4));
    value.frame.height=static_cast<unsigned>(get(packet,72,4));value.frame.slot=static_cast<unsigned>(get(packet,80,4));valid(value);return value;
}
FrameBindings::FrameBindings(ipc::Session session,std::uint64_t transport):session_(session),transport_(transport){require(transport!=0);}
bool FrameBindings::record(const VideoBinding& value,std::uint64_t received){
    try{valid(value);}catch(const std::invalid_argument&){return false;}
    std::lock_guard<std::mutex> lock(mutex_);
    if(value.frame.session!=session_ || value.transport!=transport_ || value.frame.generation<generation_ || value.frame.sequence<=last_sequence_)return false;
    if(value.frame.generation>generation_){values_={};generation_=value.frame.generation;}
    for(const auto& item:values_)if(item.binding.frame.sequence && item.binding.rtp_timestamp==value.rtp_timestamp)return false;
    values_.at(static_cast<std::size_t>(value.frame.sequence%values_.size()))={value,received};last_sequence_=value.frame.sequence;return true;
}
std::optional<VideoBinding> FrameBindings::find(std::uint32_t stamp,std::uint64_t now) const{
    std::lock_guard<std::mutex> lock(mutex_);
    for(const auto& item:values_)if(item.binding.frame.sequence && item.binding.rtp_timestamp==stamp && item.binding.frame.generation==generation_ && now>=item.received && now-item.received<=1000)return item.binding;
    return std::nullopt;
}
void FrameBindings::clear(){std::lock_guard<std::mutex> lock(mutex_);values_={};}
}
