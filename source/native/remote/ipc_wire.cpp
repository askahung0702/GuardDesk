#include "ipc_wire.hpp"
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace remote::ipc {
namespace {
void require(bool value){if(!value)throw std::invalid_argument("native_control_wire_rejected");}
template<class Bytes> std::uint64_t le(const Bytes& bytes,std::size_t offset,unsigned count){
    require(count<=8 && offset<=bytes.size() && count<=bytes.size()-offset);
    std::uint64_t value=0;for(unsigned i=0;i<count;++i)value|=std::uint64_t(bytes.at(offset+i))<<(8*i);return value;
}
bool nonzero(const Session& value){return std::any_of(value.begin(),value.end(),[](auto byte){return byte!=0;});}
std::uint32_t body_size(Kind kind){
    switch(kind){case Kind::hello:case Kind::capabilities:case Kind::desktop_state:return 16;
        case Kind::lease:case Kind::input:return 24;case Kind::stats:case Kind::frame_setup:return 32;
        case Kind::release_all:case Kind::stop:case Kind::presented:case Kind::consumed:return 0;}
    throw std::invalid_argument("native_control_kind_rejected");
}
bool broker_kind(Kind kind){return kind==Kind::lease || kind==Kind::input || kind==Kind::release_all || kind==Kind::stop || kind==Kind::presented || kind==Kind::consumed || kind==Kind::frame_setup;}
bool body_length(Kind kind,std::uint32_t size){return size==body_size(kind) || (kind==Kind::stats && (size==64 || size==384)) || (kind==Kind::release_all && size==8);}
void payload(const Message& m){
    const auto& b=m.payload;const auto kind=m.header.kind;
    if(kind==Kind::hello || kind==Kind::capabilities){
        require((le(b,0,8)&~std::uint64_t(31))==0 && le(b,8,4)==2 && le(b,12,4)==control_max_payload);
    }else if(kind==Kind::lease){
        require(le(b,0,8)>0 && le(b,8,8)>0 && le(b,16,4)<=1 && le(b,20,4)==0);
    }else if(kind==Kind::desktop_state){
        const auto state=le(b,0,4),width=le(b,4,4),height=le(b,8,4);
        require(state<=6 && le(b,12,4)==0 && width<=8192 && height<=8192 && width*height<=16777216);
        require((state!=1 && state!=3) || (width>0 && height>0 && m.header.desktop_generation>0));
    }else if(kind==Kind::frame_setup){
        // Private launch bootstrap ONLY: the authenticated SYSTEM broker has
        // duplicated these WRITE mapping handles into its retained worker.
        // Never forward this kind to/from WebRTC or accept network handles.
        require(le(b,0,8)>0 && le(b,8,8)>0 && le(b,0,8)!=le(b,8,8) &&
            le(b,16,8)>128 && le(b,16,8)<=128+16777216ull*4 && le(b,24,8)==0);
    }else if(kind==Kind::release_all && b.size()==8){
        // Targeted cleanup only: one already tracked key/button UP, never a
        // move, new down, duration, handle or arbitrary command.
        const auto type=b.at(0);const auto code=le(b,2,2);
        require(m.header.desktop_generation>0 && b.at(1)==0 && le(b,4,4)==0 &&
            ((type==1 && code>=1 && code<=254 && code!=231) || (type==2 && code>=1 && code<=3)));
    }else if(kind==Kind::input){
        const auto type=b.at(0),down=b.at(1);const auto code=le(b,2,2),x=le(b,4,4),y=le(b,8,4);
        const auto delta=static_cast<std::int32_t>(le(b,12,4));
        require(type>=1 && type<=4 && down<=1 && x<=8191 && y<=8191 && le(b,16,8)==0);
        if(type==1)require(code>0 && code<=254 && code!=231 && x==0 && y==0 && delta==0);
        if(type==2)require(code>=1 && code<=3 && delta==0);
        if(type==3)require(code==0 && down==0 && delta==0);
        if(type==4)require(code==0 && down==0 && delta>=-1200 && delta<=1200 && delta!=0 && delta%120==0);
    }
}
}
Header control_header(const std::array<std::uint8_t,control_header_bytes>& bytes,Direction direction){
    require(bytes.at(0)=='G' && bytes.at(1)=='D' && bytes.at(2)=='R' && bytes.at(3)=='2' && le(bytes,4,2)==2 && le(bytes,12,4)==0);
    const auto kind=le(bytes,6,2),size=le(bytes,8,4);require(kind>=1 && kind<=11 && size<=control_max_payload);
    Header value{static_cast<Kind>(kind),static_cast<std::uint32_t>(size),{},le(bytes,32,8),le(bytes,40,8),le(bytes,48,8),le(bytes,56,8)};
    std::copy(bytes.begin()+16,bytes.begin()+32,value.session.begin());
    // Generic owned-channel fixtures retain stats32. Product worker status is
    // version 3 / 384 bytes and is validated separately by the cohort bridge.
    require(body_length(value.kind,value.payload_bytes) && nonzero(value.session) && value.sequence>0 && value.transport_generation>0);
    if(value.kind==Kind::release_all && size==8)require(value.desktop_generation>0);
    require(broker_kind(value.kind)==(direction==Direction::broker_to_worker));
    if(value.kind==Kind::input || value.kind==Kind::presented || value.kind==Kind::consumed)require(value.desktop_generation>0 && value.frame_sequence>0);
    else require(value.frame_sequence==0);
    return value;
}
Message control_message(const std::vector<std::uint8_t>& bytes,Direction direction){
    require(bytes.size()>=control_header_bytes);std::array<std::uint8_t,control_header_bytes> header{};
    std::copy_n(bytes.begin(),control_header_bytes,header.begin());auto decoded=control_header(header,direction);
    require(bytes.size()==control_header_bytes+decoded.payload_bytes);
    Message message{decoded,{bytes.begin()+control_header_bytes,bytes.end()}};payload(message);return message;
}
std::vector<std::uint8_t> encode_control(const Message& message,Direction direction){
    const auto& h=message.header;require(message.payload.size()<=control_max_payload && h.payload_bytes==message.payload.size());
    std::vector<std::uint8_t> wire(control_header_bytes+message.payload.size());
    auto put=[&](std::size_t at,std::uint64_t value,unsigned count){for(unsigned i=0;i<count;++i)wire.at(at+i)=static_cast<std::uint8_t>(value>>(8*i));};
    wire.at(0)='G';wire.at(1)='D';wire.at(2)='R';wire.at(3)='2';put(4,2,2);put(6,static_cast<unsigned>(h.kind),2);put(8,h.payload_bytes,4);
    std::copy(h.session.begin(),h.session.end(),wire.begin()+16);put(32,h.desktop_generation,8);put(40,h.sequence,8);put(48,h.frame_sequence,8);put(56,h.transport_generation,8);
    std::copy(message.payload.begin(),message.payload.end(),wire.begin()+control_header_bytes);control_message(wire,direction);return wire;
}
ControlGate::ControlGate(Session session,std::uint64_t transport,std::uint64_t now,std::uint64_t consent_deadline)
    :session_(session),transport_(transport),consent_deadline_(consent_deadline){
    require(nonzero(session) && transport>0 && valid_consent(consent_deadline,now));
}
bool ControlGate::authorized(std::uint64_t now) const{return !stopped_ && now<consent_deadline_ && now<lease_deadline_;}
void ControlGate::invalidate_input_ack(){ack_frame_=ack_tick_=0;frames_={};}
void ControlGate::pause(){active_=false;invalidate_input_ack();}
void ControlGate::revoke(){stopped_=true;pause();}
bool ControlGate::set_desktop(std::uint64_t generation,unsigned width,unsigned height){
    if(stopped_ || generation<=generation_ || width==0 || height==0 || width>8192 || height>8192 || std::uint64_t(width)*height>16777216)return false;
    pause();generation_=generation;width_=width;height_=height;active_=true;return true;
}
bool ControlGate::frame(std::uint64_t sequence,std::uint64_t now){
    if(!active_ || !authorized(now) || sequence<=last_frame_)return false;
    frames_[static_cast<std::size_t>(sequence%frames_.size())]={sequence,now};last_frame_=sequence;return true;
}
bool ControlGate::accept_broker(const Message& m,std::uint64_t now){
    refusal_=1;auto reject=[&](unsigned reason){refusal_=reason;return false;};
    const auto& h=m.header;
    if(h.kind==Kind::frame_setup)return false; // Consumed once by startup, never a live command.
    // Message is an internal value, so repeat schema/direction validation even
    // if a future caller constructs it without using control_message().
    if(!broker_kind(h.kind) || h.payload_bytes!=m.payload.size() || !body_length(h.kind,h.payload_bytes) ||
        h.session!=session_ || h.transport_generation!=transport_ || h.sequence<=last_command_)return false;
    if(h.kind==Kind::input || h.kind==Kind::presented || h.kind==Kind::consumed){if(!h.desktop_generation || !h.frame_sequence)return false;}
    else if(h.frame_sequence)return false;
    try{payload(m);}catch(const std::invalid_argument&){return reject(7);}
    if(h.kind==Kind::stop){last_command_=h.sequence;revoke();return true;}
    if(h.kind==Kind::release_all){
        if(m.payload.size()==8 && (!generation_ || h.desktop_generation!=generation_))return false;
        last_command_=h.sequence;return true;
    }
    if(stopped_)return reject(2);
    // An expired worker is terminal; a delayed/new reply cannot revive this
    // consent/transport instance. Cleanup-only messages above remain usable.
    if(now>=consent_deadline_ || (lease_deadline_ && now>=lease_deadline_)){revoke();return reject(2);}
    // No work queue or delayed replay when an authenticated peer floods us.
    // This is a fixed per-instance bucket, not a history of timestamps. Stop
    // and release above remain cleanup-only and never restore authorization.
    if(rate_initialized_ && now<rate_started_){revoke();return reject(3);}
    if(!rate_initialized_ || now-rate_started_>=1000){rate_started_=now;rate_count_=0;rate_initialized_=true;}
    if(rate_count_>=control_commands_per_second){last_command_=h.sequence;revoke();return reject(3);}
    ++rate_count_;
    if(h.kind==Kind::lease){
        const auto deadline=le(m.payload,0,8),generation=le(m.payload,8,8);
        const bool control=le(m.payload,16,4)==1;
        if(deadline<=now || deadline-now>5000 || deadline>consent_deadline_ || generation<authorization_)return reject(2);
        if(generation!=authorization_ || control!=control_){ack_frame_=ack_tick_=0;}
        authorization_=generation;control_=control;lease_deadline_=deadline;last_command_=h.sequence;return true;
    }
    if(!authorized(now))return reject(2);
    if(!active_ || h.desktop_generation!=generation_)return reject(4);
    if(h.kind==Kind::presented || h.kind==Kind::consumed){
        const auto& frame=frames_[static_cast<std::size_t>(h.frame_sequence%frames_.size())];
        if(frame.sequence!=h.frame_sequence || now<frame.tick || now-frame.tick>1000 || h.frame_sequence<ack_frame_)return reject(5);
        if(h.kind==Kind::presented){ack_frame_=frame.sequence;ack_tick_=frame.tick;}
        last_command_=h.sequence;return true;
    }
    if(h.kind==Kind::input){
        if(!control_)return reject(6);
        if(!ack_frame_ || h.frame_sequence!=ack_frame_ || now<ack_tick_ || now-ack_tick_>1000)return reject(5);
        if(m.payload.at(0)!=1 && (le(m.payload,4,4)>=width_ || le(m.payload,8,4)>=height_))return reject(7);
        last_command_=h.sequence;return true;
    }
    return false;
}
}
