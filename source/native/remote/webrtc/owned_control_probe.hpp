#pragma once
// Owned binary-wire integration only, not a trusted product broker. No desktop,
// endpoint token, input API or center authorization. A local fixture supplies
// the short lease; packets from the WebRTC peer can never grant/renew it.
#include "ipc_wire.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <optional>
#include <span>
#include <stdexcept>
#include <thread>
#include "api/data_channel_interface.h"

namespace owned_control {
using namespace remote::ipc;
inline std::uint64_t now(){return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());}
inline void put(std::vector<std::uint8_t>& bytes,std::size_t offset,std::uint64_t value,unsigned count){
  if(offset+count>bytes.size())throw std::invalid_argument("owned_wire_write_bound");
  for(unsigned i=0;i<count;++i)bytes.at(offset+i)=static_cast<std::uint8_t>(value>>(i*8));
}
inline std::uint64_t get(const std::vector<std::uint8_t>& bytes,std::size_t offset,unsigned count){
  if(offset+count>bytes.size())throw std::invalid_argument("owned_wire_read_bound");
  std::uint64_t result=0;for(unsigned i=0;i<count;++i)result|=std::uint64_t(bytes.at(offset+i))<<(i*8);return result;
}
inline std::vector<std::uint8_t> packet(Kind kind,std::uint64_t sequence,std::uint64_t generation=1,std::uint64_t frame=1){
  const unsigned size=kind==Kind::input || kind==Kind::lease?24:kind==Kind::stats?32:0;
  std::vector<std::uint8_t> bytes(control_header_bytes+size);
  std::copy_n("GDR2",4,bytes.begin());put(bytes,4,2,2);put(bytes,6,static_cast<unsigned>(kind),2);put(bytes,8,size,4);
  bytes.at(16)=7;put(bytes,32,generation,8);put(bytes,40,sequence,8);put(bytes,56,5,8);
  if(kind==Kind::presented || kind==Kind::input)put(bytes,48,frame,8);
  if(kind==Kind::input){bytes.at(64)=1;put(bytes,66,27,2);} // Synthetic Esc metadata; never SendInput.
  if(kind==Kind::lease){put(bytes,64,now()+4500,8);put(bytes,72,1,8);put(bytes,80,1,4);}
  return bytes;
}
class Wire {
  bool endpoint_=false;
  std::optional<ControlGate> gate_;
  std::optional<std::vector<std::uint8_t>> pending_; // at most one 96-byte scalar reply
  std::uint64_t viewer_sequence_=0,broker_sequence_=1,response_sequence_=0;
 public:
  std::atomic<bool> failed{false};
  std::atomic<unsigned> replies{0};
  std::atomic<std::uint64_t> echoed_sequence{0};
  std::atomic<bool> accepted{false};
  void endpoint(){
    endpoint_=true;Session session{};session.at(0)=7;const auto tick=now();gate_.emplace(session,5,tick,tick+8000);
    if(!gate_->accept_broker(control_message(packet(Kind::lease,1),Direction::broker_to_worker),tick) ||
       !gate_->set_desktop(1,320,180) || !gate_->frame(1,tick))throw std::runtime_error("owned_wire_fixture_grant");
  }
  // All receive/state/mailbox access is on the signaling thread. Do not call
  // WebRTC APIs from OnMessage: its observer contract forbids re-entrant calls.
  void receive(const webrtc::DataBuffer& value){
    if(failed)return;
    try{
      if(!value.binary || value.size()<64 || value.size()>96)throw std::invalid_argument("owned_wire_size_or_type");
      std::vector<std::uint8_t> bytes(value.data.begin(),value.data.end());
      auto message=control_message(bytes,endpoint_?Direction::broker_to_worker:Direction::worker_to_broker);
      Session session{};session.at(0)=7;
      if(message.header.session!=session || message.header.transport_generation!=5)throw std::invalid_argument("owned_wire_binding");
      if(endpoint_){
        if(pending_)throw std::invalid_argument("owned_wire_no_reply_queue");
        const auto sequence=message.header.sequence;bool allowed=false;
        if(sequence>viewer_sequence_){
          viewer_sequence_=sequence; // consume refused commands too; never replay later
          // This local fixture models the broker's separate authority/order.
          // No network lease, regardless of a valid DTLS channel or schema.
          if(message.header.kind!=Kind::lease){
            message.header.sequence=++broker_sequence_;allowed=gate_->accept_broker(message,now());
          }
        }
        auto reply=packet(Kind::stats,++response_sequence_);put(reply,64,allowed?1:0,8);put(reply,72,sequence,8);pending_=std::move(reply);
      }else{
        if(message.header.kind!=Kind::stats || message.header.sequence!=replies.load()+1 || get(message.payload,0,8)>1)
          throw std::invalid_argument("owned_wire_reply_order");
        accepted=get(message.payload,0,8)==1;echoed_sequence=get(message.payload,8,8);++replies;
      }
    }catch(const std::exception&){if(gate_)gate_->revoke();pending_.reset();failed=true;}
  }
  std::optional<std::vector<std::uint8_t>> take_reply(){auto result=std::move(pending_);pending_.reset();return result;}
  bool switch_desktop(){gate_->pause();return gate_->set_desktop(2,320,180) && gate_->frame(2,now());}
};
inline bool send(webrtc::DataChannelInterface* channel,const std::vector<std::uint8_t>& bytes){
  return channel && channel->state()==webrtc::DataChannelInterface::kOpen && bytes.size()<=96 &&
    channel->buffered_amount()+bytes.size()<=4096 && channel->Send(webrtc::DataBuffer(webrtc::CopyOnWriteBuffer(std::span<const std::uint8_t>(bytes)),true));
}
template<class A,class B>
bool run(A& a,B& b,webrtc::Thread& signaling){
  // Negotiate first; the fixture's five-second lease does not include ICE's
  // unrelated startup time. Only this local trusted fixture can supply it.
  signaling.BlockingCall([&]{b.wire.endpoint();});
  auto request=[&](std::vector<std::uint8_t> bytes,bool expected){
    const auto sequence=get(bytes,40,8);const auto count=a.wire.replies.load();
    if(!send(a.channel.get(),bytes))return false;
    const auto end=now()+3000;
    while(a.wire.replies==count && now()<end && !a.wire.failed && !b.wire.failed){
      auto reply=signaling.BlockingCall([&]{return b.wire.take_reply();});
      if(reply && !send(b.channel.get(),*reply))return false;
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return a.wire.replies==count+1 && a.wire.accepted==expected && a.wire.echoed_sequence==sequence && !a.wire.failed && !b.wire.failed;
  };
  if(!request(packet(Kind::input,1),false) || !request(packet(Kind::presented,2,1,99),false) ||
     !request(packet(Kind::presented,3),true) || !request(packet(Kind::input,4),true) ||
     !request(packet(Kind::input,4),false) || !request(packet(Kind::lease,5),false))return false;
  if(!signaling.BlockingCall([&]{return b.wire.switch_desktop();}))return false;
  if(!request(packet(Kind::input,6),false) || !request(packet(Kind::presented,7,2,2),true) ||
     !request(packet(Kind::input,8,2,2),true) || !request(packet(Kind::presented,9),false) ||
     !request(packet(Kind::stop,10),true) || !request(packet(Kind::input,11,2,2),false) ||
     !request(packet(Kind::lease,12),false) || !request(packet(Kind::release_all,13),true))return false;
  // A malformed packet terminates this owned endpoint state, not a resync
  // that may resurrect a stopped authorization. No packet bytes enter logs.
  auto malformed=packet(Kind::input,14,2,2);put(malformed,8,65537,4);
  if(!send(a.channel.get(),malformed))return false;
  const auto end=now()+3000;while(!b.wire.failed && now()<end)std::this_thread::sleep_for(std::chrono::milliseconds(1));
  return b.wire.failed && !a.wire.failed && a.wire.replies==14;
}
}
