// Pure native control-wire/lease tests. No Windows input or desktop API.
#include "ipc_wire.hpp"
#include "worker_status.hpp"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace {
using namespace remote::ipc;
void require(bool value){if(!value)throw std::runtime_error("native_wire_test_failed");}
template<class F> void rejected(F&& action){bool denied=false;try{action();}catch(const std::invalid_argument&){denied=true;}require(denied);}
void put(std::vector<std::uint8_t>& bytes,std::size_t offset,std::uint64_t value,unsigned count){
    require(offset+count<=bytes.size());for(unsigned i=0;i<count;++i)bytes.at(offset+i)=static_cast<std::uint8_t>(value>>(8*i));
}
std::vector<std::uint8_t> packet(Kind kind,unsigned body,std::uint64_t sequence=1,std::uint64_t generation=0,std::uint64_t frame=0){
    std::vector<std::uint8_t> bytes(control_header_bytes+body);std::memcpy(bytes.data(),"GDR2",4);
    put(bytes,4,2,2);put(bytes,6,static_cast<unsigned>(kind),2);put(bytes,8,body,4);bytes[16]=7;
    put(bytes,32,generation,8);put(bytes,40,sequence,8);put(bytes,48,frame,8);put(bytes,56,5,8);return bytes;
}
Message command(Kind kind,std::uint64_t sequence,std::uint64_t generation=1,std::uint64_t frame=1){
    const bool with_frame=kind==Kind::input || kind==Kind::presented;
    auto bytes=packet(kind,kind==Kind::input?24:0,sequence,generation,with_frame?frame:0);
    if(kind==Kind::input){bytes[64]=2;bytes[65]=1;put(bytes,66,1,2);put(bytes,68,10,4);put(bytes,72,20,4);}
    return control_message(bytes,Direction::broker_to_worker);
}
Message lease(std::uint64_t sequence,std::uint64_t deadline,std::uint64_t authorization,bool control){
    auto bytes=packet(Kind::lease,24,sequence);put(bytes,64,deadline,8);put(bytes,72,authorization,8);put(bytes,80,control?1:0,4);
    return control_message(bytes,Direction::broker_to_worker);
}
int test(){
    auto up=packet(Kind::release_all,8,1,1);up[64]=2;up[66]=1;
    require(control_message(up,Direction::broker_to_worker).payload.size()==8);
    rejected([&]{control_message(up,Direction::worker_to_broker);});
    for(auto field:{std::make_pair(64u,3u),std::make_pair(65u,1u),std::make_pair(66u,4u),std::make_pair(68u,1u),std::make_pair(32u,0u)}){
        auto bad=up;bad[field.first]=static_cast<std::uint8_t>(field.second);rejected([&]{control_message(bad,Direction::broker_to_worker);});
    }
    up[64]=1;up[66]=231;rejected([&]{control_message(up,Direction::broker_to_worker);});
    remote::WorkerStatus sample;sample.stage=3;sample.api=106;sample.error=0x887a0022;
    sample.polls=0xffffffff;remote::WorkerStatus::increment(sample.polls);require(sample.polls==0xffffffff);
    auto diagnostic=packet(Kind::stats,static_cast<unsigned>(remote::WorkerStatus::wire_bytes));const auto body=sample.encode();std::copy(body.begin(),body.end(),diagnostic.begin()+64);
    require(control_message(diagnostic,Direction::worker_to_broker).payload.at(12)==0x22);
    require(remote::valid_worker_status(control_message(diagnostic,Direction::worker_to_broker).payload));
    require(!remote::valid_worker_status({}));
    rejected([&]{control_message(diagnostic,Direction::broker_to_worker);});
    for(auto entry:{std::make_pair(64u,1u),std::make_pair(68u,14u),std::make_pair(72u,113u),std::make_pair(116u,33u)}){
        auto bad=diagnostic;put(bad,entry.first,entry.second,4);require(!remote::valid_worker_status(control_message(bad,Direction::worker_to_broker).payload));
    }
    auto input=packet(Kind::input,24,1,1,1);input[64]=1;put(input,66,27,2);
    require(control_message(input,Direction::broker_to_worker).header.frame_sequence==1);
    unsigned truncated=0;
    for(std::size_t size=0;size<control_header_bytes;++size){
        rejected([&]{control_message({input.begin(),input.begin()+size},Direction::broker_to_worker);});++truncated;
    }
    rejected([&]{control_message(input,Direction::worker_to_broker);});
    for(unsigned offset:{0u,4u,6u,8u,12u,16u,32u,40u,48u,56u}){
        auto invalid=input;invalid.at(offset)=offset==12?1:0;
        rejected([&]{control_message(invalid,Direction::broker_to_worker);});
    }
    auto invalid=input;put(invalid,8,65537,4);rejected([&]{control_message(invalid,Direction::broker_to_worker);});
    invalid=input;invalid.push_back(0);rejected([&]{control_message(invalid,Direction::broker_to_worker);});
    invalid=input;invalid[65]=2;rejected([&]{control_message(invalid,Direction::broker_to_worker);});
    invalid=input;put(invalid,66,231,2);rejected([&]{control_message(invalid,Direction::broker_to_worker);});
    invalid=input;put(invalid,80,1,8);rejected([&]{control_message(invalid,Direction::broker_to_worker);});
    auto hello=packet(Kind::hello,16);put(hello,72,2,4);put(hello,76,control_max_payload,4);
    require(control_message(hello,Direction::worker_to_broker).header.kind==Kind::hello);
    hello[64]=128;rejected([&]{control_message(hello,Direction::worker_to_broker);});
    Session session{};session[0]=7;ControlGate gate(session,5,100,10000);
    require(!gate.authorized(100));require(gate.accept_broker(lease(1,5000,1,true),101));
    require(gate.set_desktop(1,1920,1080));require(gate.frame(1,102));
    require(!gate.accept_broker(command(Kind::input,2),103));
    require(gate.accept_broker(command(Kind::presented,3),104));require(gate.accept_broker(command(Kind::input,4),105));
    require(!gate.accept_broker(command(Kind::input,4),106));require(gate.frame(2,106));
    require(!gate.accept_broker(command(Kind::presented,5,1,99),107));
    require(gate.accept_broker(command(Kind::presented,6,1,2),107));
    require(!gate.accept_broker(command(Kind::presented,7,1,1),108));
    gate.pause();require(!gate.frame(3,109));require(!gate.accept_broker(command(Kind::input,8,1,2),109));
    require(!gate.set_desktop(1,1920,1080));require(gate.set_desktop(2,1920,1080));require(gate.frame(3,110));
    require(!gate.accept_broker(command(Kind::presented,9,1,3),111));
    require(gate.accept_broker(command(Kind::presented,10,2,3),112));require(gate.accept_broker(command(Kind::input,11,2,3),113));
    require(!gate.accept_broker(command(Kind::input,12,1,2),114));
    require(!gate.accept_broker(lease(13,120,1,true),130)); // Delayed expired lease never restarts its duration.
    require(gate.accept_broker(lease(14,4500,2,false),200));
    require(gate.accept_broker(command(Kind::presented,15,2,3),201));require(!gate.accept_broker(command(Kind::input,16,2,3),202));
    require(gate.accept_broker(lease(17,4500,3,true),202));require(!gate.accept_broker(command(Kind::input,18,2,3),203));
    require(gate.accept_broker(command(Kind::presented,19,2,3),203));require(gate.accept_broker(command(Kind::input,20,2,3),204));
    require(!gate.accept_broker(command(Kind::input,21,2,3),1111));require(gate.frame(4,1112));
    require(gate.accept_broker(command(Kind::presented,22,2,4),1113));require(gate.accept_broker(command(Kind::input,23,2,4),1114));
    for(unsigned sequence=5;sequence<=100;++sequence)require(gate.frame(sequence,1200+sequence));
    require(!gate.accept_broker(command(Kind::presented,24,2,4),1350));
    require(gate.accept_broker(command(Kind::presented,25,2,100),1350));
    require(!gate.frame(99,1351));
    require(!gate.accept_broker(lease(26,99999,3,true),1351)); // No greater-than-five-second grant.
    auto other=command(Kind::input,27,2,100);++other.header.transport_generation;require(!gate.accept_broker(other,1352));
    other=command(Kind::input,28,2,100);other.header.session[0]=8;require(!gate.accept_broker(other,1352));
    require(gate.accept_broker(command(Kind::release_all,29),6000));require(!gate.authorized(6000));
    require(gate.accept_broker(command(Kind::stop,30),6000));require(!gate.accept_broker(lease(31,9000,4,true),6001));
    ControlGate expired(session,5,100,10000);
    require(expired.accept_broker(lease(1,300,1,true),101));require(!expired.authorized(300));
    require(!expired.accept_broker(lease(2,1000,2,true),400));
    require(!expired.accept_broker(lease(3,1200,3,true),401));
    require(expired.accept_broker(command(Kind::release_all,4),402));
    require(expired.accept_broker(command(Kind::stop,5),403));
    require(!expired.accept_broker(command(Kind::input,6),404));
    // A valid authenticated stream still needs a CPU/work bound. No queue or
    // delayed replay; cleanup remains possible after the overload terminal.
    ControlGate flood(session,5,100,10000);
    require(flood.accept_broker(lease(1,4500,1,true),101));
    require(flood.set_desktop(1,1920,1080) && flood.frame(1,102));
    require(flood.accept_broker(command(Kind::presented,2),103));
    for(unsigned i=3;i<=240;++i)require(flood.accept_broker(command(Kind::input,i),104));
    if(flood.accept_broker(command(Kind::input,241),104))throw std::runtime_error("native_rate_overflow_did_not_revoke");
    require(flood.accept_broker(command(Kind::release_all,242),105));
    require(!flood.accept_broker(lease(243,5000,2,true),1200));
    require(!flood.accept_broker(command(Kind::input,244),1201));
    ControlGate paced(session,5,100,10000);
    require(paced.accept_broker(lease(1,4500,1,true),101));
    require(paced.set_desktop(1,1920,1080) && paced.frame(1,102));
    require(paced.accept_broker(command(Kind::presented,2),103));
    for(unsigned i=3;i<=200;++i)require(paced.accept_broker(command(Kind::input,i),104));
    require(paced.frame(2,1102));
    require(paced.accept_broker(lease(201,5000,1,true),1102));
    require(paced.accept_broker(command(Kind::presented,202,1,2),1103));
    for(unsigned i=203;i<=400;++i)require(paced.accept_broker(command(Kind::input,i,1,2),1104));
    // The bound resets with time; it is not a cumulative session/file limit.
    ControlGate clock_reversed(session,5,100,10000);
    require(clock_reversed.accept_broker(lease(1,4500,1,true),101));
    require(!clock_reversed.accept_broker(lease(2,4500,1,true),100));
    require(!clock_reversed.accept_broker(lease(3,4500,1,true),102));
    rejected([&]{ControlGate invalid_gate(session,5,100,700000);});
    ControlGate continued(session,5,100,no_session_deadline);
    std::uint64_t renewal=0;
    for(std::uint64_t now=101;now<3600101;now+=1000){
        require(continued.accept_broker(lease(++renewal,now+4000,1,true),now));
        require(continued.authorized(now+999));
    }
    require(!continued.authorized(3605000));
    require(!continued.accept_broker(lease(++renewal,3609000,1,true),3605000));
    require(!continued.authorized(3605001)); // Expired leases cannot be revived.
    std::cout<<"{\"passed\":true,\"native_wire\":2,\"truncated_headers_rejected\":"<<truncated
        <<",\"lease_ACK_generation_replay_tests\":true,\"rate_overload_terminal_and_paced_windows\":true,\"actual_IPC_IO\":false,\"SYSTEM_or_OS_input\":false,\"product_capability_enabled\":false}\n";
    return 0;
}
}
int main(){try{return test();}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
