#include "media_peer.hpp"
#include "network_guard.hpp"
#include "p2p/test/test_turn_server.h"
#include "api/environment/environment_factory.h"
#include "rtc_base/win32_socket_init.h"
#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>
namespace {
void require(bool value){if(!value)throw std::runtime_error("owned_relay_check");}
void put(std::vector<std::uint8_t>& b,unsigned at,std::uint64_t value,unsigned count){for(unsigned i=0;i<count;++i)b.at(at+i)=static_cast<std::uint8_t>(value>>(8*i));}
remote::MediaPeerOptions options(bool endpoint){remote::MediaPeerOptions value;value.session[0]=19;value.transport=8;value.endpoint=endpoint;value.owned_loopback=true;
    value.consent_deadline=GetTickCount64()+30000;value.local_ipv4={"127.0.0.1"};value.peer_ipv4={"127.0.0.1"};return value;}
std::vector<std::uint8_t> policy(unsigned port,bool tls=false,std::string password="owned-relay-credential"){
    std::string host=tls?"owned.guarddesk.invalid":"",user="owned-relay-credential";std::vector<std::uint8_t> b(128+host.size()+user.size()+password.size());
    b.at(0)='G';b.at(1)='D';b.at(2)='R';b.at(3)='3';put(b,4,1,2);put(b,6,tls?1:2,2);put(b,8,b.size(),4);b.at(16)=1;
    put(b,48,GetTickCount64()+15000,8);put(b,56,0x0100007f,4);put(b,60,port,2);put(b,62,host.size(),2);put(b,64,user.size(),2);put(b,66,password.size(),2);
    put(b,68,1,4);put(b,72,0x0100007f,4);put(b,88,1,2);put(b,90,65535,2);std::copy(host.begin(),host.end(),b.begin()+128);
    std::copy(user.begin(),user.end(),b.begin()+128+host.size());std::copy(password.begin(),password.end(),b.begin()+128+host.size()+user.size());return b;
}
unsigned stage=0;
void test(){
    webrtc::WinsockInitializer winsock;require(winsock.error()==0);
    auto environment=webrtc::CreateEnvironment();auto thread=webrtc::Thread::CreateWithSocketServer();require(thread->Start());
    std::unique_ptr<webrtc::TestTurnServer> server,tls_server;unsigned port=0;
    // Bind an owned ephemeral loopback port, release only to the test server.
    thread->BlockingCall([&]{std::unique_ptr<webrtc::Socket> socket(thread->socketserver()->Create(AF_INET,SOCK_DGRAM));require(socket!=nullptr);
        require(socket->Bind(webrtc::SocketAddress("127.0.0.1",0))==0);port=socket->GetLocalAddress().port();socket->Close();
        server=std::make_unique<webrtc::TestTurnServer>(environment,thread.get(),thread->socketserver(),webrtc::SocketAddress("127.0.0.1",port),webrtc::SocketAddress("127.0.0.1",0));});
    struct Cleanup{std::unique_ptr<webrtc::Thread>& thread;std::unique_ptr<webrtc::TestTurnServer>& server;std::unique_ptr<webrtc::TestTurnServer>& tls;~Cleanup(){thread->BlockingCall([&]{tls.reset();server.reset();});thread->Stop();}} cleanup{thread,server,tls_server};
    // Same production socket wrapper: an alternate loopback port is blocked
    // before OS send, with an owned trap socket receiving no packet.
    bool alive=true;auto socket_guard=std::make_shared<remote::NetworkGuard>(std::vector<webrtc::IPAddress>{},[&]{return alive;});
    socket_guard->relay(remote::parse_relay(policy(port)));
    thread->BlockingCall([&]{remote::GuardedSocketFactory factory(thread->socketserver(),socket_guard);auto socket=factory.Create(AF_INET,SOCK_DGRAM);
        auto trap=thread->socketserver()->Create(AF_INET,SOCK_DGRAM);require(socket && trap && trap->Bind(webrtc::SocketAddress("127.0.0.1",0))==0);
        require(socket->Bind(webrtc::SocketAddress("127.0.0.1",0))==0);const char byte=0;
        require(socket->SendTo(&byte,1,trap->GetLocalAddress())==SOCKET_ERROR && socket->GetError()==WSAEACCES);
        char received=0;webrtc::SocketAddress from;std::int64_t stamp=0;require(trap->RecvFrom(&received,1,&from,&stamp)==SOCKET_ERROR);
        require(socket->SendTo(&byte,1,webrtc::SocketAddress("127.0.0.1",port))==1);
        alive=false;require(socket->SendTo(&byte,1,webrtc::SocketAddress("127.0.0.1",port))==SOCKET_ERROR);});
    require(socket_guard->blocked>=2);
    bool lease_live=true;webrtc::IPAddress approved_ip;require(webrtc::IPFromString("127.0.0.1",&approved_ip));
    auto direct_guard=std::make_shared<remote::NetworkGuard>(std::vector<webrtc::IPAddress>{approved_ip},[&]{return lease_live;});
    thread->BlockingCall([&]{remote::GuardedSocketFactory factory(thread->socketserver(),direct_guard);
        auto socket=factory.Create(AF_INET,SOCK_DGRAM),tcp=factory.Create(AF_INET,SOCK_STREAM);
        auto accepted=thread->socketserver()->Create(AF_INET,SOCK_DGRAM),other=thread->socketserver()->Create(AF_INET,SOCK_DGRAM);
        require(socket && tcp && accepted && other && socket->Bind(webrtc::SocketAddress("127.0.0.1",0))==0);
        require(accepted->Bind(webrtc::SocketAddress("127.0.0.1",0))==0 && other->Bind(webrtc::SocketAddress("127.0.0.2",0))==0);
        const char byte=41;require(socket->SendTo(&byte,1,accepted->GetLocalAddress())==1);
        require(socket->SendTo(&byte,1,other->GetLocalAddress())==SOCKET_ERROR && socket->GetError()==WSAEACCES);
        require(tcp->Connect(accepted->GetLocalAddress())==SOCKET_ERROR && tcp->GetError()==WSAEACCES);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));char received=0;webrtc::SocketAddress from;std::int64_t stamp=0;
        require(accepted->RecvFrom(&received,1,&from,&stamp)==1 && received==byte);require(other->RecvFrom(&received,1,&from,&stamp)==SOCKET_ERROR);
        lease_live=false;require(socket->SendTo(&byte,1,accepted->GetLocalAddress())==SOCKET_ERROR && socket->GetError()==WSAEACCES);
        require(accepted->RecvFrom(&received,1,&from,&stamp)==SOCKET_ERROR);
    });require(direct_guard->blocked>=3);
    stage=1;auto bytes=policy(port);auto decoded=remote::parse_relay(bytes);remote::require_relay(decoded,GetTickCount64(),GetTickCount64()+30000,true);
    bool denied=false;try{remote::require_relay(decoded,GetTickCount64(),GetTickCount64()+30000,false);}catch(...){denied=true;}require(denied);
    auto bad=bytes;bad.at(92)=1;denied=false;try{remote::parse_relay(bad);}catch(...){denied=true;}require(denied);
    std::atomic<unsigned> frames{0},cursors{0};remote::MediaPeer receiver(options(false),[](auto,bool){},[&](auto){++frames;return true;},[&](auto){++cursors;return true;});
    remote::MediaPeer sender(options(true),[](auto,bool){},[](auto){return false;});require(receiver.relay(bytes) && sender.relay(bytes));
    auto renew=[&]{require(receiver.grant(GetTickCount64()+3000) && sender.grant(GetTickCount64()+3000));};renew();
    stage=2;require(receiver.make_offer());auto offer=receiver.take_signal();require(offer && offer->offer && offer->sdp.find(" typ relay")!=std::string::npos && offer->sdp.find(" typ host")==std::string::npos);renew();
    stage=3;require(sender.signal(*offer));auto answer=sender.take_signal();require(answer && !answer->offer && answer->sdp.find(" typ relay")!=std::string::npos);renew();require(receiver.signal(*answer));
    stage=4;std::uint64_t sequence=0,last=0;const auto until=GetTickCount64()+8000;
    while(GetTickCount64()<until && frames<3){renew();receiver.pump();sender.pump();if(sender.connected() && GetTickCount64()-last>=70){last=GetTickCount64();
        remote::SharedFrame frame{{options(true).session,2,++sequence,last,0,320,180},{320,180,std::vector<std::uint8_t>(320*180*4,71)}};require(sender.frame(frame));}
        std::this_thread::sleep_for(std::chrono::milliseconds(5));}require(frames>=3 && sender.connected() && receiver.connected());
    remote::CursorUpdate cursor;cursor.session=options(true).session;cursor.transport=8;cursor.generation=2;cursor.sequence=1;cursor.source_width=320;cursor.source_height=180;
    for(unsigned i=0;i<100 && !cursors;++i){renew();sender.cursor(cursor);std::this_thread::sleep_for(std::chrono::milliseconds(5));}require(cursors>0);
    receiver.release_all();bool released=false;for(unsigned i=0;i<100 && !released;++i){renew();auto m=sender.take_control();released=m && m->header.kind==remote::ipc::Kind::release_all;std::this_thread::sleep_for(std::chrono::milliseconds(5));}require(released);
    stage=5;remote::MediaPeer rejected(options(true),[](auto,bool){},[](auto){return false;});require(rejected.relay(bytes));require(rejected.grant(GetTickCount64()+3000));
    auto forged=*offer;const auto at=forged.sdp.find(" 127.0.0.1 ");require(at!=std::string::npos);forged.sdp.replace(at,11," 127.0.0.2 ");require(!rejected.signal(forged) && rejected.ended());
    stage=6;remote::MediaPeer wrong_port(options(true),[](auto,bool){},[](auto){return false;});auto limited=policy(port);put(limited,90,1,2);
    require(wrong_port.relay(limited) && wrong_port.grant(GetTickCount64()+3000));require(!wrong_port.signal(*offer) && wrong_port.ended());
    require(!receiver.relay(bytes) && receiver.ended());sender.request_stop();require(receiver.ended() && sender.ended());receiver.pump();sender.pump();
    stage=7;remote::MediaPeer expired(options(true),[](auto,bool){},[](auto){return false;});auto ending=policy(port);put(ending,48,GetTickCount64()+150,8);
    require(expired.relay(ending) && expired.grant(GetTickCount64()+2000));std::this_thread::sleep_for(std::chrono::milliseconds(170));expired.pump();require(expired.ended());
    stage=8;remote::MediaPeer wrong_password(options(false),[](auto,bool){},[](auto){return false;});require(wrong_password.relay(policy(port,false,"incorrect-relay-password")));
    require(wrong_password.grant(GetTickCount64()+5000));wrong_password.make_offer();auto no_offer=wrong_password.take_signal();
    require(!no_offer || no_offer->sdp.find(" typ relay")==std::string::npos);require(!wrong_password.connected());wrong_password.request_stop();wrong_password.pump();
    remote::MediaPeer stopped(options(false),[](auto,bool){},[](auto){return false;});stopped.request_stop();require(!stopped.make_offer() && !stopped.relay(policy(port)));
    stage=9;unsigned tls_port=0;thread->BlockingCall([&]{std::unique_ptr<webrtc::Socket> socket(thread->socketserver()->Create(AF_INET,SOCK_STREAM));require(socket!=nullptr);
        require(socket->Bind(webrtc::SocketAddress("127.0.0.1",0))==0);tls_port=socket->GetLocalAddress().port();socket->Close();
        // ignore_bad_cert is SERVER-side only: clients have no certificate. The
        // product client keeps secure TLS validation and cannot set this flag.
        tls_server=std::make_unique<webrtc::TestTurnServer>(environment,thread.get(),thread->socketserver(),webrtc::SocketAddress("127.0.0.1",tls_port),webrtc::SocketAddress("127.0.0.1",0),webrtc::PROTO_TLS,true,"owned.guarddesk.invalid");});
    remote::MediaPeer certificate(options(false),[](auto,bool){},[](auto){return false;});require(certificate.relay(policy(tls_port,true)) && certificate.grant(GetTickCount64()+5000));
    certificate.make_offer();auto untrusted=certificate.take_signal();require(!untrusted || untrusted->sdp.find(" typ relay")==std::string::npos);require(!certificate.connected());certificate.request_stop();certificate.pump();
    std::cout<<"{\"passed\":true,\"owned_loopback_TURN_UDP_only\":true,\"forced_relay_SDP\":true,\"socket_alternate_destination_blocked\":true,\"direct_allowed_peer_received\":true,\"direct_other_loopback_IP_no_packet\":true,\"direct_TCP_connect_refused\":true,\"lease_socket_send_refused\":true,\"denied_socket_received_no_packet\":true,\"stop_socket_send_refused\":true,\"SRTP_decoded_frames\":"<<frames<<",\"cursor_received\":"<<cursors
        <<",\"control_release_all\":true,\"wrong_relay_IP_refused\":true,\"owned_mode_production_refused\":true,\"schema_reserved_refused\":true,\"wrong_allocation_port_refused\":true,\"reconfigure_refused\":true,\"stop_before_offer_refused\":true,\"relay_expiry_terminal\":true,\"wrong_password_no_relay_candidate\":true,\"self_signed_TLS_fixture_no_relay_candidate\":true,\"company_TLS_tested\":false,\"desktop_capture\":false,\"OS_input\":false}\n";
}
}
int main(){try{test();return 0;}catch(...){std::cerr<<"owned_relay_failed_stage_"<<stage<<"\n";return 1;}}
