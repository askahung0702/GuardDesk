#include "network_guard.hpp"
#include <windows.h>
#include <algorithm>
#include <stdexcept>
namespace remote {
void NetworkGuard::relay(const RelayPolicy& value){std::lock_guard<std::mutex> lock(mutex_);if(relay_)throw std::invalid_argument("relay_socket_policy_already_set");
    relay_=value;relay_->username.clear();std::fill(relay_->password.begin(),relay_->password.end(),'\0');relay_->password.clear();}
bool NetworkGuard::allows(const webrtc::SocketAddress& address,int type){
    bool allowed=false;
    if(live_() && !address.IsUnresolvedIP() && address.ipaddr().family()==AF_INET && address.port()>0){
        std::lock_guard<std::mutex> lock(mutex_);
        if(relay_){const auto& relay=*relay_;allowed=GetTickCount64()<relay.expires && address.ipaddr().ipv4_address().s_addr==relay.turn_ipv4 &&
            address.port()==static_cast<int>(relay.turn_port) && type==(relay.owned_udp?SOCK_DGRAM:SOCK_STREAM);}
        else allowed=type==SOCK_DGRAM && std::find(peers_.begin(),peers_.end(),address.ipaddr())!=peers_.end();
    }
    if(!allowed)++blocked;return allowed;
}
namespace {
class GuardedSocket final:public webrtc::AsyncSocketAdapter {
    std::shared_ptr<NetworkGuard> guard_;int type_;
    int refuse(){SetError(WSAEACCES);return SOCKET_ERROR;}
public:
    GuardedSocket(webrtc::Socket* socket,std::shared_ptr<NetworkGuard> guard,int type):AsyncSocketAdapter(socket),guard_(std::move(guard)),type_(type){}
    int Connect(const webrtc::SocketAddress& address) override{return guard_->allows(address,type_)?AsyncSocketAdapter::Connect(address):refuse();}
    int Send(const void* bytes,std::size_t count) override{return guard_->allows(GetRemoteAddress(),type_)?AsyncSocketAdapter::Send(bytes,count):refuse();}
    int SendTo(const void* bytes,std::size_t count,const webrtc::SocketAddress& address) override{return guard_->allows(address,type_)?AsyncSocketAdapter::SendTo(bytes,count,address):refuse();}
    int Listen(int) override{return refuse();} // No passive TCP listener, including relay redirects.
};
}
webrtc::Socket* GuardedSocketFactory::CreateSocket(int family,int type){
    if(family!=AF_INET || (type!=SOCK_DGRAM && type!=SOCK_STREAM))return nullptr;
    auto socket=source_->Create(family,type);if(!socket)return nullptr;
    return new GuardedSocket(socket.release(),guard_,type);
}
}
