#pragma once
#include "relay_policy.hpp"
#include "rtc_base/async_socket.h"
#include "rtc_base/socket_factory.h"
#include "rtc_base/ip_address.h"
#include <atomic>
#include <functional>
#include <mutex>
#include <optional>
namespace remote {
class NetworkGuard {
    std::mutex mutex_;
    std::vector<webrtc::IPAddress> peers_;
    std::optional<RelayPolicy> relay_;
    std::function<bool()> live_;
public:
    std::atomic<std::uint64_t> blocked{0};
    NetworkGuard(std::vector<webrtc::IPAddress> peers,std::function<bool()> live):peers_(std::move(peers)),live_(std::move(live)){}
    void relay(const RelayPolicy& value);
    bool allows(const webrtc::SocketAddress& address,int type);
};
class GuardedSocketFactory final:public webrtc::SocketFactory {
    webrtc::SocketFactory* source_;
    std::shared_ptr<NetworkGuard> guard_;
public:
    GuardedSocketFactory(webrtc::SocketFactory* source,std::shared_ptr<NetworkGuard> guard):source_(source),guard_(std::move(guard)){}
    webrtc::Socket* CreateSocket(int family,int type) override;
};
}
