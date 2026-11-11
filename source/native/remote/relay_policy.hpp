#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>
namespace remote {
struct RelayPolicy {
    std::array<std::uint8_t,32> identity{};
    std::uint64_t expires=0;
    bool owned_udp=false;
    std::uint32_t turn_ipv4=0;
    unsigned turn_port=0,allocation_min=0,allocation_max=0;
    std::vector<std::uint32_t> allocation_ipv4;
    std::string hostname,username,password;
};
// Bounded structural parser; no DNS, sockets, SDP, logs or worker authority.
RelayPolicy parse_relay(const std::vector<std::uint8_t>& bytes);
void require_relay(const RelayPolicy& value,std::uint64_t now,std::uint64_t consent_deadline,bool owned_loopback);
}
