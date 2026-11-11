#pragma once
#include "broker_api.hpp"
#include <array>

namespace remote {
// Anonymous handles are duplicated into one suspended child before Resume.
// The named bootstrap section is SYSTEM-owned and grants only READ/READ_CONTROL
// to the target user. No user-writable file, inherited handle set or token with
// impersonate/duplicate/assign privileges enters the child.
struct LaunchCapsule {
    std::uint32_t bytes=0,format=1;
    GD_REMOTE_START spec{};
    std::uint64_t parent_process=0,parent_query_token=0,parent_created=0,stop=0;
    std::array<std::uint64_t,2> frames{};
    std::uint32_t parent_pid=0,role=1; // 1 protected capture/input; 2 restricted media
};
static_assert(sizeof(LaunchCapsule)<=2048);
void validate_launch_capsule(const LaunchCapsule& value,std::uint64_t now);
}
