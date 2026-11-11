#pragma once
#include "ipc_peer.hpp"
#include <string>
namespace remote {
struct CohortPaths{std::wstring root,broker,worker,media,bridge;};
CohortPaths installed_cohort();
HANDLE pin_program_image(const std::wstring& path);
void require_fixed_peer(const ipc::Peer& peer,const std::wstring& image,const std::wstring& sid,DWORD session);
}
