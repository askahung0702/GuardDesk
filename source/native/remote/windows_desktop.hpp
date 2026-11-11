#pragma once
#include "session.hpp"
#include "ipc_peer.hpp"
#include "display_geometry.hpp"
#include <string>

namespace remote {
struct LogonBinding{
    DWORD session=0;
    std::uint64_t authentication=0,logon_time=0,consent_filetime=0;
    std::wstring sid;
    bool administrator_assistance=false;
};
// Called only by the dedicated windowless desktop thread of an authenticated,
// fixed-image worker. It has no center credential or network/SDP parser.
class WindowsDesktop {
    PhysicalPixelScope physical_pixels_;
    LogonBinding logon_;
    HDESK original_=nullptr,attached_=nullptr;
    std::wstring name_;
    std::unique_ptr<ipc::Peer> prompt_;
    HANDLE consent_image_=INVALID_HANDLE_VALUE;
    bool same_logon();
    bool actual_uac();
public:
    explicit WindowsDesktop(LogonBinding logon);
    ~WindowsDesktop();
    DesktopObservation select();
    bool input_guard(const DesktopObservation& expected);
    bool logon_alive(){return same_logon();}
};
}
