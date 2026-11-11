#pragma once
#include "ipc_wire.hpp"
#include <windows.h>
#include <array>
#include <functional>
#include <vector>

namespace remote {
// Owned by the desktop thread. The guard must recheck the same WTS logon,
// attached/input desktop, consent and lease immediately before an ordinary
// batch. Cleanup has a separate host guard: tracked ups only, same logon;
// a still-authorized desktop transition can release on the verified new UAC.
class InputLedger {
    std::array<bool,255> keys_{};
    std::array<bool,3> buttons_{};
    std::function<UINT(const std::vector<INPUT>&)> send_;
    bool failed_=false;
public:
    explicit InputLedger(std::function<UINT(const std::vector<INPUT>&)> send);
    bool apply(const ipc::Message& message,const RECT& output,const RECT& virtual_screen,unsigned stream_width=0,unsigned stream_height=0);
    bool release_all(bool same_logon_and_desktop);
    bool release_up(unsigned type,unsigned code,bool same_logon_and_desktop);
    void abandon_logon(); // Never inject into a different user's desktop.
    bool held() const;
    bool failed() const{return failed_;}
};
UINT send_windows_input(const std::vector<INPUT>& batch);
}
