#pragma once
#include <windows.h>
#include <cstdint>
#include <string>

namespace remote::ipc {
// These expectations must come from the broker's retained launch handles and
// fixed protected cohort, never from a connecting peer's message or path.
struct Identity {
    DWORD pid=0,session=0;
    std::uint64_t created=0;
    std::wstring sid,image;
};
class Peer {
    HANDLE handle_=nullptr;
    Identity identity_;
    void snapshot(HANDLE primary_query_token);
public:
    explicit Peer(DWORD pid);
    // Adopts two minimal handles duplicated by the trusted launch owner. The
    // token must be the primary token of that retained process; this binding
    // comes from the protected launch capsule, NEVER an untrusted pipe packet.
    Peer(HANDLE process_query_sync,HANDLE primary_query_token);
    ~Peer();
    Peer(const Peer&)=delete;
    Peer& operator=(const Peer&)=delete;
    Peer(Peer&&) noexcept;
    Peer& operator=(Peer&&) noexcept;
    const Identity& identity() const{return identity_;}
    HANDLE wait_handle() const{return handle_;} // borrowed, retained by this object
    void require_alive() const;
    void require_match(const Identity& expected) const;
};
// Mutual local-pipe primary-process identity primitives. Owner and process SID are
// independent expectations: a standard-user media client cannot own a SYSTEM
// broker pipe. Channel additionally checks effective client identification and
// bounds IO; protected launch policy, SYSTEM integration and same-SID media
// tamper isolation remain caller responsibilities, not proven by this helper.
std::wstring pipe_owner(HANDLE pipe);
Peer authenticate_pipe(HANDLE pipe,bool server_side,const Identity& expected,const std::wstring& expected_owner);
// Call only after a bounded read established the client's pipe context. The
// reader thread must not already impersonate. Revert failure ends this process;
// it must never resume privileged work in the client's identity.
void require_effective_client(HANDLE pipe,const std::wstring& expected_sid);
}
