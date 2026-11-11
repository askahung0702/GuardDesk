#pragma once
#include "ipc_peer.hpp"
#include "ipc_wire.hpp"
#include "media_wire.hpp"
#include <memory>
#include <mutex>

namespace remote::ipc {
// Local-only, one non-reusable instance. No public network name/path argument.
// Each channel has one caller, no queue and at most one in-flight operation.
// The caller owns the cancel event lifetime; the channel duplicates sync-only.
class Channel{
#ifdef GUARDDESK_OWNED_CHANNEL_FIXTURES
    friend struct OwnedChannelFixture;
#endif
    HANDLE pipe_=INVALID_HANDLE_VALUE,cancel_=nullptr;
    bool server_=false,poisoned_=false;
    std::unique_ptr<Peer> peer_;
    std::mutex operation_;
    std::vector<std::uint8_t> prefetched_;
    Channel(HANDLE pipe,HANDLE cancel,bool server);
    void guard() const;
    DWORD transfer(bool write,void* bytes,DWORD count,std::uint64_t deadline);
    void exact(bool write,void* bytes,std::size_t count,std::uint64_t deadline);
    void fail();
public:
    ~Channel();
    Channel(const Channel&)=delete;
    Channel& operator=(const Channel&)=delete;
    // nonce is exactly 32 lowercase hexadecimal characters. The server owner
    // is the current process SID; permitted SID is trusted launch policy.
    static std::unique_ptr<Channel> listen(const std::wstring& nonce,const std::wstring& permitted_sid,HANDLE cancel,bool low_integrity=false);
    static std::unique_ptr<Channel> open(const std::wstring& nonce,const Identity& server,const std::wstring& owner,HANDLE cancel,DWORD timeout,std::unique_ptr<Peer> launch_peer=nullptr);
    void accept(const Identity& expected,const std::wstring& owner,DWORD timeout);
    Message read(DWORD timeout);
    void write(const std::vector<std::uint8_t>& packet,DWORD timeout);
    MediaMessage read_media(DWORD timeout);
    void write_media(const std::vector<std::uint8_t>& packet,DWORD timeout);
    bool available();
    // Single I/O owner: wait for one byte or a local mailbox wake. A timeout
    // cancels/drains only this readiness read; it never poisons an idle pipe.
    bool wait_readable(DWORD timeout,HANDLE wake);
    HANDLE native_handle() const{return pipe_;} // borrowed, internal/test use
    static unsigned quarantined_operations();
};
#ifdef GUARDDESK_OWNED_CHANNEL_FIXTURES
// Separate owned-process fault injection, never part of a product target.
unsigned owned_quarantine_selftest();
#endif
}
