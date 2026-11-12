#pragma once
#include "frame_bridge.hpp"
#include "ipc_wire.hpp"
#include "relay_policy.hpp"
#include "latency.hpp"
#include "input_diagnostics.hpp"
#include <string>

namespace remote {
struct MediaPeerOptions {
    ipc::Session session{};
    std::uint64_t transport=0,consent_deadline=0;
    bool endpoint=false,can_control=false,owned_loopback=false;
    // Explicit interface/peer addresses from the authenticated control plane.
    // No wildcard binding, public STUN, discovery listener or arbitrary URL.
    std::vector<std::string> local_ipv4,peer_ipv4;
    std::function<void()> activity; // local event notification; no authority
};
struct MediaSignal{bool offer=false;std::string sdp;};
enum class MediaEndReason:std::uint32_t {none=0,local_stop=1,authority_expired=2,connection_closed=3,protocol_rejected=4,send_failed=5,callback_failed=6,cleanup_timeout=7};
struct MediaPeerStats {std::uint64_t encoded=0,decoded=0,codec_failures=0,unknown_timestamps=0;bool channel_open=false,peer_connected=false;std::uint64_t cursor_sent=0,cursor_received=0,cursor_dropped=0,cursor_unsupported=0;
    std::uint32_t codec_rebuilds=0,hardware_frames=0,hardware_fallbacks=0,hardware_candidates=0,bitrate_updates=0,bitrate_failures=0,target_bitrate=0;
    std::array<std::uint32_t,10> encode_latency{};
};
// Low-privilege product transport. The endpoint worker/SYSTEM process never
// links this library. Caller owns one app thread for SDP/frame/pump/close;
// grant and request_stop are immediate, thread-safe authority fences.
class MediaPeer {
    class Impl;
    std::unique_ptr<Impl> impl_;
public:
    MediaPeer(MediaPeerOptions options,std::function<void(std::uint64_t,bool)> state,
        std::function<bool(SharedFrame)> submit,std::function<bool(CursorUpdate)> cursor={});
    ~MediaPeer();
    bool relay(const std::vector<std::uint8_t>& policy); // Before first SDP, once.
    bool make_offer();
    bool signal(const MediaSignal& signal);
    std::optional<MediaSignal> take_signal();
    bool grant(std::uint64_t absolute_tick_deadline);
    bool frame(const SharedFrame& frame);
    bool cursor(const CursorUpdate& cursor);
    bool presented(const FrameTicket& frame);
    bool input(const std::vector<std::uint8_t>& fixed_input_payload);
    void release_all();
    bool release_up(unsigned type,unsigned code);
    void pause_source(std::uint64_t generation);
    std::optional<ipc::Message> take_control(); // No lease/setup/consumed from network.
    void pump();
    void request_stop(MediaEndReason reason=MediaEndReason::local_stop);
    bool connected() const;
    bool ended() const;
    MediaEndReason end_reason() const;
    std::array<std::uint32_t,20> send_diagnostics() const;
    std::array<std::uint32_t,64> input_diagnostics() const;
    MediaPeerStats stats() const;
};
}
