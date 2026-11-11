#pragma once
#include <array>
#include <cstdint>
#include <vector>
#include <algorithm>

namespace remote::ipc {
// Consent lifetime only. Five-second renewable leases remain mandatory.
constexpr std::uint64_t no_session_deadline=0x7fffffffffffffffULL;
inline bool valid_consent(std::uint64_t deadline,std::uint64_t now){
    return deadline==no_session_deadline || (deadline>now && deadline-now<=600000);
}
// Unshipped native control wire 2, independent of the HTTP preview's wire 6.
// Transport must validate this fixed header before allocating/reading a body.
// No paths, shell text, credentials, screen bytes or caller-selected handles.
constexpr std::size_t control_header_bytes=64,control_max_payload=65536;
constexpr unsigned control_commands_per_second=240;
using Session=std::array<std::uint8_t,16>;
enum class Kind:std::uint16_t{hello=1,capabilities,lease,desktop_state,input,release_all,stop,stats,presented,frame_setup,consumed};
enum class Direction{broker_to_worker,worker_to_broker};
// release_all: empty body = focus cleanup + invalidate input ACK. Eight-byte
// body = tracked UP only: type(1 key/2 mouse), zero, u16 code, four zeros.
// Requires the exact desktop generation/logon and never moves, presses, renews
// authorization or refreshes ACK. Exact cohort matching excludes older peers.
struct Header{
    Kind kind;
    std::uint32_t payload_bytes;
    Session session;
    std::uint64_t desktop_generation,sequence,frame_sequence,transport_generation;
};
struct Message{Header header;std::vector<std::uint8_t> payload;};
Header control_header(const std::array<std::uint8_t,control_header_bytes>& bytes,Direction direction);
Message control_message(const std::vector<std::uint8_t>& bytes,Direction direction);
std::vector<std::uint8_t> encode_control(const Message& message,Direction direction);

// Pure policy only. The caller must first authenticate the broker connection,
// retain/check WTS/logon/parent/cancel and run the real desktop/input guard.
// Deadlines use the same boot-relative millisecond clock in broker and worker;
// never accept a duration anchored at a delayed IPC response's arrival.
class ControlGate{
    struct Frame{std::uint64_t sequence=0,tick=0;};
    Session session_;
    std::uint64_t transport_,consent_deadline_,lease_deadline_=0,authorization_=0,last_command_=0;
    std::uint64_t generation_=0,last_frame_=0,ack_frame_=0,ack_tick_=0;
    unsigned width_=0,height_=0;
    bool active_=false,control_=false,stopped_=false;
    std::uint64_t rate_started_=0;
    unsigned rate_count_=0;
    bool rate_initialized_=false;
    unsigned refusal_=0;
    std::array<Frame,64> frames_{}; // metadata only, never pixel slots
public:
    ControlGate(Session session,std::uint64_t transport,std::uint64_t now,std::uint64_t consent_deadline);
    bool set_desktop(std::uint64_t generation,unsigned width,unsigned height);
    void pause();
    void invalidate_input_ack();
    void revoke();
    bool frame(std::uint64_t sequence,std::uint64_t now);
    bool accept_broker(const Message& message,std::uint64_t now);
    bool authorized(std::uint64_t now) const;
    std::uint64_t deadline()const{return (std::min)(consent_deadline_,lease_deadline_);}
    unsigned refusal()const{return refusal_;} // scalar explanation, never authority
};
}
