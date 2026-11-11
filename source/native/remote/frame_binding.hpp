#pragma once
#include "frame_pool.hpp"
#include <optional>

namespace remote {
struct VideoBinding{FrameTicket frame;std::uint64_t transport=0;std::uint32_t rtp_timestamp=0;};
std::vector<std::uint8_t> encode_video_binding(const VideoBinding& binding);
VideoBinding decode_video_binding(const std::vector<std::uint8_t>& packet);
// Scalar correlation only: at most 64 entries. RTP timestamps are not used as
// desktop epochs. ACKs retain the original capture sequence and generation.
class FrameBindings {
    struct Item{VideoBinding binding{};std::uint64_t received=0;};
    ipc::Session session_;
    std::uint64_t transport_,generation_=0,last_sequence_=0;
    std::array<Item,64> values_{};
    mutable std::mutex mutex_;
public:
    FrameBindings(ipc::Session session,std::uint64_t transport);
    bool record(const VideoBinding& binding,std::uint64_t received);
    std::optional<VideoBinding> find(std::uint32_t rtp_timestamp,std::uint64_t now) const;
    void clear();
};
}
