#pragma once
#include "ipc_wire.hpp"

namespace remote::ipc {
constexpr std::size_t media_header_bytes=64,media_max_payload=65536;
constexpr std::size_t media_stats_bytes=96;
constexpr std::uint32_t media_stats_version=2;
enum class MediaDirection{broker_to_media,media_to_broker};
enum class MediaKind:std::uint16_t{grant=1,signal=2,network_control=3,consumed=4,stop=5,stats=6,configuration=7,relay_configuration=8};
struct MediaMessage{
    MediaKind kind{};Session session{};std::uint64_t transport=0,sequence=0;
    std::vector<std::uint8_t> payload;
};
struct MediaHeader{MediaMessage message;std::uint32_t payload_bytes=0;};
// Startup and periodic snapshots share the exact schema. The version and
// reserved trailing word are owned here, never supplied as counters.
std::vector<std::uint8_t> media_stats_payload(const std::array<std::uint32_t,22>& counters={});
MediaHeader media_header(const std::array<std::uint8_t,media_header_bytes>& bytes,MediaDirection direction);
MediaMessage media_message(const std::vector<std::uint8_t>& bytes,MediaDirection direction);
std::vector<std::uint8_t> encode_media(const MediaMessage& message,MediaDirection direction);
}
