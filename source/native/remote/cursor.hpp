#pragma once
#include "ipc_wire.hpp"
#include <cstdint>
#include <vector>
namespace remote {
struct Pixels;
constexpr unsigned cursor_max_side=64;
constexpr std::size_t cursor_max_pixels=cursor_max_side*cursor_max_side*4;
constexpr std::size_t cursor_wire_header=96,cursor_storage_bytes=32+cursor_wire_header+cursor_max_pixels;
enum class CursorMode:std::uint16_t {hidden=0,separate=1,embedded=2,unsupported=3};
struct CursorUpdate {
    CursorUpdate()=default;
    CursorUpdate(const CursorUpdate&)=default;
    CursorUpdate(CursorUpdate&&) noexcept=default;
    CursorUpdate& operator=(CursorUpdate value) noexcept;
    ~CursorUpdate();
    ipc::Session session{};
    std::uint64_t transport=0,generation=0,sequence=0,shape=0;
    unsigned source_width=0,source_height=0,width=0,height=0,hot_x=0,hot_y=0;
    std::int32_t x=0,y=0;
    CursorMode mode=CursorMode::hidden;
    std::vector<std::uint8_t> bgra; // premultiplied BGRA; optional on position-only updates
    // Capture-local XOR flags only. Resolve against the current authorized
    // frame before encoding; raw XOR masks never cross IPC/network boundaries.
    std::vector<std::uint8_t> xor_mask;
};
std::vector<std::uint8_t> encode_cursor(const CursorUpdate& value);
CursorUpdate decode_cursor(const std::vector<std::uint8_t>& value);
// Actual DXGI shape types: 1 monochrome / 2 color / 4 masked color.
bool convert_cursor_shape(CursorUpdate& value,unsigned type,unsigned width,unsigned height,unsigned pitch,
    unsigned hot_x,unsigned hot_y,const std::vector<std::uint8_t>& bytes);
CursorUpdate scale_cursor(CursorUpdate value,unsigned source_width,unsigned source_height,unsigned target_width,unsigned target_height);
CursorUpdate compose_cursor(CursorUpdate value,const Pixels& authorized_background,unsigned source_width,unsigned source_height);
}
