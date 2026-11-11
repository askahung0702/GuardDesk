#pragma once
#include "capture.hpp"
#include "cursor.hpp"
#include <optional>
#include "ipc_wire.hpp"
#include <array>
#include <mutex>
#include <stdexcept>

namespace remote {
struct FrameTicket{
    ipc::Session session{};
    std::uint64_t generation=0,sequence=0,tick=0;
    unsigned slot=0,width=0,height=0;
};
struct SharedFrame{FrameTicket ticket;Pixels pixels;};
// An expected latest-slot race/empty/stale sample during pause/reuse. Callers
// discard it and retry their bounded poll; schema/session errors stay fatal.
class FrameRetry:public std::runtime_error{public:FrameRetry():std::runtime_error("frame_retry_latest"){} };
// Two anonymous, page-file-backed mappings. Only the capture process has write
// handles. The authenticated launch owner duplicates READ handles exclusively
// into its retained media process. No name/path, pixels on disk or public cache.
class FramePool {
    struct Slot{HANDLE mapping=nullptr;void* view=nullptr;FrameTicket ticket{};bool busy=false;};
    std::array<Slot,2> slots_{};
    ipc::Session session_;
    std::size_t capacity_;
    std::uint64_t last_sequence_=0,cursor_revision_=0;
    std::mutex mutex_;
public:
    FramePool(ipc::Session session,unsigned maximum_width,unsigned maximum_height);
    // Owns handles duplicated by the authenticated broker into this worker.
    FramePool(ipc::Session session,unsigned maximum_width,unsigned maximum_height,std::array<HANDLE,2> writable);
    ~FramePool();
    FramePool(const FramePool&)=delete;
    FramePool& operator=(const FramePool&)=delete;
    bool publish(const Pixels& pixels,std::uint64_t generation,std::uint64_t sequence,std::uint64_t tick,FrameTicket& result);
    bool release(const FrameTicket& ticket);
    bool release_sequence(std::uint64_t generation,std::uint64_t sequence);
    void clear();
    // Target is a retained, already authenticated process handle with DUP_HANDLE.
    HANDLE duplicate_read(unsigned slot,HANDLE target) const;
    HANDLE duplicate_write(unsigned slot,HANDLE target) const;
    static std::size_t shared_mapping_bytes(unsigned width,unsigned height);
    std::size_t mapping_bytes() const{return capacity_+128+cursor_storage_bytes;}
    bool publish_cursor(const CursorUpdate& cursor,std::uint64_t tick);
};
// Reads exactly the requested bounded mapping, validates trusted frame metadata,
// copies only tight BGRA rows, then checks that clear/reuse did not race the copy.
SharedFrame read_shared_frame(HANDLE read_mapping,std::size_t mapping_bytes,
    const ipc::Session& session,std::uint64_t minimum_generation,std::uint64_t now);
std::optional<CursorUpdate> read_shared_cursor(HANDLE mapping,std::size_t mapping_bytes,const ipc::Session& session,std::uint64_t transport,std::uint64_t generation,std::uint64_t now);
// Scalar-only sample. sequence==0/generation>0 means consumed/free; both zero
// means the worker explicitly cleared capture authority. Never acknowledges it.
FrameTicket peek_shared_frame(HANDLE read_mapping,std::size_t mapping_bytes,const ipc::Session& session);
}
