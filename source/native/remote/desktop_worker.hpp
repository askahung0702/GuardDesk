#pragma once
#include "windows_desktop.hpp"
#include "frame_pool.hpp"
#include <optional>
#include "worker_status.hpp"
#include "async_capture.hpp"

namespace remote {
// Production composition of Windows logon/UAC guard, DXGI capture, short-lease
// state machine, bounded shared frames and OS input. The process entry supplies
// only authenticated broker messages, never network/SDP or long-term tokens.
class DesktopWorker {
    WindowsDesktop desktop_;
    std::unique_ptr<FramePool> frames_;
    std::unique_ptr<CaptureTask> capture_;
    DesktopObservation current_{};
    Pixels latest_pixels_{};
    SessionRuntime runtime_;
    std::uint64_t opened_generation_=0,frame_sequence_=0;
    std::uint64_t refresh_tick_=0,retry_capture_=0;
    std::uint64_t next_request_=0;
    std::optional<CursorUpdate> latest_cursor_;std::uint64_t cursor_refresh_=0;
    ipc::Session session_;std::uint64_t transport_=0,cursor_sequence_=0;
    bool initial_lease_=false,capture_outstanding_=false;
    WorkerStatus status_;
    bool input_guard();
public:
    DesktopWorker(LogonBinding logon,ipc::Session session,std::uint64_t transport,std::uint64_t consent_deadline,std::unique_ptr<FramePool> frames);
    ~DesktopWorker();
    bool command(const ipc::Message& message);
    void queue_observation(std::uint32_t coalesced,std::uint32_t high_water,std::uint64_t age,bool stale_input,unsigned down_type=0,bool stale_presented=false);
    std::optional<FrameTicket> poll();
    void close();
    bool ended() const{return runtime_.ended();}
    FramePool& frames(){return *frames_;}
    WorkerStatus status() const{return status_;}
    HANDLE capture_event()const{return capture_->ready_event();}
};
}
