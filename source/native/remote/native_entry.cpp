// Private broker-launched product worker. Never runs from an employee-writable
// extraction folder. There is no arbitrary executable/config/path argument.
#include "desktop_worker.hpp"
#include "pointer_flow.hpp"
#include "cohort.hpp"
#include "ipc_channel.hpp"
#include "launch_capsule.hpp"
#include <sddl.h>
#include <deque>
#include <thread>
#include <atomic>
#include <iostream>
#include <limits>
#include <algorithm>
#include <cstring>

namespace {
using namespace remote;
void require(bool okay,const char* reason){if(!okay)throw std::runtime_error(reason);}
struct Handle{HANDLE value=nullptr;~Handle(){if(value && value!=INVALID_HANDLE_VALUE)CloseHandle(value);}};
ipc::Session session(const wchar_t* text){
    std::wstring input(text);require(input.size()==32,"worker_session");ipc::Session value{};
    auto nibble=[](wchar_t c){if(c>=L'0' && c<=L'9')return c-L'0';if(c>=L'a' && c<=L'f')return c-L'a'+10;throw std::runtime_error("worker_hex");};
    for(unsigned i=0;i<value.size();++i)value.at(i)=static_cast<std::uint8_t>((nibble(input.at(i*2))<<4)|nibble(input.at(i*2+1)));return value;
}
int run(int argc,wchar_t** argv){
    require(argc==3 && std::wstring(argv[1])==L"--broker-worker","worker_private_entry_required");
    require(SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)!=nullptr,"worker_physical_DPI_context");
    const auto nonce=std::wstring(argv[2]);session(nonce.c_str());
    Handle bootstrap{OpenFileMappingW(FILE_MAP_READ|READ_CONTROL,FALSE,(L"Global\\GuardDesk-Remote-Launch-"+nonce).c_str())};
    require(bootstrap.value && ipc::pipe_owner(bootstrap.value)==L"S-1-5-18","worker_bootstrap_owner");
    const void* view=MapViewOfFile(bootstrap.value,FILE_MAP_READ,0,0,sizeof(LaunchCapsule));require(view!=nullptr,"worker_bootstrap_view");
    LaunchCapsule capsule{};std::memcpy(&capsule,view,sizeof(capsule));UnmapViewOfFile(view);validate_launch_capsule(capsule,GetTickCount64());
    require(capsule.role==1,"worker_capsule_role");const auto& spec=capsule.spec;
    LogonBinding binding{spec.wts_session,spec.authentication,spec.logon_time,spec.consent_filetime,spec.user_sid,spec.administrator==1};
    PSID sid=nullptr;require(ConvertStringSidToSidW(binding.sid.c_str(),&sid)!=FALSE,"worker_user_sid");LocalFree(sid);
    const auto deadline=spec.consent_tick_deadline,transport=spec.transport;ipc::Session id{};std::copy_n(spec.session,id.size(),id.begin());
    const auto paths=installed_cohort();ipc::Peer self(GetCurrentProcessId());
    auto parent=std::make_unique<ipc::Peer>(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(capsule.parent_process)),reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(capsule.parent_query_token)));
    require_fixed_peer(*parent,paths.broker,L"S-1-5-18",0);require(parent->identity().pid==capsule.parent_pid && parent->identity().created==capsule.parent_created,"worker_parent_reused");
    require_fixed_peer(self,paths.worker,binding.administrator_assistance?L"S-1-5-18":binding.sid,spec.wts_session);
    Handle image{pin_program_image(paths.worker)},broker_image{pin_program_image(paths.broker)};
    Handle stop{reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(capsule.stop))};
    require(stop.value && ipc::pipe_owner(stop.value)==L"S-1-5-18","worker_stop_identity");
    Handle cancel{CreateEventW(nullptr,TRUE,FALSE,nullptr)};require(cancel.value!=nullptr,"worker_cancel");
    const auto parent_identity=parent->identity();const auto parent_wait=parent->wait_handle();
    auto channel=ipc::Channel::open(nonce,parent_identity,L"S-1-5-18",cancel.value,5000,std::move(parent));
    std::array<HANDLE,2> mapping{reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(capsule.frames.at(0))),reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(capsule.frames.at(1)))};
    auto pool=std::make_unique<FramePool>(id,1920,1080,mapping);
    DesktopWorker worker(binding,id,transport,deadline,std::move(pool));
    ipc::Message hello{{ipc::Kind::hello,16,id,0,1,0,transport},std::vector<std::uint8_t>(16)};
    hello.payload.at(8)=2;hello.payload.at(14)=1; // wire2 / 65536; features withheld until cohort acceptance.
    channel->write(ipc::encode_control(hello,ipc::Direction::worker_to_broker),1000);
    Handle command_wake{CreateEventW(nullptr,FALSE,FALSE,nullptr)},io_wake{CreateEventW(nullptr,FALSE,FALSE,nullptr)};
    require(command_wake.value && io_wake.value,"worker_wake_events");
    std::mutex mutex;WorkerCommandQueue commands;std::optional<ipc::Message> pending_status;std::atomic<bool> failed=false;
    std::thread reader([&]{
        try{while(WaitForSingleObject(cancel.value,0)==WAIT_TIMEOUT){
            // Channel deliberately has a single I/O owner. Capture publishes
            // only a latest scalar snapshot; it must not write concurrently
            // with this thread's command read/available checks.
            std::optional<ipc::Message> status;
            {std::lock_guard<std::mutex> lock(mutex);status.swap(pending_status);}
            if(status)channel->write(ipc::encode_control(*status,ipc::Direction::worker_to_broker),100);
            if(!channel->available()){channel->wait_readable(20,io_wake.value);continue;}
            auto message=channel->read(100);std::lock_guard<std::mutex> lock(mutex);
            require(commands.push(std::move(message),GetTickCount64()),"worker_control_backlog_or_sequence");
            SetEvent(command_wake.value);
        }}catch(...){failed=true;SetEvent(cancel.value);}
    });
    bool passed=true;
    try{
        auto next_capture=GetTickCount64(),next_status=next_capture+1000;std::uint64_t status_sequence=1;
        while(!worker.ended() && GetTickCount64()<deadline && WaitForSingleObject(stop.value,0)==WAIT_TIMEOUT && WaitForSingleObject(parent_wait,0)==WAIT_TIMEOUT && !failed){
            // Bound command work between captures. Leave remaining entries in
            // the shared queue so a new pure position can replace its tail.
            for(unsigned budget=0;budget<4;++budget){
                std::optional<QueuedCommand> queued;std::uint32_t combined=0,high_water=0;
                {std::lock_guard<std::mutex> lock(mutex);queued=commands.pop();combined=commands.coalesced;high_water=commands.high_water;}
                if(!queued)break;auto& pending=*queued;
                const auto age=GetTickCount64()-pending.arrived;
                worker.queue_observation(combined,high_water,age,pending.message.header.kind==ipc::Kind::input && age>100);
                // A delayed click/ACK must not replay after a capture stall.
                // Release tracked keys instead; absolute leases and terminal
                // cleanup retain their own deadlines and remain processable.
                if(age>100 && (pending.message.header.kind==ipc::Kind::input || pending.message.header.kind==ipc::Kind::presented)){
                    pending.message.header.kind=ipc::Kind::release_all;pending.message.header.payload_bytes=0;
                    pending.message.header.desktop_generation=pending.message.header.frame_sequence=0;pending.message.payload.clear();
                }
                if(pending.message.header.kind==ipc::Kind::lease && !spec.can_control && pending.message.payload.at(16))throw std::runtime_error("worker_mode_broadened");
                worker.command(pending.message);if(worker.ended())break;
            }
            const auto now=GetTickCount64();if(now>=next_capture || WaitForSingleObject(worker.capture_event(),0)==WAIT_OBJECT_0){
                worker.poll();if(now>=next_capture)next_capture=now+33;
            }
            if(GetTickCount64()>=next_status){
                const auto payload=worker.status().encode();
                ipc::Message status{{ipc::Kind::stats,static_cast<std::uint32_t>(payload.size()),id,0,++status_sequence,0,transport},{payload.begin(),payload.end()}};
                {std::lock_guard<std::mutex> lock(mutex);pending_status=std::move(status);}
                SetEvent(io_wake.value);
                next_status=GetTickCount64()+1000;
            }
            HANDLE waits[]{cancel.value,command_wake.value,worker.capture_event(),stop.value,parent_wait};
            {std::lock_guard<std::mutex> lock(mutex);if(!commands.empty())SetEvent(command_wake.value);}
            const auto tick=GetTickCount64();const auto wait=next_capture>tick?std::min<std::uint64_t>(next_capture-tick,33):0;
            WaitForMultipleObjects(5,waits,FALSE,static_cast<DWORD>(wait));
        }
    }catch(...){passed=false;}
    SetEvent(cancel.value);reader.join();worker.close();return passed?0:1;
}
}
int wmain(int argc,wchar_t** argv){
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    try{return run(argc,argv);}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
