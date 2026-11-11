#define GUARDDESK_REMOTE_BRIDGE_BUILD
#include "broker_api.hpp"
#include "worker_status.hpp"
#include "cohort.hpp"
#include "kernel_trust.hpp"
#include "media_runtime_defaults.hpp"
#include "frame_pool.hpp"
#include "ipc_channel.hpp"
#include "launch_capsule.hpp"
#include "relay_policy.hpp"
#include <bcrypt.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <algorithm>
#include <atomic>
#include <array>
#include <map>
#include <limits>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <thread>
#include <deque>
#include <aclapi.h>

namespace {
using namespace remote;
thread_local const char* phase="broker_validation";
void win(BOOL okay,const char* operation){if(!okay)throw std::runtime_error(std::string(operation)+"/win32="+std::to_string(GetLastError()));}
void require(bool okay){if(!okay)throw std::runtime_error("native_broker_rejected");}
struct Handle{
    HANDLE value=nullptr;
    ~Handle(){if(value && value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
    Handle()=default;explicit Handle(HANDLE handle):value(handle){}
    Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
};
class Security {
    PSECURITY_DESCRIPTOR value_=nullptr;
public:
    SECURITY_ATTRIBUTES attributes{};
    explicit Security(const std::wstring& reader=L""){
        auto sddl=std::wstring(L"O:SYD:P(A;;GA;;;SY)(A;;RC;;;OW)");if(!reader.empty())sddl+=L"(A;;0x20004;;;"+reader+L")";
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&value_,nullptr)!=FALSE);attributes={sizeof(attributes),value_,FALSE};
    }
    ~Security(){LocalFree(value_);}
};
class Tcb {
    Handle token_;
public:
    Tcb(){
        HANDLE previous=nullptr;
        if(OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&previous)){CloseHandle(previous);throw std::runtime_error("native_broker_impersonating");}
        require(GetLastError()==ERROR_NO_TOKEN && ImpersonateSelf(SecurityImpersonation));
        try{
            require(OpenThreadToken(GetCurrentThread(),TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,TRUE,&token_.value)!=FALSE);
            TOKEN_PRIVILEGES wanted{};wanted.PrivilegeCount=1;require(LookupPrivilegeValueW(nullptr,SE_TCB_NAME,&wanted.Privileges[0].Luid)!=FALSE);
            wanted.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;SetLastError(ERROR_SUCCESS);
            require(AdjustTokenPrivileges(token_.value,FALSE,&wanted,0,nullptr,nullptr) && GetLastError()==ERROR_SUCCESS);
        }catch(...){if(!RevertToSelf())TerminateProcess(GetCurrentProcess(),0xe0000001u);throw;}
    }
    ~Tcb(){if(!RevertToSelf()){TerminateProcess(GetCurrentProcess(),0xe0000001u);for(;;)Sleep(INFINITE);}}
};
std::wstring hexadecimal(const std::uint8_t* bytes,std::size_t size){
    constexpr wchar_t digits[]=L"0123456789abcdef";std::wstring result;
    for(std::size_t i=0;i<size;++i){result.push_back(digits[bytes[i]>>4]);result.push_back(digits[bytes[i]&15]);}return result;
}
void require_broker_trust(){
    phase="broker_image_trust";
    const auto paths=installed_cohort();ipc::Peer self(GetCurrentProcessId());
    require_fixed_peer(self,paths.broker,L"S-1-5-18",0);
    phase="broker_process_trust";
    require_query_only_kernel_trust(GetCurrentProcess(),PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE|READ_CONTROL);
    phase="broker_token_trust";Handle token;
    win(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|READ_CONTROL,&token.value),"broker_token_open");
    require_query_only_kernel_trust(token.value,TOKEN_QUERY|READ_CONTROL);
}
#include "broker_context.hpp"
}
DWORD __stdcall GDRemoteCheckTrust(){
    try{require_broker_trust();return ERROR_SUCCESS;}catch(...){return failed();}
}
DWORD __stdcall GDRemoteReserve(const GD_REMOTE_START* spec,void** result){
    if(!spec || !result)return ERROR_INVALID_PARAMETER;*result=nullptr;
    try{
        auto& r=contexts();
        {std::lock_guard<std::mutex> lock(r.mutex);require(r.entries.size()+r.reservations<4);++r.reservations;}
        std::shared_ptr<Context> context;
        try{context=std::make_shared<Context>(*spec);}catch(...){std::lock_guard<std::mutex> lock(r.mutex);--r.reservations;throw;}
        {std::lock_guard<std::mutex> lock(r.mutex);--r.reservations;require(r.next<std::numeric_limits<std::uintptr_t>::max());
            const auto value=reinterpret_cast<void*>(++r.next);r.entries.emplace(value,std::move(context));*result=value;}
        return ERROR_SUCCESS;
    }catch(...){return failed();}
}
DWORD __stdcall GDRemoteLaunch(void* value){
    try{phase="broker_launch";auto c=find(value);std::unique_lock<std::mutex> lock(c->operation,std::try_to_lock);require(lock.owns_lock());c->launch();return ERROR_SUCCESS;}
    catch(...){try{find(value)->stop_now();}catch(...){}return failed();}
}
DWORD __stdcall GDRemoteCommand(void* value,const std::uint8_t* packet,std::uint32_t count){
    phase="worker_command";
    if(!packet || count<64 || count>64+65536)return ERROR_INVALID_PARAMETER;
    try{
        auto c=find(value);phase="worker_command_lock";std::unique_lock<std::mutex> lock(c->operation,std::try_to_lock);require(lock.owns_lock());
        phase="worker_command_live";c->live();
        std::vector<std::uint8_t> bytes(packet,packet+count);auto m=ipc::control_message(bytes,ipc::Direction::broker_to_worker);
        phase="worker_command_identity_sequence";
        require(m.header.kind!=ipc::Kind::frame_setup && m.header.kind!=ipc::Kind::consumed && m.header.transport_generation==c->spec.transport && m.header.session==c->session() && m.header.sequence>c->sequence);
        phase="worker_command_mode";if(m.header.kind==ipc::Kind::lease)require(c->spec.can_control || m.payload.at(16)==0);
        phase="worker_command_enqueue";c->sequence=m.header.sequence;c->enqueue(false,std::move(bytes));return ERROR_SUCCESS;
    }catch(...){try{find(value)->stop_now();}catch(...){}return failed();}
}
DWORD __stdcall GDRemoteMediaWrite(void* value,const std::uint8_t* packet,std::uint32_t count){
    phase="media_control_write";
    if(!packet || count<64 || count>64+65536)return ERROR_INVALID_PARAMETER;
    try{
        auto c=find(value);std::unique_lock<std::mutex> lock(c->operation,std::try_to_lock);require(lock.owns_lock());c->live();require(c->launched);
        std::vector<std::uint8_t> bytes(packet,packet+count);const auto m=ipc::media_message(bytes,ipc::MediaDirection::broker_to_media);
        require(m.session==c->session() && m.transport==c->spec.transport && m.sequence>c->media_write_sequence);
        if(m.kind==ipc::MediaKind::configuration){require(!c->configured);c->configured=true;c->owned_loopback=m.payload.at(8)==1;}
        else require(c->configured);
        if(m.kind==ipc::MediaKind::relay_configuration){
            require(!c->relay_configured && !c->media_signaled);
            const auto relay=parse_relay(m.payload);require_relay(relay,GetTickCount64(),c->spec.consent_tick_deadline,c->owned_loopback);
            c->relay_configured=true;
        }
        if(m.kind==ipc::MediaKind::signal)c->media_signaled=true;
        if(m.kind==ipc::MediaKind::grant){
            std::uint64_t deadline=0;for(unsigned i=0;i<8;++i)deadline|=std::uint64_t(m.payload.at(i))<<(i*8);
            const auto now=GetTickCount64();require(deadline>now && deadline-now<=5000 && deadline<=c->spec.consent_tick_deadline && (c->spec.can_control || m.payload.at(8)==0));
        }
        c->media_write_sequence=m.sequence;c->enqueue(true,std::move(bytes));
        if(m.kind==ipc::MediaKind::stop)c->stop_now();return ERROR_SUCCESS;
    }catch(...){try{find(value)->stop_now();}catch(...){}return failed();}
}
DWORD __stdcall GDRemoteMediaPoll(void* value,std::uint8_t* packet,std::uint32_t capacity,std::uint32_t* bytes){
    phase="media_control_read";
    if(!packet || !bytes || capacity<64+65536)return ERROR_INVALID_PARAMETER;*bytes=0;
    try{
        auto c=find(value);std::unique_lock<std::mutex> lock(c->operation,std::try_to_lock);require(lock.owns_lock());c->live();require(c->launched);
        std::lock_guard<std::mutex> messages(c->mailbox);std::vector<std::uint8_t> wire;
        if(!c->signals.empty()){wire=std::move(c->signals.front());c->signals.pop_front();}
        else if(c->media_snapshot){wire=std::move(*c->media_snapshot);c->media_snapshot.reset();}
        else return ERROR_NO_DATA;
        std::copy(wire.begin(),wire.end(),packet);*bytes=static_cast<std::uint32_t>(wire.size());return ERROR_SUCCESS;
    }catch(...){try{find(value)->stop_now();}catch(...){}return failed();}
}
DWORD __stdcall GDRemoteWorkerPoll(void* value,std::uint8_t* packet,std::uint32_t capacity,std::uint32_t* bytes){
    phase="worker_status_read";
    if(!packet || !bytes || capacity!=WorkerStatus::wire_bytes)return ERROR_INVALID_PARAMETER;*bytes=0;
    try{
        auto c=find(value);std::unique_lock<std::mutex> lock(c->operation,std::try_to_lock);require(lock.owns_lock());c->live();require(c->launched);
        std::lock_guard<std::mutex> messages(c->mailbox);if(!c->worker_snapshot)return ERROR_NO_DATA;
        std::copy(c->worker_snapshot->begin(),c->worker_snapshot->end(),packet);*bytes=static_cast<std::uint32_t>(c->worker_snapshot->size());c->worker_snapshot.reset();return ERROR_SUCCESS;
    }catch(...){try{find(value)->stop_now();}catch(...){}return failed();}
}
DWORD __stdcall GDRemoteLastError(char* text,std::uint32_t capacity){
    if(!text || capacity<128)return ERROR_INVALID_PARAMETER;const auto n=std::min<std::size_t>(failure.size(),127);std::memcpy(text,failure.data(),n);text[n]=0;return ERROR_SUCCESS;
}
DWORD __stdcall GDRemoteStop(void* value){try{find(value)->stop_now();return ERROR_SUCCESS;}catch(...){return ERROR_INVALID_HANDLE;}}
DWORD __stdcall GDRemoteClose(void* value){
    std::shared_ptr<Context> context;auto& r=contexts();
    {std::lock_guard<std::mutex> lock(r.mutex);auto i=r.entries.find(value);if(i==r.entries.end())return ERROR_INVALID_HANDLE;context=std::move(i->second);r.entries.erase(i);}
    context->stop_now();return ERROR_SUCCESS;
}
