#include "ipc_channel.hpp"
#include <sddl.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <stdexcept>
#include <span>

namespace remote::ipc {
namespace {
void require(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
std::wstring name(const std::wstring& nonce){
    require(nonce.size()==32,"control_nonce_size");
    for(auto c:nonce)require((c>=L'0' && c<=L'9') || (c>=L'a' && c<=L'f'),"control_nonce_format");
    return L"\\\\.\\pipe\\GuardDesk-Remote-Control-"+nonce;
}
std::uint64_t until(DWORD timeout){require(timeout>0 && timeout<=5000,"control_timeout_range");return GetTickCount64()+timeout;}
DWORD remaining(std::uint64_t deadline){const auto now=GetTickCount64();return now<deadline?static_cast<DWORD>(deadline-now):0;}
struct Operation{
    OVERLAPPED overlapped{};
    std::vector<std::uint8_t> bytes;
    explicit Operation(DWORD size):bytes(size){
        overlapped.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);require(overlapped.hEvent!=nullptr,"control_io_event_failed");
    }
    ~Operation(){CloseHandle(overlapped.hEvent);}
};
// Four bounded slots across this process. An uncancelable operation retains
// its heap OVERLAPPED/buffer/event until OS process teardown. Do not free it on
// an uncompleted cancel or in a static destructor. The channel is poisoned and
// cannot allocate again; exhaustion rejects before issuing more kernel I/O.
std::array<std::atomic<bool>,4> used{};
std::atomic<unsigned> quarantined{0};
class Pending{
    unsigned slot_=4;Operation* operation_=nullptr;
public:
    explicit Pending(DWORD size){
        require(size<=control_header_bytes+control_max_payload,"control_io_size");
        for(unsigned i=0;i<used.size();++i){bool free=false;if(used[i].compare_exchange_strong(free,true)){slot_=i;break;}}
        require(slot_<used.size(),"control_io_capacity");
        try{operation_=new Operation(size);}catch(...){used[slot_]=false;throw;}
    }
    ~Pending(){if(operation_){delete operation_;used[slot_]=false;}}
    Operation& get(){return *operation_;}
    void quarantine(){operation_=nullptr;++quarantined;}
};
bool cancel_and_drain(HANDLE pipe,Pending& pending){
    auto& operation=pending.get();CancelIoEx(pipe,&operation.overlapped);
    if(WaitForSingleObject(operation.overlapped.hEvent,250)==WAIT_OBJECT_0)return true;
    pending.quarantine();return false;
}
}
#ifdef GUARDDESK_OWNED_CHANNEL_FIXTURES
unsigned owned_quarantine_selftest(){
    // Simulate completion that never arrives, without submitting kernel I/O.
    // Run in a separate process: deliberately retained contexts cannot be
    // reset/reused by a production retry or freed by a static destructor.
    std::array<Operation*,4> retained{};
    for(unsigned i=0;i<retained.size();++i){
        Pending pending(static_cast<DWORD>(control_header_bytes+control_max_payload));
        retained[i]=&pending.get();retained[i]->bytes.back()=static_cast<std::uint8_t>(i+1);
        require(!cancel_and_drain(INVALID_HANDLE_VALUE,pending),"fixture_expected_quarantine");
    }
    require(quarantined.load()==4,"fixture_quarantine_count");
    bool capacity=false;
    try{Pending fifth(1);}catch(const std::runtime_error& error){capacity=std::strcmp(error.what(),"control_io_capacity")==0;}
    require(capacity,"fixture_quarantine_capacity_not_enforced");
    for(unsigned i=0;i<retained.size();++i){
        DWORD flags=0;
        require(GetHandleInformation(retained[i]->overlapped.hEvent,&flags)!=FALSE,"fixture_retained_event_released");
        require(WaitForSingleObject(retained[i]->overlapped.hEvent,0)==WAIT_TIMEOUT,"fixture_retained_event_signaled");
        require(retained[i]->bytes.back()==i+1,"fixture_retained_buffer_released");
    }
    return quarantined.load();
}
#endif
Channel::Channel(HANDLE pipe,HANDLE cancel,bool server):pipe_(pipe),server_(server){
    require(cancel && DuplicateHandle(GetCurrentProcess(),cancel,GetCurrentProcess(),&cancel_,SYNCHRONIZE,FALSE,0)!=FALSE,"control_cancel_handle_failed");
}
Channel::~Channel(){if(pipe_!=INVALID_HANDLE_VALUE)CloseHandle(pipe_);if(cancel_)CloseHandle(cancel_);}
void Channel::fail(){poisoned_=true;if(pipe_!=INVALID_HANDLE_VALUE){CloseHandle(pipe_);pipe_=INVALID_HANDLE_VALUE;}}
void Channel::guard() const{
    require(!poisoned_ && pipe_!=INVALID_HANDLE_VALUE,"control_channel_closed");
    require(WaitForSingleObject(cancel_,0)==WAIT_TIMEOUT,"control_canceled");
    if(peer_)peer_->require_alive();
}
unsigned Channel::quarantined_operations(){return quarantined.load();}
std::unique_ptr<Channel> Channel::listen(const std::wstring& nonce,const std::wstring& permitted_sid,HANDLE cancel,bool low_integrity){
    const auto path=name(nonce);Peer self(GetCurrentProcessId());
    PSID sid=nullptr;require(ConvertStringSidToSidW(permitted_sid.c_str(),&sid)!=FALSE,"control_permitted_sid_invalid");LocalFree(sid);
    const auto sddl=L"O:"+self.identity().sid+L"D:P(A;;GA;;;SY)(A;;GA;;;"+self.identity().sid+L")(A;;0x120083;;;"+permitted_sid+L")(A;;RC;;;OW)"+(low_integrity?L"S:(ML;;NW;;;LW)":L"");
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr)!=FALSE,"control_security_descriptor_failed");
    SECURITY_ATTRIBUTES security{sizeof(security),descriptor,FALSE};
    const auto pipe=CreateNamedPipeW(path.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,65536,65536,0,&security);
    LocalFree(descriptor);require(pipe!=INVALID_HANDLE_VALUE,"control_pipe_create_failed");
    try{return std::unique_ptr<Channel>(new Channel(pipe,cancel,true));}catch(...){CloseHandle(pipe);throw;}
}
std::unique_ptr<Channel> Channel::open(const std::wstring& nonce,const Identity& server,const std::wstring& owner,HANDLE cancel,DWORD timeout,std::unique_ptr<Peer> launch_peer){
    const auto path=name(nonce);const auto deadline=until(timeout);HANDLE pipe=INVALID_HANDLE_VALUE;
    while(remaining(deadline)){
        require(WaitForSingleObject(cancel,0)==WAIT_TIMEOUT,"control_connect_canceled");
        pipe=CreateFileW(path.c_str(),FILE_READ_DATA|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE,0,nullptr,OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION|SECURITY_EFFECTIVE_ONLY,nullptr);
        if(pipe!=INVALID_HANDLE_VALUE)break;
        const auto error=GetLastError();require(error==ERROR_PIPE_BUSY || error==ERROR_FILE_NOT_FOUND,"control_pipe_open_failed");
        WaitForSingleObject(cancel,std::min<DWORD>(remaining(deadline),10));
    }
    require(pipe!=INVALID_HANDLE_VALUE,"control_pipe_connect_timeout");
    std::unique_ptr<Channel> channel;
    try{channel=std::unique_ptr<Channel>(new Channel(pipe,cancel,false));}catch(...){CloseHandle(pipe);throw;}
    if(launch_peer){
        ULONG pid=0;require(pipe_owner(pipe)==owner && GetNamedPipeServerProcessId(pipe,&pid) && pid==server.pid,"control_launch_server_pipe");
        launch_peer->require_match(server);channel->peer_=std::move(launch_peer);
    }else channel->peer_=std::make_unique<Peer>(authenticate_pipe(pipe,false,server,owner));
    channel->guard();return channel;
}
void Channel::accept(const Identity& expected,const std::wstring& owner,DWORD timeout){
    std::unique_lock<std::mutex> lock(operation_,std::try_to_lock);require(lock.owns_lock(),"control_channel_busy");
    require(server_ && !peer_,"control_accept_state");guard();const auto deadline=until(timeout);Pending pending(0);auto& op=pending.get();
    const auto connected=ConnectNamedPipe(pipe_,&op.overlapped);const auto error=connected?ERROR_SUCCESS:GetLastError();
    if(!connected && error==ERROR_IO_PENDING){
        HANDLE waits[]{op.overlapped.hEvent,cancel_};const auto result=WaitForMultipleObjects(2,waits,FALSE,remaining(deadline));
        if(result!=WAIT_OBJECT_0){cancel_and_drain(pipe_,pending);fail();throw std::runtime_error("control_accept_canceled_or_timeout");}
        DWORD bytes=0;if(!GetOverlappedResult(pipe_,&op.overlapped,&bytes,FALSE)){fail();throw std::runtime_error("control_accept_failed");}
    }else if(!connected && error!=ERROR_PIPE_CONNECTED){fail();throw std::runtime_error("control_accept_failed");}
    try{peer_=std::make_unique<Peer>(authenticate_pipe(pipe_,true,expected,owner));guard();}catch(...){fail();throw;}
}
DWORD Channel::transfer(bool write,void* bytes,DWORD count,std::uint64_t deadline){
    guard();require(peer_!=nullptr,"control_peer_not_bound");require(remaining(deadline)>0,"control_io_timeout");
    Pending pending(count);auto& op=pending.get();if(write)std::memcpy(op.bytes.data(),bytes,count);DWORD transferred=0;
    const auto immediate=write?WriteFile(pipe_,op.bytes.data(),count,&transferred,&op.overlapped):ReadFile(pipe_,op.bytes.data(),count,&transferred,&op.overlapped);
    if(!immediate){
        if(GetLastError()!=ERROR_IO_PENDING){fail();throw std::runtime_error("control_io_failed");}
        HANDLE waits[]{op.overlapped.hEvent,cancel_,peer_->wait_handle()};
        const auto result=WaitForMultipleObjects(3,waits,FALSE,remaining(deadline));
        if(result!=WAIT_OBJECT_0){cancel_and_drain(pipe_,pending);fail();throw std::runtime_error("control_io_canceled_timeout_or_peer_exit");}
        if(!GetOverlappedResult(pipe_,&op.overlapped,&transferred,FALSE)){fail();throw std::runtime_error("control_io_failed");}
    }
    require(transferred>0 && transferred<=count,"control_io_no_progress");guard();
    if(!write)std::memcpy(bytes,op.bytes.data(),transferred);return transferred;
}
void Channel::exact(bool write,void* bytes,std::size_t count,std::uint64_t deadline){
    auto cursor=std::span<std::uint8_t>(static_cast<std::uint8_t*>(bytes),count);std::size_t offset=0;
    if(!write && !prefetched_.empty()){
        offset=std::min(count,prefetched_.size());std::copy_n(prefetched_.begin(),offset,cursor.begin());
        prefetched_.erase(prefetched_.begin(),prefetched_.begin()+offset);
    }
    while(offset<count){const auto transferred=transfer(write,cursor.subspan(offset).data(),static_cast<DWORD>(count-offset),deadline);offset+=transferred;}
}
Message Channel::read(DWORD timeout){
    std::unique_lock<std::mutex> lock(operation_,std::try_to_lock);require(lock.owns_lock(),"control_channel_busy");
    try{
        const auto deadline=until(timeout);std::array<std::uint8_t,control_header_bytes> header{};exact(false,header.data(),header.size(),deadline);
        if(server_)require_effective_client(pipe_,peer_->identity().sid);
        const auto direction=server_?Direction::worker_to_broker:Direction::broker_to_worker;const auto decoded=control_header(header,direction);
        std::vector<std::uint8_t> wire(header.begin(),header.end());wire.resize(control_header_bytes+decoded.payload_bytes);
        if(decoded.payload_bytes)exact(false,&wire.at(control_header_bytes),decoded.payload_bytes,deadline);
        guard();return control_message(wire,direction);
    }catch(...){fail();throw;}
}
void Channel::write(const std::vector<std::uint8_t>& packet,DWORD timeout){
    std::unique_lock<std::mutex> lock(operation_,std::try_to_lock);require(lock.owns_lock(),"control_channel_busy");
    try{
        control_message(packet,server_?Direction::broker_to_worker:Direction::worker_to_broker);
        const auto deadline=until(timeout);
        // Operation owns a copy while kernel I/O is pending; caller data is
        // never referenced after a timeout/quarantined cancellation.
        exact(true,const_cast<std::uint8_t*>(packet.data()),packet.size(),deadline);guard();
    }catch(...){fail();throw;}
}
bool Channel::available(){
    std::unique_lock<std::mutex> lock(operation_,std::try_to_lock);require(lock.owns_lock(),"control_channel_busy");guard();
    DWORD count=0;if(!PeekNamedPipe(pipe_,nullptr,0,nullptr,&count,nullptr)){fail();throw std::runtime_error("control_peek_failed");}
    return count+prefetched_.size()>=media_header_bytes;
}
bool Channel::wait_readable(DWORD timeout,HANDLE wake){
    std::unique_lock<std::mutex> lock(operation_,std::try_to_lock);require(lock.owns_lock(),"control_channel_busy");guard();
    require(timeout>0 && timeout<=100 && wake,"control_readiness_arguments");
    if(prefetched_.size()>=media_header_bytes)return true;
    Pending pending(static_cast<DWORD>(media_header_bytes-prefetched_.size()));auto& op=pending.get();DWORD received=0;
    BOOL done=ReadFile(pipe_,op.bytes.data(),static_cast<DWORD>(op.bytes.size()),&received,&op.overlapped);
    if(!done){
        if(GetLastError()!=ERROR_IO_PENDING){fail();throw std::runtime_error("control_readiness_read");}
        HANDLE waits[]{op.overlapped.hEvent,cancel_,wake};const auto result=WaitForMultipleObjects(3,waits,FALSE,timeout);
        if(result!=WAIT_OBJECT_0 && !cancel_and_drain(pipe_,pending)){fail();throw std::runtime_error("control_readiness_quarantined");}
        done=GetOverlappedResult(pipe_,&op.overlapped,&received,FALSE);
        if(!done && GetLastError()!=ERROR_OPERATION_ABORTED){fail();throw std::runtime_error("control_readiness_completion");}
    }
    if(done){
        if(!received || received>op.bytes.size()){fail();throw std::runtime_error("control_readiness_eof");}
        prefetched_.insert(prefetched_.end(),op.bytes.begin(),op.bytes.begin()+received);
    }
    guard();return prefetched_.size()>=media_header_bytes;
}
MediaMessage Channel::read_media(DWORD timeout){
    std::unique_lock<std::mutex> lock(operation_,std::try_to_lock);require(lock.owns_lock(),"control_channel_busy");
    try{
        const auto deadline=until(timeout);std::array<std::uint8_t,media_header_bytes> header{};exact(false,header.data(),header.size(),deadline);
        if(server_)require_effective_client(pipe_,peer_->identity().sid);
        const auto direction=server_?MediaDirection::media_to_broker:MediaDirection::broker_to_media;
        const auto decoded=media_header(header,direction);std::vector<std::uint8_t> wire(header.begin(),header.end());wire.resize(media_header_bytes+decoded.payload_bytes);
        if(decoded.payload_bytes)exact(false,&wire.at(media_header_bytes),decoded.payload_bytes,deadline);
        guard();return media_message(wire,direction);
    }catch(...){fail();throw;}
}
void Channel::write_media(const std::vector<std::uint8_t>& packet,DWORD timeout){
    std::unique_lock<std::mutex> lock(operation_,std::try_to_lock);require(lock.owns_lock(),"control_channel_busy");
    try{
        media_message(packet,server_?MediaDirection::broker_to_media:MediaDirection::media_to_broker);
        exact(true,const_cast<std::uint8_t*>(packet.data()),packet.size(),until(timeout));guard();
    }catch(...){fail();throw;}
}
}
