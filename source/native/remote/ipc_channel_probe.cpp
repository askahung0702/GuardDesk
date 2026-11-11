// Owned standard-user IPC integration. No desktop, real consent or OS input.
#include "ipc_channel.hpp"
#include <objbase.h>
#include <algorithm>
#include <chrono>
#include <cwchar>
#include <cwctype>
#include <iostream>
#include <sstream>
#include <thread>

namespace remote::ipc {
// Test-only friend: malformed peers still use the production-owned heap I/O
// lifetime. Never leave a stack OVERLAPPED pending when a test times out.
struct OwnedChannelFixture{
    static bool busy(Channel& channel){std::unique_lock<std::mutex> lock(channel.operation_,std::try_to_lock);return !lock.owns_lock();}
    static void write(HANDLE raw,const Identity& expected,const std::wstring& owner,HANDLE cancel,const std::vector<std::uint8_t>& bytes){
        HANDLE duplicate=nullptr;
        if(!DuplicateHandle(GetCurrentProcess(),raw,GetCurrentProcess(),&duplicate,0,FALSE,DUPLICATE_SAME_ACCESS))throw std::runtime_error("fixture_duplicate_failed");
        std::unique_ptr<Channel> channel;
        try{channel=std::unique_ptr<Channel>(new Channel(duplicate,cancel,false));}catch(...){CloseHandle(duplicate);throw;}
        channel->peer_=std::make_unique<Peer>(authenticate_pipe(duplicate,false,expected,owner));
        channel->exact(true,const_cast<std::uint8_t*>(bytes.data()),bytes.size(),GetTickCount64()+1000);
    }
};
}
namespace {
using namespace remote::ipc;
const char* phase="channel_probe";
void require(bool value){if(!value)throw std::runtime_error(phase);}
struct Handle{HANDLE value=nullptr;~Handle(){if(value && value!=INVALID_HANDLE_VALUE)CloseHandle(value);}};
struct Event:Handle{Event(){value=CreateEventW(nullptr,TRUE,FALSE,nullptr);require(value!=nullptr);}};
void put(std::vector<std::uint8_t>& bytes,std::size_t at,std::uint64_t value,unsigned count){require(at+count<=bytes.size());for(unsigned i=0;i<count;++i)bytes.at(at+i)=static_cast<std::uint8_t>(value>>(8*i));}
std::uint64_t get(const std::vector<std::uint8_t>& bytes,std::size_t at,unsigned count){require(at+count<=bytes.size());std::uint64_t value=0;for(unsigned i=0;i<count;++i)value|=std::uint64_t(bytes.at(at+i))<<(8*i);return value;}
std::vector<std::uint8_t> packet(Kind kind,unsigned body,std::uint64_t sequence,std::uint64_t frame=0){
    std::vector<std::uint8_t> bytes(64+body);std::copy_n("GDR2",4,bytes.begin());
    put(bytes,4,2,2);put(bytes,6,static_cast<unsigned>(kind),2);put(bytes,8,body,4);bytes[16]=7;
    put(bytes,32,1,8);put(bytes,40,sequence,8);put(bytes,48,frame,8);put(bytes,56,5,8);return bytes;
}
std::vector<std::uint8_t> hello(){auto bytes=packet(Kind::hello,16,1);put(bytes,72,2,4);put(bytes,76,control_max_payload,4);return bytes;}
std::vector<std::uint8_t> lease(unsigned sequence){auto bytes=packet(Kind::lease,24,sequence);put(bytes,64,GetTickCount64()+4500,8);put(bytes,72,1,8);put(bytes,80,1,4);return bytes;}
std::vector<std::uint8_t> input(unsigned sequence){auto bytes=packet(Kind::input,24,sequence,1);bytes[64]=1;bytes[65]=1;put(bytes,66,27,2);return bytes;}
// The owned peer uses the schema's published counter for its synthetic result.
// This is a test response, never an input grant or product ACK.
std::vector<std::uint8_t> stats(unsigned sequence,bool accepted){auto bytes=packet(Kind::stats,32,sequence);put(bytes,64,1,4);put(bytes,88,accepted?1:0,4);return bytes;}
std::wstring nonce(){GUID guid{};require(SUCCEEDED(CoCreateGuid(&guid)));wchar_t text[40]{};require(StringFromGUID2(guid,text,40)>0);std::wstring result;for(auto c:text)if(std::iswxdigit(c))result+=static_cast<wchar_t>(std::towlower(c));require(result.size()==32);return result;}
std::uintptr_t number(const wchar_t* text){const auto size=std::wcslen(text);require(size>0 && size<=16);for(std::size_t i=0;i<size;++i)require(std::wcschr(L"0123456789abcdef",text[i]));return static_cast<std::uintptr_t>(wcstoull(text,nullptr,16));}
struct Child{
    Handle process,thread,inherited;HANDLE cancel;
    Child(const std::wstring& token,HANDLE stop):cancel(stop){
        Peer self(GetCurrentProcessId());
        require(DuplicateHandle(GetCurrentProcess(),stop,GetCurrentProcess(),&inherited.value,SYNCHRONIZE,TRUE,0)!=FALSE);
        SIZE_T size=0;InitializeProcThreadAttributeList(nullptr,1,0,&size);require(size>0 && size<=65536);
        std::vector<std::uint8_t> storage(size);auto attributes=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        require(InitializeProcThreadAttributeList(attributes,1,0,&size)!=FALSE);
        STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.lpAttributeList=attributes;
        std::wostringstream command;command<<L'"'<<self.identity().image<<L"\" --owned-worker "<<token<<L' '<<std::hex<<self.identity().pid<<L' '<<self.identity().created<<L' '<<reinterpret_cast<std::uintptr_t>(inherited.value);
        auto arguments=command.str();PROCESS_INFORMATION info{};bool created=false;
        if(UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,&inherited.value,sizeof(inherited.value),nullptr,nullptr))
            created=CreateProcessW(self.identity().image.c_str(),arguments.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&startup.StartupInfo,&info)!=FALSE;
        DeleteProcThreadAttributeList(attributes);require(created);process.value=info.hProcess;thread.value=info.hThread;
    }
    ~Child(){SetEvent(cancel);if(process.value && WaitForSingleObject(process.value,4000)!=WAIT_OBJECT_0){TerminateProcess(process.value,1);WaitForSingleObject(process.value,1000);}}
    Identity identity(){return Peer(GetProcessId(process.value)).identity();}
    void success(){require(WaitForSingleObject(process.value,4000)==WAIT_OBJECT_0);DWORD code=1;require(GetExitCodeProcess(process.value,&code)!=FALSE && code==0);}
};
int worker(wchar_t** args){
    Peer self(GetCurrentProcessId());auto expected=self.identity();const auto pid=number(args[3]);require(pid<=MAXDWORD);
    expected.pid=static_cast<DWORD>(pid);expected.created=number(args[4]);auto cancel=reinterpret_cast<HANDLE>(number(args[5]));
    auto pipe=Channel::open(args[2],expected,self.identity().sid,cancel,3000);pipe->write(hello(),3000);
    Session session{};session[0]=7;ControlGate gate(session,5,GetTickCount64(),GetTickCount64()+8000);
    auto grant=pipe->read(3000);require(grant.header.kind==Kind::lease && gate.accept_broker(grant,GetTickCount64()));
    require(gate.set_desktop(1,320,180) && gate.frame(1,GetTickCount64()));
    auto state=packet(Kind::desktop_state,16,2);put(state,64,1,4);put(state,68,320,4);put(state,72,180,4);pipe->write(state,3000);
    bool stopped=false;
    try{
        for(unsigned round=0;round<4;++round){
            auto command=pipe->read(3000);const bool accepted=gate.accept_broker(command,GetTickCount64());
            stopped=stopped || (command.header.kind==Kind::stop && accepted);pipe->write(stats(3+round,accepted),3000);
        }
        const auto delivered=pipe->read(3000);require(delivered.header.kind==Kind::release_all && gate.accept_broker(delivered,GetTickCount64()));
        require(WaitForSingleObject(cancel,4000)==WAIT_OBJECT_0);return 0;
    }catch(...){if(stopped && WaitForSingleObject(cancel,0)==WAIT_OBJECT_0)return 0;throw;}
}
bool rejected_read(Channel& channel,DWORD timeout){try{channel.read(timeout);return false;}catch(const std::exception&){return true;}}
void require_no_token(){HANDLE token=nullptr;const bool opened=OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&token)!=FALSE;if(opened)CloseHandle(token);require(!opened && GetLastError()==ERROR_NO_TOKEN);}
void failure_case(unsigned mode){
    Event cancel,finish;Peer self(GetCurrentProcessId());const auto token=nonce();auto server=Channel::listen(token,self.identity().sid,cancel.value);
    bool client_ok=false;std::thread client([&]{
        try{
            Handle raw;const auto path=L"\\\\.\\pipe\\GuardDesk-Remote-Control-"+token;
            const DWORD qos=mode==4?SECURITY_ANONYMOUS:mode==5?SECURITY_IMPERSONATION:SECURITY_IDENTIFICATION;
            raw.value=CreateFileW(path.c_str(),FILE_READ_DATA|FILE_WRITE_DATA|READ_CONTROL|SYNCHRONIZE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|qos,nullptr);require(raw.value!=INVALID_HANDLE_VALUE);
            auto raw_write=[&](const auto& bytes){OwnedChannelFixture::write(raw.value,self.identity(),self.identity().sid,cancel.value,bytes);};
            if(mode==1)raw_write(std::vector<std::uint8_t>{'G','D','R','2',2,0,1});
            if(mode==2){auto malformed=hello();put(malformed,8,65537,4);malformed.resize(64);raw_write(malformed);}
            if(mode==3)raw_write(lease(1));
            if(mode==4 || mode==5)raw_write(hello());
            if(mode==6){
                const auto bytes=hello();
                for(auto byte:bytes){
                    if(WaitForSingleObject(finish.value,10)==WAIT_OBJECT_0)break;
                    try{raw_write(std::vector<std::uint8_t>{byte});}catch(...){break;}
                }
            }
            WaitForSingleObject(finish.value,4000);client_ok=true;
        }catch(...){client_ok=false;}
    });
    try{
        server->accept(self.identity(),self.identity().sid,2000);const auto started=GetTickCount64();
        require(rejected_read(*server,mode==6?80:mode==0 || mode==1?60:1000));require(GetTickCount64()-started<1500);
        require(rejected_read(*server,100));require_no_token();
    }catch(...){SetEvent(finish.value);client.join();throw;}
    SetEvent(finish.value);client.join();require(client_ok);
}
void cancel_case(){
    Event cancel,finish;Peer self(GetCurrentProcessId());const auto token=nonce();auto server=Channel::listen(token,self.identity().sid,cancel.value);
    std::thread client([&]{try{auto pipe=Channel::open(token,self.identity(),self.identity().sid,cancel.value,2000);WaitForSingleObject(finish.value,3000);}catch(...){}});
    std::thread trigger;
    try{
        server->accept(self.identity(),self.identity().sid,2000);trigger=std::thread([&]{Sleep(40);SetEvent(cancel.value);});
        const auto started=GetTickCount64();require(rejected_read(*server,3000));require(GetTickCount64()-started<1000);
    }catch(...){SetEvent(finish.value);SetEvent(cancel.value);if(trigger.joinable())trigger.join();client.join();throw;}
    SetEvent(finish.value);trigger.join();client.join();
}
void peer_exit_case(){
    Event cancel;Peer self(GetCurrentProcessId());const auto token=nonce();auto server=Channel::listen(token,self.identity().sid,cancel.value);Child child(token,cancel.value);
    server->accept(child.identity(),self.identity().sid,3000);require(server->read(3000).header.kind==Kind::hello);
    std::thread trigger([&]{Sleep(40);TerminateProcess(child.process.value,0);});
    const auto started=GetTickCount64();const auto denied=rejected_read(*server,3000);trigger.join();require(denied && GetTickCount64()-started<1000);
}
void blocked_write_case(){
    Event cancel,finish;Peer self(GetCurrentProcessId());const auto token=nonce();auto server=Channel::listen(token,self.identity().sid,cancel.value);
    std::thread client([&]{try{auto pipe=Channel::open(token,self.identity(),self.identity().sid,cancel.value,2000);WaitForSingleObject(finish.value,4000);}catch(...){}});
    try{
        server->accept(self.identity(),self.identity().sid,2000);bool refused=false;const auto started=GetTickCount64();
        for(unsigned i=1;i<=4096;++i){try{server->write(lease(i),40);}catch(const std::exception&){refused=true;break;}}
        require(refused && GetTickCount64()-started<2000);
    }catch(...){SetEvent(finish.value);SetEvent(cancel.value);client.join();throw;}
    SetEvent(finish.value);client.join();
}
void concurrent_call_case(){
    Event cancel,finish;Peer self(GetCurrentProcessId());const auto token=nonce();auto server=Channel::listen(token,self.identity().sid,cancel.value);
    std::thread client([&]{try{auto pipe=Channel::open(token,self.identity(),self.identity().sid,cancel.value,2000);WaitForSingleObject(finish.value,4000);}catch(...){}});
    std::thread reader;bool read_denied=false;
    try{
        server->accept(self.identity(),self.identity().sid,2000);reader=std::thread([&]{read_denied=rejected_read(*server,3000);});
        const auto end=GetTickCount64()+1000;while(!OwnedChannelFixture::busy(*server) && GetTickCount64()<end)Sleep(1);
        require(OwnedChannelFixture::busy(*server));bool denied=false;
        try{server->write(lease(1),1000);}catch(const std::exception&){denied=true;}
        require(denied);SetEvent(cancel.value);reader.join();require(read_denied);
    }catch(...){SetEvent(cancel.value);SetEvent(finish.value);if(reader.joinable())reader.join();client.join();throw;}
    SetEvent(finish.value);client.join();
}
int test(){
    phase="cross_process_native_channel";
    Event cancel;Peer self(GetCurrentProcessId());const auto token=nonce();auto server=Channel::listen(token,self.identity().sid,cancel.value);Child child(token,cancel.value);
    phase="cross_accept";server->accept(child.identity(),self.identity().sid,3000);
    phase="cross_hello";Event wake;
    while(!server->wait_readable(100,wake.value)){}
    require(server->read(3000).header.kind==Kind::hello);require_no_token();
    phase="idle_readiness_is_not_failure";require(!server->wait_readable(5,wake.value));SetEvent(wake.value);
    require(!server->wait_readable(100,wake.value));ResetEvent(wake.value);
    phase="cross_lease_state";server->write(lease(1),3000);require(server->read(3000).header.kind==Kind::desktop_state);
    phase="cross_input_before_ACK";server->write(input(2),3000);require(get(server->read(3000).payload,24,4)==0);
    phase="cross_presented_ACK";server->write(packet(Kind::presented,0,3,1),3000);require(get(server->read(3000).payload,24,4)==1);
    phase="cross_input_after_ACK";server->write(input(4),3000);require(get(server->read(3000).payload,24,4)==1);
    phase="cross_stop";server->write(packet(Kind::stop,0,5),3000);require(get(server->read(3000).payload,24,4)==1);
    phase="cross_delivery";server->write(packet(Kind::release_all,0,6),3000);SetEvent(cancel.value);
    phase="cross_child_exit";child.success();
    for(unsigned mode=0;mode<7;++mode){phase="bounded_or_identity_failure_case";failure_case(mode);}
    phase="cancel_pending_read";cancel_case();phase="peer_exit_pending_read";peer_exit_case();
    phase="blocked_write";blocked_write_case();phase="concurrent_no_queue";concurrent_call_case();
    require(Channel::quarantined_operations()==0);
    std::cout<<"{\"passed\":true,\"actual_cross_process_pipe\":true,\"wire2_lease_ACK_gate\":true,\"effective_client_identification\":true,\"negative_IO_cases\":11,\"quarantined_operations\":0,\"SYSTEM_boundary\":false,\"center_authorization\":false,\"desktop_capture\":false,\"OS_input\":false,\"product_installed\":false}\n";
    return 0;
}
}
int wmain(int argc,wchar_t** argv){
    try{
        if(argc==6 && std::wstring(argv[1])==L"--owned-worker")return worker(argv);
        if(argc==2 && std::wstring(argv[1])==L"--self-test")return test();
        if(argc==2 && std::wstring(argv[1])==L"--owned-quarantine"){
            phase="fault_injected_uncompleted_cancel";require(owned_quarantine_selftest()==4);
            std::cout<<"{\"passed\":true,\"fault_injection\":true,\"kernel_IO_submitted\":false,\"retained_contexts\":4,\"fifth_operation_denied\":true,\"actual_stuck_driver_test\":false}\n";return 0;
        }
        return 2;
    }
    catch(const std::exception& error){std::cerr<<phase<<":"<<error.what()<<'\n';return 1;}
}
