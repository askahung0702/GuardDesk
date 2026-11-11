// Owned, standard-user IPC identity tests. No desktop, elevation or input.
#include "ipc_peer.hpp"
#include <sddl.h>
#include <objbase.h>
#include <iomanip>
#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace {
using remote::ipc::Identity;
using remote::ipc::Peer;
const char* phase="owned_ipc_assertion";
struct Handle{
    HANDLE value=nullptr;
    ~Handle(){if(value && value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
};
void require(bool value){if(!value)throw std::runtime_error(phase);}
template<class F> void rejected(F&& action){bool denied=false;try{action();}catch(const std::runtime_error&){denied=true;}require(denied);}
HANDLE make_pipe(const std::wstring& name,const std::wstring& owner){
    PSECURITY_DESCRIPTOR descriptor=nullptr;const auto sddl=L"O:"+owner+L"D:P(A;;GA;;;SY)(A;;GA;;;"+owner+L")";
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr)!=FALSE);
    SECURITY_ATTRIBUTES security{sizeof(security),descriptor,FALSE};
    const auto result=CreateNamedPipeW(name.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,65536,65536,0,&security);
    LocalFree(descriptor);require(result!=INVALID_HANDLE_VALUE);return result;
}
std::uintptr_t hex(const wchar_t* value){
    const auto length=std::wcslen(value);require(length>0 && length<=2*sizeof(std::uintptr_t));
    for(std::size_t i=0;i<length;++i)require(std::wcschr(L"0123456789abcdef",value[i])!=nullptr);
    wchar_t* end=nullptr;const auto raw=wcstoull(value,&end,16);require(raw!=0 && end && !*end);
    return static_cast<std::uintptr_t>(raw);
}
void cross_process(const Identity& own,const std::wstring& guid,HANDLE server){
    phase="cross_create";
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),nullptr,TRUE};Handle ready,finish;
    ready.value=CreateEventW(&security,TRUE,FALSE,nullptr);finish.value=CreateEventW(&security,TRUE,FALSE,nullptr);
    require(ready.value && finish.value);HANDLE inherited[]{ready.value,finish.value};
    SIZE_T size=0;InitializeProcThreadAttributeList(nullptr,1,0,&size);require(size>0 && size<=65536);
    std::vector<std::uint8_t> storage(size);auto attributes=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    require(InitializeProcThreadAttributeList(attributes,1,0,&size)!=FALSE);
    PROCESS_INFORMATION process{};STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.lpAttributeList=attributes;
    std::wostringstream command;command<<L'"'<<own.image<<L"\" --owned-identity-child "<<guid<<L' '<<std::hex
        <<reinterpret_cast<std::uintptr_t>(ready.value)<<L' '<<reinterpret_cast<std::uintptr_t>(finish.value)<<L' '<<own.pid<<L' '<<own.created;
    auto arguments=command.str();bool created=false;
    if(UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),nullptr,nullptr))
        created=CreateProcessW(own.image.c_str(),arguments.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&startup.StartupInfo,&process)!=FALSE;
    DeleteProcThreadAttributeList(attributes);require(created);
    Handle child;child.value=process.hProcess;Handle thread;thread.value=process.hThread;
    try{
        phase="cross_launched_peer";
        Peer launched(process.dwProcessId);const auto expected=launched.identity();
        phase="cross_child_ready";
        HANDLE waits[]{ready.value,child.value};const auto ready_state=WaitForMultipleObjects(2,waits,FALSE,5000);
        if(ready_state==WAIT_OBJECT_0+1){DWORD exit=1;GetExitCodeProcess(child.value,&exit);std::cerr<<"owned_child_exit_before_ready="<<exit<<'\n';}
        require(ready_state==WAIT_OBJECT_0);
        // Ready means this owned child has opened and authenticated its server;
        // the server-side synchronous connect is now already satisfied.
        phase="cross_server_connect";require(ConnectNamedPipe(server,nullptr)!=FALSE || GetLastError()==ERROR_PIPE_CONNECTED);
        phase="cross_mutual_authenticate";
        auto authenticated=remote::ipc::authenticate_pipe(server,true,expected,own.sid);
        auto wrong=expected;++wrong.created;
        rejected([&]{remote::ipc::authenticate_pipe(server,true,wrong,own.sid);});
        authenticated.require_alive();require(SetEvent(finish.value)!=FALSE);
        phase="cross_child_exit";require(WaitForSingleObject(child.value,5000)==WAIT_OBJECT_0);DWORD exit=1;
        require(GetExitCodeProcess(child.value,&exit)!=FALSE && exit==0);rejected([&]{authenticated.require_alive();});
    }catch(...){SetEvent(finish.value);if(WaitForSingleObject(child.value,5000)!=WAIT_OBJECT_0){TerminateProcess(child.value,1);WaitForSingleObject(child.value,1000);}throw;}
}
void test_child_exit(const Identity& own){
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),nullptr,TRUE};
    Handle event;event.value=CreateEventW(&security,TRUE,FALSE,nullptr);require(event.value!=nullptr);
    SIZE_T size=0;InitializeProcThreadAttributeList(nullptr,1,0,&size);require(size>0 && size<=65536);
    std::vector<std::uint8_t> storage(size);
    auto attributes=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    require(InitializeProcThreadAttributeList(attributes,1,0,&size)!=FALSE);
    PROCESS_INFORMATION process{};STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.lpAttributeList=attributes;
    std::wostringstream command;command<<L'"'<<own.image<<L"\" --owned-wait "<<std::hex<<reinterpret_cast<std::uintptr_t>(event.value);
    std::wstring arguments=command.str();bool created=false;
    if(UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,&event.value,sizeof(event.value),nullptr,nullptr))
        created=CreateProcessW(own.image.c_str(),arguments.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&startup.StartupInfo,&process)!=FALSE;
    DeleteProcThreadAttributeList(attributes);require(created);
    Handle child;child.value=process.hProcess;Handle thread;thread.value=process.hThread;
    try{
        Peer peer(process.dwProcessId);auto expected=peer.identity();peer.require_match(expected);
        require(SetEvent(event.value)!=FALSE);require(WaitForSingleObject(child.value,5000)==WAIT_OBJECT_0);
        rejected([&]{peer.require_alive();});
    }catch(...){SetEvent(event.value);if(WaitForSingleObject(child.value,5000)!=WAIT_OBJECT_0){TerminateProcess(child.value,1);WaitForSingleObject(child.value,1000);}throw;}
}
int test(){
    Peer own_peer(GetCurrentProcessId());const auto own=own_peer.identity();
    GUID guid{};require(SUCCEEDED(CoCreateGuid(&guid)));wchar_t text[40]{};require(StringFromGUID2(guid,text,40)>0);
    const std::wstring name=L"\\\\.\\pipe\\GuardDesk-Owned-Remote-Peer-"+std::wstring(text);
    Handle server;server.value=make_pipe(name,own.sid);
    Handle client;client.value=CreateFileW(name.c_str(),GENERIC_READ|GENERIC_WRITE|READ_CONTROL,0,nullptr,OPEN_EXISTING,
        SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);require(client.value!=INVALID_HANDLE_VALUE);
    require(ConnectNamedPipe(server.value,nullptr)!=FALSE || GetLastError()==ERROR_PIPE_CONNECTED);
    auto verified_client=remote::ipc::authenticate_pipe(server.value,true,own,own.sid);
    auto verified_server=remote::ipc::authenticate_pipe(client.value,false,own,own.sid);
    verified_client.require_alive();verified_server.require_alive();
    rejected([&]{remote::ipc::authenticate_pipe(client.value,false,own,L"S-1-0-0");});
    for(unsigned variant=0;variant<5;++variant){
        auto wrong=own;
        switch(variant){case 0:++wrong.pid;break;case 1:++wrong.created;break;case 2:++wrong.session;break;
            case 3:wrong.sid=L"S-1-0-0";break;default:wrong.image+=L".invalid";break;}
        rejected([&]{remote::ipc::authenticate_pipe(server.value,true,wrong,own.sid);});
    }
    test_child_exit(own);
    require(DisconnectNamedPipe(server.value)!=FALSE);
    // A disconnected old instance is not a fresh listening instance; the
    // previous client must also close its handle. Keep this owned fixture's
    // ready-before-connect path bounded by creating a genuinely new instance.
    CloseHandle(client.value);client.value=nullptr;CloseHandle(server.value);server.value=nullptr;
    server.value=make_pipe(name,own.sid);
    cross_process(own,text,server.value);
    std::cout<<"{\"passed\":true,\"scope\":\"owned_standard_user_IPC_identity_only\",\"mutual_pipe_identity\":true,\"negative_identity_cases\":6,\"distinct_same_user_process_test\":true,\"retained_child_exit_detected\":true,\"SYSTEM_boundary_tested\":false,\"lease_payload_media_isolation_tested\":false,\"desktop_capture\":false,\"os_input\":false}\n";
    return 0;
}
}
int wmain(int argc,wchar_t** argv){
    if(argc==3 && std::wstring(argv[1])==L"--owned-wait"){
        try{return WaitForSingleObject(reinterpret_cast<HANDLE>(hex(argv[2])),5000)==WAIT_OBJECT_0?0:2;}catch(...){return 2;}
    }
    if(argc==7 && std::wstring(argv[1])==L"--owned-identity-child"){
        try{
            GUID guid{};require(SUCCEEDED(CLSIDFromString(argv[2],&guid)));wchar_t canonical[40]{};
            require(StringFromGUID2(guid,canonical,40)>0 && std::wstring(canonical)==argv[2]);
            Peer self(GetCurrentProcessId());auto expected=self.identity();
            const auto pid=hex(argv[5]);require(pid<=MAXDWORD);expected.pid=static_cast<DWORD>(pid);expected.created=hex(argv[6]);
            const std::wstring name=L"\\\\.\\pipe\\GuardDesk-Owned-Remote-Peer-"+std::wstring(canonical);Handle pipe;
            pipe.value=CreateFileW(name.c_str(),GENERIC_READ|GENERIC_WRITE|READ_CONTROL,0,nullptr,OPEN_EXISTING,
                SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
            if(pipe.value==INVALID_HANDLE_VALUE)return static_cast<int>(0x40000000u|(GetLastError()&0xffff));
            auto parent=remote::ipc::authenticate_pipe(pipe.value,false,expected,self.identity().sid);
            require(SetEvent(reinterpret_cast<HANDLE>(hex(argv[3])))!=FALSE);
            require(WaitForSingleObject(reinterpret_cast<HANDLE>(hex(argv[4])),5000)==WAIT_OBJECT_0);
            parent.require_alive();return 0;
        }catch(...){return 2;}
    }
    if(argc!=2 || std::wstring(argv[1])!=L"--self-test")return 2;
    try{return test();}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
