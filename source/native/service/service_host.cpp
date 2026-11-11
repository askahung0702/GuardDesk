// Fixed-purpose SCM host. No arbitrary executable, shell, network or desktop API.
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>
#include "../remote/cohort.hpp"

namespace {
constexpr wchar_t ServiceName[]=L"GuardDeskRemote";
struct Handle {
    HANDLE value=nullptr;
    explicit Handle(HANDLE h=nullptr):value(h){}
    ~Handle(){if(value && value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
    Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
};
void require(bool ok){if(!ok)throw std::runtime_error("service_boundary_failed");}
std::wstring image(){std::vector<wchar_t> b(32768);const DWORD n=GetModuleFileNameW(nullptr,b.data(),static_cast<DWORD>(b.size()));require(n && n<b.size());return {b.data(),n};}
bool device_id(const std::wstring& value){return value.size()==24 && value.find_first_not_of(L"0123456789abcdef")==std::wstring::npos;}
void require_system(){
    HANDLE raw=nullptr;require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw)!=FALSE);Handle token(raw);
    DWORD size=0;GetTokenInformation(token.value,TokenUser,nullptr,0,&size);
    require(size && size<=4096);std::vector<BYTE> data(size);
    require(GetTokenInformation(token.value,TokenUser,data.data(),size,&size)!=FALSE);
    require(IsWellKnownSid(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid,WinLocalSystemSid)!=FALSE);
    DWORD session=1;require(ProcessIdToSessionId(GetCurrentProcessId(),&session) && session==0);
}
// The host job owns only the coordinator. Interactive helpers cross sessions;
// Windows jobs cannot span sessions. Those helpers retain their existing
// authenticated parent/session leases and media workers own per-session jobs.
// Installer stop separately waits for every installed image to be unmapped.
DWORD child_lifetime(const std::wstring& exe,std::wstring command,HANDLE stop,void (*pending)(),unsigned grace=45){
#ifdef GUARDDESK_OWNED_SERVICE_TEST
    const auto job_name=L"GuardDeskOwnedServiceJob-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());
    Handle job(CreateJobObjectW(nullptr,job_name.c_str()));require(GetLastError()!=ERROR_ALREADY_EXISTS);
    if(command.find(L"--owned-spawner")!=std::wstring::npos)command+=L" "+job_name;
#else
    Handle job(CreateJobObjectW(nullptr,nullptr));require(job.value!=nullptr);
#endif
    require(job.value!=nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit{};limit.BasicLimitInformation.LimitFlags=
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    require(SetInformationJobObject(job.value,JobObjectExtendedLimitInformation,&limit,sizeof(limit))!=FALSE);
    SIZE_T bytes=0;InitializeProcThreadAttributeList(nullptr,1,0,&bytes);
    std::vector<BYTE> storage(bytes);auto* attributes=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    require(InitializeProcThreadAttributeList(attributes,1,0,&bytes)!=FALSE);
    struct Attributes{LPPROC_THREAD_ATTRIBUTE_LIST p;~Attributes(){DeleteProcThreadAttributeList(p);}} cleanup{attributes};
    require(SetHandleInformation(stop,HANDLE_FLAG_INHERIT,HANDLE_FLAG_INHERIT)!=FALSE);
    require(UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,&stop,sizeof(stop),nullptr,nullptr)!=FALSE);
    STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.lpAttributeList=attributes;
    PROCESS_INFORMATION process{};
    const auto slash=exe.find_last_of(L"\\");require(slash!=std::wstring::npos);
    const auto cwd=exe.substr(0,slash);
    const BOOL created=CreateProcessW(exe.c_str(),command.data(),nullptr,nullptr,TRUE,
        CREATE_SUSPENDED|CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,cwd.c_str(),&startup.StartupInfo,&process);
    const DWORD error=created?0:GetLastError();SetHandleInformation(stop,HANDLE_FLAG_INHERIT,0);
    if(!created)return error;
    Handle worker(process.hProcess),thread(process.hThread);
    if(!AssignProcessToJobObject(job.value,worker.value)){
        // The one suspended process was just created by us; it never ran code.
        const DWORD failure=GetLastError();TerminateProcess(worker.value,failure);WaitForSingleObject(worker.value,5000);return failure;
    }
    require(ResumeThread(thread.value)!=static_cast<DWORD>(-1));
    HANDLE waits[]{stop,worker.value};const DWORD wait=WaitForMultipleObjects(2,waits,FALSE,INFINITE);
    require(wait==WAIT_OBJECT_0 || wait==WAIT_OBJECT_0+1);
    if(wait==WAIT_OBJECT_0){
        for(unsigned i=0;i<grace && WaitForSingleObject(worker.value,1000)==WAIT_TIMEOUT;++i)if(pending)pending();
        if(WaitForSingleObject(worker.value,0)!=WAIT_OBJECT_0){
            require(TerminateJobObject(job.value,ERROR_TIMEOUT)!=FALSE);
            require(WaitForSingleObject(worker.value,5000)==WAIT_OBJECT_0);
            return ERROR_TIMEOUT;
        }
    }
    DWORD exit=ERROR_GEN_FAILURE;require(GetExitCodeProcess(worker.value,&exit)!=FALSE);
    // Drain the exact coordinator job; helper shutdown is independently checked.
    require(TerminateJobObject(job.value,exit)!=FALSE);
    for(unsigned i=0;i<50;++i){
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
        require(QueryInformationJobObject(job.value,JobObjectBasicAccountingInformation,&accounting,sizeof(accounting),nullptr)!=FALSE);
        if(accounting.ActiveProcesses==0)return exit;
        Sleep(100);
    }
    return ERROR_TIMEOUT;
}
#ifndef GUARDDESK_OWNED_SERVICE_TEST
HANDLE system_stop_event(){
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYD:P(A;;GA;;;SY)",SDDL_REVISION_1,&descriptor,nullptr)!=FALSE);
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),descriptor,FALSE};
    HANDLE event=CreateEventW(&attributes,TRUE,FALSE,nullptr);LocalFree(descriptor);require(event!=nullptr);
    PSID owner=nullptr;PSECURITY_DESCRIPTOR actual=nullptr;
    const auto result=GetSecurityInfo(event,SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION,&owner,nullptr,nullptr,nullptr,&actual);
    const bool trusted=result==ERROR_SUCCESS && owner && IsWellKnownSid(owner,WinLocalSystemSid);
    if(actual)LocalFree(actual);
    if(!trusted){CloseHandle(event);require(false);}return event;
}
SERVICE_STATUS_HANDLE registration=nullptr;HANDLE stopping=nullptr;std::wstring did;
DWORD checkpoint=0;
void status(DWORD state,DWORD error=0){
    SERVICE_STATUS value{};value.dwServiceType=SERVICE_WIN32_OWN_PROCESS;value.dwCurrentState=state;
    value.dwControlsAccepted=state==SERVICE_RUNNING?(SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN):0;
    value.dwWin32ExitCode=error;
    if(state==SERVICE_START_PENDING || state==SERVICE_STOP_PENDING){value.dwCheckPoint=++checkpoint;value.dwWaitHint=5000;}
    SetServiceStatus(registration,&value);
}
void pending(){status(SERVICE_STOP_PENDING);}
DWORD WINAPI control(DWORD code,DWORD,void*,void*){
    if(code==SERVICE_CONTROL_STOP || code==SERVICE_CONTROL_SHUTDOWN){SetEvent(stopping);return NO_ERROR;}
    return code==SERVICE_CONTROL_INTERROGATE?NO_ERROR:ERROR_CALL_NOT_IMPLEMENTED;
}
void WINAPI service_main(DWORD,wchar_t**){
    registration=RegisterServiceCtrlHandlerExW(ServiceName,control,nullptr);if(!registration)return;
    status(SERVICE_START_PENDING);DWORD error=ERROR_GEN_FAILURE;
    try{
        require_system();const auto paths=remote::installed_cohort();
        const auto own=image();
        require(CompareStringOrdinal(own.c_str(),-1,(paths.root+L"\\GuardDeskService.exe").c_str(),-1,TRUE)==CSTR_EQUAL ||
            CompareStringOrdinal(own.c_str(),-1,(paths.root+L"\\_internal\\GuardDeskService.exe").c_str(),-1,TRUE)==CSTR_EQUAL);
        Handle pin(remote::pin_program_image(paths.broker));
        Handle stop(system_stop_event());stopping=stop.value;
        const auto command=L"\""+paths.broker+L"\" remote-service-worker --device-id "+did+
            L" --stop-handle "+std::to_wstring(reinterpret_cast<ULONG_PTR>(stop.value));
        status(SERVICE_RUNNING);
        error=child_lifetime(paths.broker,command,stop.value,pending);
        stopping=nullptr;
    }catch(...){error=ERROR_GEN_FAILURE;}
    status(SERVICE_STOPPED,error);
}
#endif
}

int wmain(int argc,wchar_t** argv){
#ifdef GUARDDESK_OWNED_SERVICE_TEST
    // Compiled into the separate test target only; absent from product EXE.
    if(argc==3 && std::wstring(argv[1])==L"--owned-child"){
        HANDLE stop=reinterpret_cast<HANDLE>(_wcstoui64(argv[2],nullptr,10));
        return WaitForSingleObject(stop,5000)==WAIT_OBJECT_0?0:13;
    }
    if(argc==2 && std::wstring(argv[1])==L"--owned-failure")return 27;
    if(argc==2 && std::wstring(argv[1])==L"--owned-stuck"){Sleep(60000);return 14;}
    if(argc==3 && std::wstring(argv[1])==L"--owned-detached"){
        Handle job(OpenJobObjectW(JOB_OBJECT_QUERY,FALSE,argv[2]));
        BOOL member=TRUE;return job.value && IsProcessInJob(GetCurrentProcess(),job.value,&member) && !member?0:19;
    }
    if(argc==3 && std::wstring(argv[1])==L"--owned-spawner"){
        Handle job(OpenJobObjectW(JOB_OBJECT_QUERY,FALSE,argv[2]));
        BOOL member=FALSE;if(!job.value || !IsProcessInJob(GetCurrentProcess(),job.value,&member) || !member)return 20;
        auto exe=image();auto command=L"\""+exe+L"\" --owned-detached "+argv[2];
        STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION p{};
        if(!CreateProcessW(exe.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&p))return 21;
        Handle process(p.hProcess),thread(p.hThread);
        if(WaitForSingleObject(process.value,5000)!=WAIT_OBJECT_0){TerminateProcess(process.value,22);WaitForSingleObject(process.value,5000);return 22;}
        DWORD result=23;GetExitCodeProcess(process.value,&result);return static_cast<int>(result);
    }
    if(argc!=1)return 2;
    try{
        require(device_id(L"ee5138c901b7ad6898b27c94"));require(!device_id(L"../bad"));
        Handle stop(CreateEventW(nullptr,TRUE,TRUE,nullptr));require(stop.value!=nullptr);
        const auto exe=image();const auto cmd=L"\""+exe+L"\" --owned-child "+std::to_wstring(reinterpret_cast<ULONG_PTR>(stop.value));
        require(child_lifetime(exe,cmd,stop.value,nullptr)==0);
        Handle idle(CreateEventW(nullptr,TRUE,FALSE,nullptr));require(idle.value!=nullptr);
        require(child_lifetime(exe,L"\""+exe+L"\" --owned-failure",idle.value,nullptr)==27);
        require(child_lifetime(exe,L"\""+exe+L"\" --owned-spawner",idle.value,nullptr)==0);
        require(child_lifetime(exe,L"\""+exe+L"\" --owned-stuck",stop.value,nullptr,1)==ERROR_TIMEOUT);
        std::cout<<"owned_service_lifetime=passed; SCM=not_tested; SYSTEM=not_tested\n";return 0;
    }catch(...){return 1;}
#else
    if(argc==2 && std::wstring(argv[1])==L"--component-info"){
        std::cout<<"{\"build_role\":\"remote-service-host\",\"protocol\":1,\"internal_trial\":true}\n";return 0;
    }
    if(argc!=3 || std::wstring(argv[1])!=L"--device-id" || !device_id(argv[2]))return ERROR_INVALID_PARAMETER;
    did=argv[2];SERVICE_TABLE_ENTRYW table[]{{const_cast<wchar_t*>(ServiceName),service_main},{nullptr,nullptr}};
    return StartServiceCtrlDispatcherW(table)?0:static_cast<int>(GetLastError());
#endif
}
