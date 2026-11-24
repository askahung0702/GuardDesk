// Fixed-purpose SCM host. No arbitrary executable, shell, network or desktop API.
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <thread>
#include <mutex>
#include "../remote/cohort.hpp"
#include "recovery_store.hpp"
#include "recovery_runtime.hpp"
#include "recovery_service.hpp"
#include "recovery_probe.hpp"
#include "recovery_maintenance_probe.hpp"

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
SERVICE_STATUS_HANDLE registration=nullptr;HANDLE stopping=nullptr;std::wstring did;std::mutex stopping_mutex;
struct PublishedStop {
    explicit PublishedStop(HANDLE event){std::lock_guard<std::mutex> lock(stopping_mutex);stopping=event;}
    ~PublishedStop(){std::lock_guard<std::mutex> lock(stopping_mutex);stopping=nullptr;}
};
DWORD checkpoint=0;
void status(DWORD state,DWORD error=0){
    SERVICE_STATUS value{};value.dwServiceType=SERVICE_WIN32_OWN_PROCESS;value.dwCurrentState=state;
    value.dwControlsAccepted=state==SERVICE_RUNNING?(SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN):0;
    value.dwWin32ExitCode=error;
    if(state==SERVICE_START_PENDING || state==SERVICE_STOP_PENDING){value.dwCheckPoint=++checkpoint;value.dwWaitHint=5000;}
    SetServiceStatus(registration,&value);
}
void pending(){status(SERVICE_STOP_PENDING);}
int maintenance(const std::wstring& device,bool reset,bool security_reviewed){
    try{
        if(!service_recovery::administrator()){
            std::cout<<"{\"available\":false,\"error\":\"administrator_required\",\"service_started\":false}\n";return ERROR_ELEVATION_REQUIRED;}
        const auto paths=remote::installed_cohort();const auto own=image();
        require(CompareStringOrdinal(own.c_str(),-1,(paths.root+L"\\GuardDeskService.exe").c_str(),-1,TRUE)==CSTR_EQUAL ||
            CompareStringOrdinal(own.c_str(),-1,(paths.root+L"\\_internal\\GuardDeskService.exe").c_str(),-1,TRUE)==CSTR_EQUAL);
        Handle pin(remote::pin_program_image(paths.broker));
        service_recovery::ServiceControl gate(own,device,reset);
        if(reset)gate.require_stopped();
        service_recovery::Store state(device,!reset);
        if(reset)service_recovery::reviewed_reset(state,gate,security_reviewed);
        const bool marker=state.security_marker();
        const auto& r=state.record;
        std::cout<<"{\"available\":true,\"phase\":"<<r.phase<<",\"hold\":"<<r.hold
            <<",\"attempts\":"<<r.attempts<<",\"first_error\":"<<r.first_error<<",\"last_error\":"<<r.last_error
            <<",\"updated_ms\":"<<r.updated<<",\"security_marker\":"<<(marker?"true":"false")
            <<",\"service_disabled\":"<<(gate.start_type()==SERVICE_DISABLED?"true":"false")
            <<",\"reset_completed\":"<<(reset?"true":"false")<<",\"service_started\":false}\n";
        return 0;
    }catch(const std::exception& error){
        const std::string reason=error.what();
        const auto fixed=(reason=="security_review_required" || reason=="service_must_be_stopped" || reason=="review_archive_limit" || reason=="clock_review_required")?reason:"unavailable_or_untrusted";
        std::cout<<"{\"available\":false,\"error\":\""<<fixed<<"\",\"service_started\":false}\n";return ERROR_GEN_FAILURE;
    }
}
DWORD WINAPI control(DWORD code,DWORD,void*,void*){
    if(code==SERVICE_CONTROL_STOP || code==SERVICE_CONTROL_SHUTDOWN){
        std::lock_guard<std::mutex> lock(stopping_mutex);if(stopping)SetEvent(stopping);return NO_ERROR;}
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
        service_recovery::ServiceControl gate(own,did);
        try{
            Handle pin(remote::pin_program_image(paths.broker));
            Handle stop(system_stop_event());PublishedStop published(stop.value);
            const auto command=L"\""+paths.broker+L"\" remote-service-worker --device-id "+did+
                L" --stop-handle "+std::to_wstring(reinterpret_cast<ULONG_PTR>(stop.value));
            service_recovery::Store recovery(did);
            status(SERVICE_RUNNING);
            error=service_recovery::supervise(recovery,
                [&]{return child_lifetime(paths.broker,command,stop.value,pending);},
                [&](DWORD delay){const DWORD result=WaitForSingleObject(stop.value,delay);
                    require(result==WAIT_OBJECT_0 || result==WAIT_TIMEOUT);return result==WAIT_OBJECT_0;},
                service_recovery::now,[&]{return WaitForSingleObject(stop.value,0)==WAIT_OBJECT_0;});
            // Check the marker even when SCM stop won the worker-exit race.
            if(recovery.security_marker() || recovery.record.hold!=service_recovery::none)gate.disable();
        }catch(...){gate.disable();throw;}
    }catch(...){error=ERROR_GEN_FAILURE;}
    status(SERVICE_STOPPED,error);
}
#endif
}

int wmain(int argc,wchar_t** argv){
#ifdef GUARDDESK_OWNED_SERVICE_TEST
    // Compiled into the separate test target only; absent from product EXE.
    if(argc==2 && std::wstring(argv[1])==L"--owned-zero")return 0;
    if(argc==2 && std::wstring(argv[1])==L"--owned-recovery-process"){
        try{
            using namespace service_recovery;
            struct State {Record record;void save(){record.checksum=checksum(record);}bool security_marker(){return false;}} state;
            state.record.window_start=state.record.updated=now();unsigned launches=0;std::vector<DWORD> waits;
            Handle stop(CreateEventW(nullptr,TRUE,FALSE,nullptr));require(stop.value!=nullptr);const auto exe=image();
            const auto result=supervise(state,[&]{++launches;return child_lifetime(exe,L"\""+exe+(launches<3?L"\" --owned-failure":L"\" --owned-zero"),stop.value,nullptr);},
                [&](DWORD delay){waits.push_back(delay);return WaitForSingleObject(stop.value,1)==WAIT_OBJECT_0;},
                now,[&]{return WaitForSingleObject(stop.value,0)==WAIT_OBJECT_0;});
            require(result==0 && launches==3 && waits==std::vector<DWORD>{30000,60000});
            State canceled;canceled.record.window_start=canceled.record.updated=now();unsigned canceled_launches=0;
            Handle entered(CreateEventW(nullptr,TRUE,FALSE,nullptr));require(entered.value!=nullptr);
            bool wait_observed=false;unsigned canceled_waits=0;
            std::thread signaler([&]{wait_observed=WaitForSingleObject(entered.value,3000)==WAIT_OBJECT_0;SetEvent(stop.value);});const auto start=GetTickCount64();
            const auto cancellation=supervise(canceled,[&]{++canceled_launches;return child_lifetime(exe,L"\""+exe+L"\" --owned-failure",stop.value,nullptr);},
                [&](DWORD delay){++canceled_waits;SetEvent(entered.value);return WaitForSingleObject(stop.value,delay)==WAIT_OBJECT_0;},now,
                [&]{return WaitForSingleObject(stop.value,0)==WAIT_OBJECT_0;});
            signaler.join();require(cancellation==0 && wait_observed && canceled_launches==1 && canceled_waits==1 && GetTickCount64()-start<3000);
            std::cout<<"owned_recovery_process=passed; cases=2; retry_waits_scaled_only_in_owned_probe; SCM=not_tested\n";return 0;
        }catch(...){return 1;}
    }
    if(argc==3 && std::wstring(argv[1])==L"--owned-recovery-store")return recovery_store_probe(argv[2]);
    if(argc==3 && std::wstring(argv[1])==L"--owned-recovery-maintenance")return recovery_maintenance_probe(argv[2]);
    if(argc==2 && std::wstring(argv[1])==L"--owned-recover"){
        try{
            using namespace service_recovery;
            struct State {
                Record record;unsigned writes=0;bool blocked=false;
                void save(){++writes;record.checksum=checksum(record);}
                bool security_marker(){return blocked;}
            } state;
            std::uint64_t tick=1000;state.record.window_start=state.record.updated=tick;
            unsigned launches=0;std::vector<DWORD> waits;bool stopping=false;
            const auto result=supervise(state,[&]()->DWORD{++launches;return 0xc0000005u;},
                [&](DWORD delay){waits.push_back(delay);tick+=delay;return false;},[&]{return tick;},[&]{return stopping;});
            require(result==0xc0000005u && launches==4 && waits==std::vector<DWORD>{30000,60000,300000});
            require(state.record.hold==exhausted && state.record.first_error==0xc0000005u);
            // A persisted exhausted state must not launch again after host restart.
            require(supervise(state,[&]()->DWORD{++launches;return 0;},[](DWORD){return false;},[&]{return tick;},[]{return false;})==ERROR_ACCESS_DISABLED_BY_POLICY && launches==4);
            State cancel;cancel.record.window_start=cancel.record.updated=tick;unsigned canceled_launches=0;
            require(supervise(cancel,[&]()->DWORD{++canceled_launches;return 27;},[&](DWORD){stopping=true;return true;},[&]{return tick;},[&]{return stopping;})==0);
            require(canceled_launches==1 && cancel.record.phase==idle && cancel.record.attempts==1);
            State stopped_av;stopped_av.record.window_start=stopped_av.record.updated=tick;bool av_stop=false;
            require(supervise(stopped_av,[&]()->DWORD{av_stop=true;return 1260;},[](DWORD){return false;},[&]{return tick;},[&]{return av_stop;})==0);
            require(stopped_av.record.hold==security && stopped_av.record.last_error==1260);
            State healthy;healthy.record.window_start=healthy.record.updated=tick;unsigned recovered=0;
            require(supervise(healthy,[&]()->DWORD{return ++recovered==1?27u:0u;},[](DWORD){return false;},[&]{return tick;},[]{return false;})==0 && recovered==2 && healthy.record.phase==idle);
            State blocked;blocked.record.window_start=blocked.record.updated=tick;unsigned rejected=0;
            require(supervise(blocked,[&]()->DWORD{++rejected;return 225;},[](DWORD){return false;},[&]{return tick;},[]{return false;})==225);
            require(rejected==1 && blocked.record.hold==security && blocked.record.attempts==0);
            State policy;policy.record.window_start=policy.record.updated=tick;
            require(failure(policy.record,577,tick)==0 && policy.record.hold==review && policy.record.attempts==0);
            State zero;zero.record.window_start=zero.record.updated=tick;unsigned completed=0;
            unsigned zero_waits=0;
            require(supervise(zero,[&]()->DWORD{++completed;return 0;},[&](DWORD){++zero_waits;return false;},[&]{return tick;},[]{return false;})==0 && completed==1 && zero_waits==0);
            State past;past.record.window_start=past.record.updated=tick;unsigned clock_launches=0;
            require(supervise(past,[&]()->DWORD{++clock_launches;return 0;},[](DWORD){return false;},[&]{return tick-1;},[]{return false;})==ERROR_TIME_SKEW && clock_launches==0 && past.record.hold==review);
            State prior;prior.record.window_start=prior.record.updated=tick;prior.record.phase=active;
            unsigned prior_launches=0;std::vector<DWORD> prior_waits;
            require(supervise(prior,[&]()->DWORD{++prior_launches;return 0;},[&](DWORD d){prior_waits.push_back(d);return false;},[&]{return tick;},[]{return false;})==0 && prior_launches==1 && prior_waits==std::vector<DWORD>{30000});
            State transient;transient.record.window_start=transient.record.updated=tick;transient.record.attempts=2;
            transient.record.retry_at={tick,tick,0};
            require(failure(transient.record,27,tick+Day)==30000 && transient.record.attempts==1);
            require(failure(state.record,27,tick+Day)==0 && state.record.hold==exhausted);
            State rolling;rolling.record.window_start=rolling.record.updated=tick;
            require(failure(rolling.record,27,tick)==30000);
            require(failure(rolling.record,27,tick+Day/2)==60000);
            require(failure(rolling.record,27,tick+Day-1000)==300000);
            require(failure(rolling.record,27,tick+Day)==300000 && rolling.record.attempts==3);
            require(failure(rolling.record,27,tick+Day+1000)==0 && rolling.record.hold==exhausted);
            std::cout<<"owned_recovery_policy=passed; SCM=not_tested; SYSTEM=not_tested\n";return 0;
        }catch(...){return 1;}
    }
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
    if(argc==2 && std::wstring(argv[1])==L"--recovery-help"){
        std::cout<<"{\"status\":\"--recovery-status --device-id DID\",\"reset\":\"--recovery-reset --device-id DID --review fault|security\",\"admin_required\":true,\"stopped_required_for_reset\":true,\"automatic_start\":false}\n";return 0;
    }
    if(argc==4 && std::wstring(argv[1])==L"--recovery-status" && std::wstring(argv[2])==L"--device-id" && device_id(argv[3]))
        return maintenance(argv[3],false,false);
    if(argc==6 && std::wstring(argv[1])==L"--recovery-reset" && std::wstring(argv[2])==L"--device-id" && device_id(argv[3]) &&
       std::wstring(argv[4])==L"--review" && (std::wstring(argv[5])==L"fault" || std::wstring(argv[5])==L"security"))
        return maintenance(argv[3],true,std::wstring(argv[5])==L"security");
    if(argc==2 && std::wstring(argv[1])==L"--component-info"){
        std::cout<<"{\"build_role\":\"remote-service-host\",\"protocol\":1,\"internal_trial\":true,\"worker_recovery\":1,\"recovery_maintenance\":1,\"rollback_guard\":\"service-disabled-v1\"}\n";return 0;
    }
    if(argc!=3 || std::wstring(argv[1])!=L"--device-id" || !device_id(argv[2]))return ERROR_INVALID_PARAMETER;
    did=argv[2];SERVICE_TABLE_ENTRYW table[]{{const_cast<wchar_t*>(ServiceName),service_main},{nullptr,nullptr}};
    return StartServiceCtrlDispatcherW(table)?0:static_cast<int>(GetLastError());
#endif
}
