// GuardDesk metadata-only ETW collector. No driver, injection, file contents,
// command lines, registry startup, or changes to another product's session.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <deque>
#include <mutex>
#include <atomic>
#include <cstring>
#include <cwctype>
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"tdh.lib")

static const GUID FileGuid={0x90cbdc39,0x4a3e,0x11d1,{0x84,0xf4,0,0,0xf8,4,0x64,0xe3}};
static const GUID NormalGuid={0xe0c93cd2,0x438a,0x4ddc,{0x90,0x9c,0x58,0x60,0x50,0x21,0xb7,0xc4}};
static const GUID FixtureGuid={0x16b12dac,0x435f,0x422e,{0xa5,0x14,0xee,0x21,0x95,0x7b,0x19,0x52}};
static GUID OwnGuid=NormalGuid;
static const wchar_t *Session=L"GuardDesk-DocumentIO-v1";
static const wchar_t *Mutex=L"Global\\GuardDesk-DocumentIO-v1-Owner";
static bool fixtureMode=false;
struct Record {uint64_t time,offset,bytes;uint32_t pid,tid,op,status;uint64_t openId;wchar_t path[512];};
struct Pending {Record value;uint64_t stamp;};
struct Name {std::wstring path;uint64_t stamp,openId;uint32_t pid;};
static std::unordered_map<uint64_t,Name> names;
static std::unordered_map<uint64_t,Pending> pending;
static std::deque<Record> records;
static std::mutex queueLock;
static std::vector<std::wstring> roots;
static std::vector<std::wstring> exclusions;
static uint64_t nextOpenId=0;
static std::atomic<uint64_t> dropped(0),unknown(0),completed(0);
static std::atomic<uint64_t> mergedIo(0),coalescedOpens(0);
static std::unordered_map<std::wstring,uint64_t> recentOpens;
static std::deque<std::pair<std::wstring,uint64_t>> openOrder;
static std::atomic<DWORD> consumerResult(0);
static std::atomic<bool> stopping(false);
static TRACEHANDLE session=0,consumer=INVALID_PROCESSTRACE_HANDLE;
static HANDLE threadHandle=nullptr,ownership=nullptr;
struct Properties {EVENT_TRACE_PROPERTIES p;wchar_t name[80];};
static Properties properties() {
    Properties x={};x.p.Wnode.BufferSize=sizeof(x);x.p.Wnode.Guid=OwnGuid;
    x.p.Wnode.Flags=WNODE_FLAG_TRACED_GUID;x.p.Wnode.ClientContext=2;
    x.p.BufferSize=64;x.p.MinimumBuffers=8;x.p.MaximumBuffers=32;
    x.p.FlushTimer=1;x.p.LogFileMode=EVENT_TRACE_REAL_TIME_MODE|EVENT_TRACE_SYSTEM_LOGGER_MODE;
    x.p.EnableFlags=EVENT_TRACE_FLAG_DISK_FILE_IO|EVENT_TRACE_FLAG_FILE_IO|EVENT_TRACE_FLAG_FILE_IO_INIT;
    x.p.LoggerNameOffset=offsetof(Properties,name);wcscpy_s(x.name,Session);return x;
}
static bool field(EVENT_RECORD* e,const wchar_t* name,void* output,ULONG capacity,ULONG* actual=nullptr) {
    PROPERTY_DATA_DESCRIPTOR d={};d.PropertyName=(ULONGLONG)name;d.ArrayIndex=ULONG_MAX;
    ULONG size=0;
    if(TdhGetPropertySize(e,0,nullptr,1,&d,&size)!=ERROR_SUCCESS||size>capacity||!size)return false;
    if(TdhGetProperty(e,0,nullptr,1,&d,size,(PBYTE)output)!=ERROR_SUCCESS)return false;
    if(actual)*actual=size;return true;
}
static uint64_t number(EVENT_RECORD* e,const wchar_t* name) {uint64_t v=0;return field(e,name,&v,sizeof(v))?v:0;}
static bool excludedPath(const std::wstring& path,const std::wstring& rule) {
    const auto token=rule.find(L"{user}");
    size_t suffix=rule.size();
    if(token==std::wstring::npos) {
        if(path.size()<rule.size()||_wcsnicmp(path.c_str(),rule.c_str(),rule.size())!=0)return false;
    } else {
        if(path.size()<=token||_wcsnicmp(path.c_str(),rule.c_str(),token)!=0)return false;
        auto end=path.find(L'\\',token);if(end==std::wstring::npos||end==token)return false;
        const size_t rest=rule.size()-token-6;
        if(path.size()<end+rest||_wcsnicmp(path.c_str()+end,rule.c_str()+token+6,rest)!=0)return false;
        suffix=end+rest;
    }
    return path.size()==suffix||(path.size()>suffix&&path[suffix]==L'\\');
}
static bool scoped(const std::wstring& path) {
    for(const auto& rule:exclusions)if(excludedPath(path,rule))return false;
    for(const auto& root:roots)if(path.size()>root.size()&&_wcsnicmp(path.c_str(),root.c_str(),root.size())==0&&path[root.size()]=='\\')return true;
    return false;
}
static void issuer(EVENT_RECORD* e,Record& r) {
    r.time=e->EventHeader.TimeStamp.QuadPart;r.pid=e->EventHeader.ProcessId;
    r.tid=(uint32_t)number(e,L"TTID");
    if(r.pid==ULONG_MAX)r.pid=0;
    if(r.pid<=4&&r.tid) {
        HANDLE issuing=OpenThread(THREAD_QUERY_LIMITED_INFORMATION,FALSE,r.tid);
        if(issuing) {
            FILETIME created,exited,kernel,user;
            if(GetThreadTimes(issuing,&created,&exited,&kernel,&user)) {
                ULARGE_INTEGER born;born.LowPart=created.dwLowDateTime;born.HighPart=created.dwHighDateTime;
                if(born.QuadPart<=r.time)r.pid=GetProcessIdOfThread(issuing);
            }
            CloseHandle(issuing);
        }
    }
}
static void push(const Record& r) {
    std::lock_guard<std::mutex> lock(queueLock);
    if(r.op==64) {
        uint64_t now=GetTickCount64();
        while(!openOrder.empty()&&(now-openOrder.front().second>=1000||openOrder.size()>=2048)) {
            auto old=openOrder.front();openOrder.pop_front();auto it=recentOpens.find(old.first);
            if(it!=recentOpens.end()&&it->second==old.second)recentOpens.erase(it);
        }
        // Never merge distinct open instances here: close/reopen is meaningful.
        std::wstring key=std::to_wstring(r.pid)+L"|"+std::to_wstring(r.openId)+L"|"+r.path;
        for(auto& character:key)character=std::towlower(character);
        auto it=recentOpens.find(key);
        if(it!=recentOpens.end()&&now-it->second<1000){++coalescedOpens;return;}
        recentOpens[key]=now;openOrder.push_back({key,now});
    } else if(r.op==67||r.op==68) {
        // Combine only contiguous, completed ranges from the same open/thread.
        // This retains range evidence while avoiding one ring item per buffer.
        unsigned searched=0;
        for(auto it=records.rbegin();it!=records.rend()&&searched++<16;++it) {
            if(it->op==r.op&&it->pid==r.pid&&it->tid==r.tid&&it->openId==r.openId&&it->status==r.status&&
               it->offset<=UINT64_MAX-it->bytes&&it->offset+it->bytes==r.offset&&
               r.bytes<=UINT32_MAX&&it->bytes<=UINT32_MAX-r.bytes&&wcscmp(it->path,r.path)==0) {
                it->bytes+=r.bytes;++mergedIo;return;
            }
        }
    }
    if(records.size()>=2048){++dropped;return;}records.push_back(r);
}
static void callbackImpl(EVENT_RECORD* e) {
    if(!IsEqualGUID(e->EventHeader.ProviderId,FileGuid))return;
    const UCHAR op=e->EventHeader.EventDescriptor.Opcode;
    Record actor={};
    if(op==64||op==67||op==68) {
        issuer(e,actor);
        if(!fixtureMode&&actor.pid==GetCurrentProcessId())return;
    }
    // All schemas are queried through TDH. Unknown/malformed fields fail closed.
    if(op==66){
        auto it=names.find(number(e,L"FileObject"));
        if(it!=names.end()&&it->second.pid>4&&(fixtureMode||it->second.pid!=GetCurrentProcessId())){
            Record r={};r.time=e->EventHeader.TimeStamp.QuadPart;r.op=66;r.openId=it->second.openId;r.pid=it->second.pid;
            wcsncpy_s(r.path,it->second.path.c_str(),_TRUNCATE);push(r);
        }
        names.erase(number(e,L"FileObject"));
        return;
    }
    if(op==0||op==32||op==35||op==36||op==64) {
        uint64_t key=number(e,L"FileObject");wchar_t path[512]={};ULONG n=0;
        if(!key||!field(e,op==64?L"OpenPath":L"FileName",path,sizeof(path)-2,&n)) {++unknown;return;}
        if(op==35){names.erase(key);return;}
        std::wstring value(path,n/2);auto zero=value.find(L'\0');if(zero!=std::wstring::npos)value.resize(zero);
        if(!scoped(value)){names.erase(key);return;}
        if(names.size()>=8192){names.clear();pending.clear();++dropped;}
        auto previous=names.find(key);
        uint64_t openId=(op==64||previous==names.end())?++nextOpenId:previous->second.openId;
        names[key]={value,GetTickCount64(),openId,op==64?actor.pid:(previous==names.end()?0:previous->second.pid)};
        if(op==64) {
            uint32_t options=0,attributes=0;
            // Directory opens and unknown schemas never become file opens.
            if(!field(e,L"CreateOptions",&options,sizeof(options))||!field(e,L"FileAttributes",&attributes,sizeof(attributes))){names[key].pid=0;++unknown;return;}
            if((options&1)||(attributes&FILE_ATTRIBUTE_DIRECTORY)){names[key].pid=0;return;}
            uint64_t irp=number(e,L"IrpPtr");if(!irp){++unknown;return;}
            Record r=actor;r.op=64;r.bytes=(options&0x40)?1:0;r.openId=openId;wcsncpy_s(r.path,value.c_str(),_TRUNCATE);
            if(pending.size()>=4096){pending.clear();++dropped;}
            pending[irp]={r,GetTickCount64()};
        }
        return;
    }
    if(op==67||op==68) {
        // FileKey identifies shared file metadata; FileObject identifies this
        // open. Prefer the latter so open/read dedup never joins another open.
        uint64_t key=number(e,L"FileObject");auto it=names.find(key);
        if(it==names.end())it=names.find(number(e,L"FileKey"));
        if(it==names.end())return;
        if(!it->second.pid)it->second.pid=actor.pid;
        uint64_t irp=number(e,L"IrpPtr");if(!irp){++unknown;return;}
        Record r=actor;r.offset=number(e,L"Offset");r.bytes=number(e,L"IoSize");r.op=op;
        r.openId=it->second.openId;
        wcsncpy_s(r.path,it->second.path.c_str(),_TRUNCATE);
        if(pending.size()>=4096){pending.clear();++dropped;}
        pending[irp]={r,GetTickCount64()};return;
    }
    if(op==76) {
        uint64_t irp=number(e,L"IrpPtr");auto it=pending.find(irp);if(it==pending.end())return;
        Record r=it->second.value;uint64_t age=GetTickCount64()-it->second.stamp;pending.erase(it);
        uint32_t status=0;if(!field(e,L"NtStatus",&status,sizeof(status))||age>10000){++unknown;return;}
        r.status=status;
        uint64_t extra=0;if(!field(e,L"ExtraInfo",&extra,sizeof(extra))){++unknown;return;}
        if(r.op==64) {
            // FILE_OPENED=1: an existing path opened successfully. This is not
            // evidence of ReadData, human viewing, or website transmission.
            if((int32_t)status>=0&&extra==1){push(r);++completed;}
            return;
        }
        r.bytes=extra;
        if((int32_t)r.status>=0&&r.bytes){push(r);++completed;}
    }
}
static void WINAPI callback(EVENT_RECORD* e) {try{callbackImpl(e);}catch(...){++dropped;}}
static ULONG WINAPI bufferCallback(EVENT_TRACE_LOGFILEW* e){if(e->EventsLost)dropped+=e->EventsLost;return TRUE;}
static DWORD WINAPI consume(void*) {SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_BELOW_NORMAL);DWORD code=ProcessTrace(&consumer,1,nullptr,nullptr);consumerResult=(code||stopping)?code:ERROR_OPERATION_ABORTED;return 0;}
extern "C" __declspec(dllexport) DWORD gd_trace_record_size(){return sizeof(Record);}
extern "C" __declspec(dllexport) DWORD gd_trace_lifecycle_version(){return 1;}
static DWORD startFiltered(const wchar_t* const* selected,DWORD count,const wchar_t* const* rejected,DWORD rejectedCount) {
    if(threadHandle||!count||count>26||rejectedCount>128||(!selected)||(!rejected&&rejectedCount))return ERROR_INVALID_PARAMETER;
    roots.clear();exclusions.clear();names.clear();pending.clear();records.clear();recentOpens.clear();openOrder.clear();mergedIo=0;coalescedOpens=0;dropped=0;unknown=0;completed=0;consumerResult=0;stopping=false;nextOpenId=0;
    for(DWORD i=0;i<count;++i){if(!selected[i]||wcslen(selected[i])<8||wcslen(selected[i])>450)return ERROR_INVALID_PARAMETER;roots.push_back(selected[i]);}
    for(DWORD i=0;i<rejectedCount;++i){if(!rejected[i]||wcslen(rejected[i])<8||wcslen(rejected[i])>510)return ERROR_INVALID_PARAMETER;exclusions.push_back(rejected[i]);}
    ownership=CreateMutexW(nullptr,FALSE,Mutex);
    if(!ownership)return GetLastError();
    if(GetLastError()==ERROR_ALREADY_EXISTS){CloseHandle(ownership);ownership=nullptr;return ERROR_ALREADY_EXISTS;}
    Properties p=properties();DWORD code=StartTraceW(&session,Session,&p.p);
    if(code==ERROR_ALREADY_EXISTS) {
        // A crashed controller can leave its ETW session. Mutex absence plus
        // exact own GUID permits recovery; another GUID is never stopped.
        Properties old=properties();DWORD q=ControlTraceW(0,Session,&old.p,EVENT_TRACE_CONTROL_QUERY);
        if(q==ERROR_SUCCESS&&IsEqualGUID(old.p.Wnode.Guid,OwnGuid)) {
            ControlTraceW(0,Session,&old.p,EVENT_TRACE_CONTROL_STOP);p=properties();code=StartTraceW(&session,Session,&p.p);
        }
    }
    if(code!=ERROR_SUCCESS){CloseHandle(ownership);ownership=nullptr;session=0;return code;}
    EVENT_TRACE_LOGFILEW log={};log.LoggerName=(LPWSTR)Session;log.ProcessTraceMode=PROCESS_TRACE_MODE_REAL_TIME|PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback=callback;log.BufferCallback=bufferCallback;consumer=OpenTraceW(&log);
    if(consumer==INVALID_PROCESSTRACE_HANDLE){code=GetLastError();ControlTraceW(session,Session,&p.p,EVENT_TRACE_CONTROL_STOP);session=0;CloseHandle(ownership);ownership=nullptr;return code;}
    threadHandle=CreateThread(nullptr,0,consume,nullptr,0,nullptr);
    if(!threadHandle){code=GetLastError();CloseTrace(consumer);consumer=INVALID_PROCESSTRACE_HANDLE;ControlTraceW(session,Session,&p.p,EVENT_TRACE_CONTROL_STOP);session=0;CloseHandle(ownership);ownership=nullptr;return code;}
    return ERROR_SUCCESS;
}
extern "C" __declspec(dllexport) DWORD gd_trace_start_filtered(const wchar_t* const* selected,DWORD count,const wchar_t* const* rejected,DWORD rejectedCount) {
    if(threadHandle||session)return ERROR_ALREADY_EXISTS;
    fixtureMode=false;OwnGuid=NormalGuid;Session=L"GuardDesk-DocumentIO-v1";Mutex=L"Global\\GuardDesk-DocumentIO-v1-Owner";
    return startFiltered(selected,count,rejected,rejectedCount);
}
// Local administrator fixture entry only, no IPC or additional privilege.
// Fixed separate GUID/name prevents acceptance tests stopping the live Agent.
extern "C" __declspec(dllexport) DWORD gd_trace_start_fixture_filtered(const wchar_t* const* selected,DWORD count,const wchar_t* const* rejected,DWORD rejectedCount) {
    if(threadHandle||session)return ERROR_ALREADY_EXISTS;
    fixtureMode=true;OwnGuid=FixtureGuid;Session=L"GuardDesk-DocumentIO-Fixture-v1";Mutex=L"Global\\GuardDesk-DocumentIO-Fixture-v1-Owner";
    return startFiltered(selected,count,rejected,rejectedCount);
}
extern "C" __declspec(dllexport) DWORD gd_trace_start(const wchar_t* const* selected,DWORD count) {
    return gd_trace_start_filtered(selected,count,nullptr,0);
}
extern "C" __declspec(dllexport) DWORD gd_trace_poll(Record* output,DWORD capacity,uint64_t* stats) {
    if(!output||capacity>256||!stats)return ULONG_MAX;
    std::lock_guard<std::mutex> lock(queueLock);DWORD n=0;
    while(n<capacity&&!records.empty()){output[n++]=records.front();records.pop_front();}
    stats[0]=dropped;stats[1]=unknown;stats[2]=completed;stats[3]=consumerResult;return n;
}
extern "C" __declspec(dllexport) DWORD gd_trace_aux_stats(uint64_t* stats,DWORD capacity) {
    if(!stats||capacity!=2)return ERROR_INVALID_PARAMETER;
    stats[0]=mergedIo;stats[1]=coalescedOpens;return ERROR_SUCCESS;
}
extern "C" __declspec(dllexport) DWORD gd_trace_stop() {
    if(!session)return ERROR_SUCCESS;
    stopping=true;
    Properties p=properties();DWORD code=ControlTraceW(session,Session,&p.p,EVENT_TRACE_CONTROL_QUERY);
    if(code==ERROR_SUCCESS) {
        if(IsEqualGUID(p.p.Wnode.Guid,OwnGuid))code=ControlTraceW(session,Session,&p.p,EVENT_TRACE_CONTROL_STOP);
        else code=ERROR_ACCESS_DENIED;
    }
    if(consumer!=INVALID_PROCESSTRACE_HANDLE)CloseTrace(consumer);
    // Never unload DLL while its callback thread is running.
    if(threadHandle&&WaitForSingleObject(threadHandle,5000)!=WAIT_OBJECT_0)return WAIT_TIMEOUT;
    if(threadHandle)CloseHandle(threadHandle);threadHandle=nullptr;consumer=INVALID_PROCESSTRACE_HANDLE;session=0;
    if(ownership)CloseHandle(ownership);ownership=nullptr;return code;
}
BOOL WINAPI DllMain(HINSTANCE,DWORD,LPVOID){return TRUE;}
