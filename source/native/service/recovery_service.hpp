#pragma once
#include "recovery_store.hpp"
#include <winsvc.h>

namespace service_recovery {
// Fixed installed service only. Disabled is an OS-enforced barrier that old111
// also respects: its adapter rejects non-Auto before stop/switch/start rollback.
class ServiceControl {
    SC_HANDLE manager_=nullptr,service_=nullptr;
    std::wstring image_,device_;
    static bool trusted(PSID sid){return sid && (IsWellKnownSid(sid,WinLocalSystemSid) || IsWellKnownSid(sid,WinBuiltinAdministratorsSid));}
    void protection(){
        DWORD size=0;QueryServiceObjectSecurity(service_,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,nullptr,0,&size);
        check(size && size<=65536);std::vector<BYTE> data(size);
        check(QueryServiceObjectSecurity(service_,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,data.data(),size,&size)!=FALSE);
        PSID owner=nullptr;BOOL defaulted=FALSE,present=FALSE;PACL dacl=nullptr;
        check(GetSecurityDescriptorOwner(data.data(),&owner,&defaulted) && trusted(owner));
        check(GetSecurityDescriptorDacl(data.data(),&present,&dacl,&defaulted) && present && dacl);
        for(DWORD i=0;i<dacl->AceCount;++i){void* raw=nullptr;check(GetAce(dacl,i,&raw)!=FALSE);
            const auto* header=static_cast<ACE_HEADER*>(raw);
            if(header->AceType==ACCESS_DENIED_ACE_TYPE)continue;
            check(header->AceType==ACCESS_ALLOWED_ACE_TYPE);
            const auto* ace=static_cast<ACCESS_ALLOWED_ACE*>(raw);
            check(!(ace->Mask&~0x2008du) || trusted(const_cast<DWORD*>(&ace->SidStart)));
        }
    }
public:
    ServiceControl(const std::wstring& executable,const std::wstring& did,bool change=true):image_(executable),device_(did){
        try{
            manager_=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);check(manager_!=nullptr);
            service_=OpenServiceW(manager_,L"GuardDeskRemote",READ_CONTROL|SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS|(change?SERVICE_CHANGE_CONFIG:0));
            check(service_!=nullptr);protection();start_type();
        }catch(...){close();throw;}
    }
    ~ServiceControl(){close();}
    ServiceControl(const ServiceControl&)=delete;ServiceControl& operator=(const ServiceControl&)=delete;
    void close(){if(service_){CloseServiceHandle(service_);service_=nullptr;}if(manager_){CloseServiceHandle(manager_);manager_=nullptr;}}
    DWORD start_type(){
        protection();DWORD size=0;QueryServiceConfigW(service_,nullptr,0,&size);check(size && size<=65536);
        std::vector<BYTE> data(size);auto* cfg=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(data.data());
        check(QueryServiceConfigW(service_,cfg,size,&size)!=FALSE);
        check(cfg->dwServiceType==SERVICE_WIN32_OWN_PROCESS &&
            (cfg->dwStartType==SERVICE_AUTO_START || cfg->dwStartType==SERVICE_DISABLED) &&
            cfg->lpServiceStartName && std::wstring(cfg->lpServiceStartName)==L"LocalSystem" &&
            (!cfg->lpDependencies || !*cfg->lpDependencies) && (!cfg->lpLoadOrderGroup || !*cfg->lpLoadOrderGroup));
        const auto quoted=L"\""+image_+L"\" --device-id "+device_;
        const auto plain=image_+L" --device-id "+device_;
        check(cfg->lpBinaryPathName && (CompareStringOrdinal(cfg->lpBinaryPathName,-1,quoted.c_str(),-1,TRUE)==CSTR_EQUAL ||
            (image_.find_first_of(L" \t")==std::wstring::npos && CompareStringOrdinal(cfg->lpBinaryPathName,-1,plain.c_str(),-1,TRUE)==CSTR_EQUAL)));
        return cfg->dwStartType;
    }
    DWORD state(){SERVICE_STATUS_PROCESS value{};DWORD size=0;
        check(QueryServiceStatusEx(service_,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&value),sizeof(value),&size)!=FALSE);return value.dwCurrentState;}
    void require_stopped(){start_type();if(state()!=SERVICE_STOPPED)throw std::runtime_error("service_must_be_stopped");}
    void set_start(DWORD value){
        if(start_type()!=value)check(ChangeServiceConfigW(service_,SERVICE_NO_CHANGE,value,SERVICE_NO_CHANGE,
            nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr)!=FALSE);
        check(start_type()==value);
    }
    void disable(){set_start(SERVICE_DISABLED);}
    void automatic(){require_stopped();set_start(SERVICE_AUTO_START);}
};

inline bool administrator(){
    SID_IDENTIFIER_AUTHORITY authority=SECURITY_NT_AUTHORITY;PSID sid=nullptr;BOOL member=FALSE;
    check(AllocateAndInitializeSid(&authority,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&sid)!=FALSE);
    const BOOL okay=CheckTokenMembership(nullptr,sid,&member);FreeSid(sid);check(okay!=FALSE);return member!=FALSE;
}

// The same transaction is exercised with owned state and a fake SCM gate.
// No automatic StartService, no arbitrary service name, and no ambient force flag.
template<class State,class Gate>
void reviewed_reset(State& state,Gate& gate,bool security_reviewed){
    gate.require_stopped();
    gate.disable(); // Keep old versions unable to run even when review is refused.
    state.require_review(security_reviewed);
    state.reset_after_review(security_reviewed);
    gate.automatic(); // Permission to start; this operation does not start it.
}
}
