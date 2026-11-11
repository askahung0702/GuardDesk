#include "kernel_trust.hpp"
#include <aclapi.h>
#include <sddl.h>
#include <stdexcept>
#include <string>

namespace remote {
namespace {
void require(bool okay,const char* reason){if(!okay)throw std::runtime_error(reason);}
std::wstring sid_text(PSID sid){
    LPWSTR text=nullptr;
    require(sid && IsValidSid(sid) && ConvertSidToStringSidW(sid,&text),"kernel_sid");
    try{std::wstring value(text);LocalFree(text);return value;}catch(...){LocalFree(text);throw;}
}
bool owner_trusted(const std::wstring& sid){return sid==L"S-1-5-18" || sid==L"S-1-5-32-544";}
bool writer_trusted(const std::wstring& sid){
    // Windows Task Scheduler is the SYSTEM broker's launch authority. Its
    // exact service SID appears on scheduled SYSTEM process objects (LAB01).
    // This is NOT a service-SID prefix rule, and is never an allowed owner.
    return owner_trusted(sid) || sid==L"S-1-5-80-4125092361-1567024937-842823819-2091237918-836075745";
}
}
void require_kernel_descriptor(PSECURITY_DESCRIPTOR descriptor,DWORD harmless){
    require(descriptor && IsValidSecurityDescriptor(descriptor),"kernel_descriptor");
    PSID owner=nullptr;BOOL defaulted=FALSE,present=FALSE;PACL dacl=nullptr;
    require(GetSecurityDescriptorOwner(descriptor,&owner,&defaulted),"kernel_owner_query");
    require(owner_trusted(sid_text(owner)),"kernel_owner_untrusted");
    require(GetSecurityDescriptorDacl(descriptor,&present,&dacl,&defaulted),"kernel_dacl_query");
    require(present && dacl && IsValidAcl(dacl),"kernel_dacl_required");
    for(DWORD i=0;i<dacl->AceCount;++i){
        void* raw=nullptr;require(GetAce(dacl,i,&raw)!=FALSE,"kernel_ace_query");
        const auto* header=static_cast<ACE_HEADER*>(raw);
        if(header->AceFlags&INHERIT_ONLY_ACE)continue;
        if(header->AceType==ACCESS_ALLOWED_ACE_TYPE){
            const auto* ace=static_cast<ACCESS_ALLOWED_ACE*>(raw);
            require(!(ace->Mask&~harmless) || writer_trusted(sid_text(const_cast<DWORD*>(&ace->SidStart))),"kernel_untrusted_rights");
        }else require(header->AceType==ACCESS_DENIED_ACE_TYPE,"kernel_ace_type");
    }
}
void require_query_only_kernel_trust(HANDLE object,DWORD harmless){
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    const DWORD result=GetSecurityInfo(object,SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,nullptr,nullptr,nullptr,nullptr,&descriptor);
    if(result!=ERROR_SUCCESS){if(descriptor)LocalFree(descriptor);throw std::runtime_error("kernel_security_query/win32="+std::to_string(result));}
    try{require_kernel_descriptor(descriptor,harmless);}catch(...){LocalFree(descriptor);throw;}
    LocalFree(descriptor);
}
}
