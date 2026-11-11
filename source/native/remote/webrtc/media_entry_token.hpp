#pragma once
#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <stdexcept>
#include <cstring>
namespace remote {
inline void token_require(bool value){if(!value)throw std::runtime_error("restricted_media_token_rejected");}
inline std::vector<std::uint8_t> token_information(HANDLE token,TOKEN_INFORMATION_CLASS kind){
    DWORD bytes=0;GetTokenInformation(token,kind,nullptr,0,&bytes);token_require(bytes>0 && bytes<=65536);
    std::vector<std::uint8_t> result(bytes);token_require(GetTokenInformation(token,kind,result.data(),bytes,&bytes)!=FALSE);return result;
}
inline void require_media_token(HANDLE token){
    DWORD value=0,bytes=0;
    for(auto kind:{TokenHasRestrictions,TokenElevation,TokenUIAccess}){
        token_require(GetTokenInformation(token,kind,&value,sizeof(value),&bytes)!=FALSE);
        token_require(kind==TokenHasRestrictions?value!=0:value==0);
    }
    auto label=token_information(token,TokenIntegrityLevel);auto* integrity=reinterpret_cast<TOKEN_MANDATORY_LABEL*>(&label.at(0));
    token_require(IsValidSid(integrity->Label.Sid)!=FALSE);
    token_require(*GetSidSubAuthority(integrity->Label.Sid,*GetSidSubAuthorityCount(integrity->Label.Sid)-1)<=SECURITY_MANDATORY_LOW_RID);
    auto privileges=token_information(token,TokenPrivileges);auto* list=reinterpret_cast<TOKEN_PRIVILEGES*>(&privileges.at(0));
    token_require(list->PrivilegeCount<=128 && offsetof(TOKEN_PRIVILEGES,Privileges)+std::size_t(list->PrivilegeCount)*sizeof(LUID_AND_ATTRIBUTES)<=privileges.size());
    LUID notify{};token_require(LookupPrivilegeValueW(nullptr,SE_CHANGE_NOTIFY_NAME,&notify)!=FALSE);
    for(DWORD i=0;i<list->PrivilegeCount;++i){LUID_AND_ATTRIBUTES entry{};
        // Count/stride checked above; memcpy avoids dropping the buffer bounds.
        std::memcpy(&entry,&privileges.at(offsetof(TOKEN_PRIVILEGES,Privileges)+std::size_t(i)*sizeof(entry)),sizeof(entry));
        token_require(!(entry.Attributes&SE_PRIVILEGE_ENABLED) || (entry.Luid.LowPart==notify.LowPart && entry.Luid.HighPart==notify.HighPart));
    }
    auto groups=token_information(token,TokenGroups);auto* group_list=reinterpret_cast<TOKEN_GROUPS*>(&groups.at(0));
    token_require(group_list->GroupCount<=1024 && offsetof(TOKEN_GROUPS,Groups)+std::size_t(group_list->GroupCount)*sizeof(SID_AND_ATTRIBUTES)<=groups.size());
    for(DWORD i=0;i<group_list->GroupCount;++i){SID_AND_ATTRIBUTES entry{};
        std::memcpy(&entry,&groups.at(offsetof(TOKEN_GROUPS,Groups)+std::size_t(i)*sizeof(entry)),sizeof(entry));
        if(IsWellKnownSid(entry.Sid,WinBuiltinAdministratorsSid))token_require((entry.Attributes&SE_GROUP_USE_FOR_DENY_ONLY) && !(entry.Attributes&SE_GROUP_ENABLED));
    }
}
}
