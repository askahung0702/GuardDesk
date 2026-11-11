#pragma once
#include "webrtc/media_entry_token.hpp"
#include <sddl.h>
#include <string>

namespace remote {
// Only the low-integrity media token's future runtime objects use this DACL.
// Broker-created process/thread/IPC/frame objects retain their separate SYSTEM
// descriptors. No right is added to an existing object or installed file.
inline void set_user_runtime_defaults(HANDLE token,const std::wstring& user_sid){
    TOKEN_TYPE type{};DWORD bytes=0;
    token_require(GetTokenInformation(token,TokenType,&type,sizeof(type),&bytes)!=FALSE && type==TokenPrimary);
    auto data=token_information(token,TokenUser);
    auto* user=reinterpret_cast<TOKEN_USER*>(data.data());
    LPWSTR text=nullptr;
    token_require(ConvertSidToStringSidW(user->User.Sid,&text)!=FALSE);
    const std::wstring actual(text);LocalFree(text);
    token_require(actual==user_sid && actual!=L"S-1-5-18");
    const auto sddl=L"D:P(A;;GA;;;SY)(A;;GA;;;"+actual+L")(A;;RC;;;OW)";
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    token_require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr)!=FALSE);
    struct Free {PSECURITY_DESCRIPTOR value;~Free(){LocalFree(value);}} cleanup{descriptor};
    PACL dacl=nullptr;BOOL present=FALSE,defaulted=FALSE;
    token_require(GetSecurityDescriptorDacl(descriptor,&present,&dacl,&defaulted)!=FALSE && present && dacl);
    TOKEN_DEFAULT_DACL defaults{dacl};
    token_require(SetTokenInformation(token,TokenDefaultDacl,&defaults,sizeof(defaults))!=FALSE);
}
inline void set_media_runtime_defaults(HANDLE token,const std::wstring& user_sid){
    require_media_token(token);
    set_user_runtime_defaults(token,user_sid);
}
}
