#include "media_entry_token.hpp"
#include <sddl.h>
#include <iostream>
namespace {
struct Handle{HANDLE value=nullptr;~Handle(){if(value)CloseHandle(value);}};
bool refused(HANDLE token){try{remote::require_media_token(token);return false;}catch(...){return true;}}
}
int main(){unsigned stage=0;try{
    stage=1;
    Handle original,restricted;remote::token_require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_ADJUST_DEFAULT,&original.value)!=FALSE);
    PSID ba=nullptr,low=nullptr;remote::token_require(ConvertStringSidToSidW(L"S-1-5-32-544",&ba)!=FALSE);
    struct Free{PSID value;~Free(){LocalFree(value);}} free_ba{ba};
    SID_AND_ATTRIBUTES deny{ba,0};remote::token_require(CreateRestrictedToken(original.value,DISABLE_MAX_PRIVILEGE,1,&deny,0,nullptr,0,nullptr,&restricted.value)!=FALSE);
    stage=2;remote::token_require(refused(original.value) && refused(restricted.value));
    remote::token_require(ConvertStringSidToSidW(L"S-1-16-4096",&low)!=FALSE);Free free_low{low};
    TOKEN_MANDATORY_LABEL label{{low,SE_GROUP_INTEGRITY}};
    stage=3;remote::token_require(SetTokenInformation(restricted.value,TokenIntegrityLevel,&label,sizeof(label)+GetLengthSid(low))!=FALSE);
    stage=4;remote::require_media_token(restricted.value);
    std::cout<<"{\"passed\":true,\"TokenHasRestrictions_checked\":true,\"LowIL_checked\":true,\"UIAccess_checked\":true,\"enabled_privileges_bounded\":true,\"BA_deny_only_checked\":true,\"process_launched\":false,\"process_token_changed\":false}\n";return 0;
}catch(...){std::cerr<<"{\"passed\":false,\"stage\":"<<stage<<",\"last_error\":"<<GetLastError()<<"}\n";return 1;}}
