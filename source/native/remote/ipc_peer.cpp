#include "ipc_peer.hpp"
#include <aclapi.h>
#include <sddl.h>
#include <stdexcept>
#include <utility>
#include <vector>
#include <cstring>

namespace remote::ipc {
namespace {
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
std::wstring sid_text(PSID sid){
    check(sid && IsValidSid(sid),"invalid_sid");LPWSTR text=nullptr;
    check(ConvertSidToStringSidW(sid,&text)!=FALSE,"sid_conversion_failed");
    try{std::wstring value(text);LocalFree(text);return value;}catch(...){LocalFree(text);throw;}
}
std::uint64_t stamp(FILETIME time){return (std::uint64_t(time.dwHighDateTime)<<32)|time.dwLowDateTime;}
bool same_path(const std::wstring& a,const std::wstring& b){
    return !a.empty() && !b.empty() && a.size()<=32767 && b.size()<=32767 &&
        CompareStringOrdinal(a.data(),static_cast<int>(a.size()),b.data(),static_cast<int>(b.size()),TRUE)==CSTR_EQUAL;
}
}
Peer::Peer(DWORD pid){
    check(pid!=0,"invalid_peer_pid");
    if(pid==GetCurrentProcessId()){
        check(DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),GetCurrentProcess(),&handle_,PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,0)!=FALSE,"peer_self_duplicate");
    }else handle_=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);
    check(handle_!=nullptr,"peer_open_failed");
    HANDLE token=nullptr;
    try{
        require_alive();identity_.pid=GetProcessId(handle_);check(identity_.pid==pid,"peer_pid_changed");
        check(OpenProcessToken(handle_,TOKEN_QUERY,&token)!=FALSE,"peer_token_failed");
        snapshot(token);CloseHandle(token);token=nullptr;
    }catch(...){if(token)CloseHandle(token);CloseHandle(handle_);handle_=nullptr;throw;}
}
Peer::Peer(HANDLE process,HANDLE token):handle_(process){
    try{check(process && token,"peer_launch_handles");snapshot(token);CloseHandle(token);}
    catch(...){if(token)CloseHandle(token);if(handle_)CloseHandle(handle_);handle_=nullptr;throw;}
}
void Peer::snapshot(HANDLE token){
        require_alive();identity_.pid=GetProcessId(handle_);check(identity_.pid!=0,"peer_pid_missing");
        FILETIME created{},exited{},kernel{},user{};
        check(GetProcessTimes(handle_,&created,&exited,&kernel,&user)!=FALSE,"peer_time_failed");
        identity_.created=stamp(created);check(identity_.created!=0,"peer_time_missing");
        std::vector<wchar_t> path(32768);DWORD length=static_cast<DWORD>(path.size());
        check(QueryFullProcessImageNameW(handle_,0,path.data(),&length)!=FALSE && length>0 && length<path.size(),"peer_image_failed");
        identity_.image.assign(path.data(),length);
        TOKEN_TYPE type{};DWORD actual=0;
        check(GetTokenInformation(token,TokenType,&type,sizeof(type),&actual)!=FALSE && actual==sizeof(type) && type==TokenPrimary,"peer_primary_token_required");
        DWORD size=0;GetTokenInformation(token,TokenUser,nullptr,0,&size);
        check(size>=sizeof(TOKEN_USER) && size<=65536,"peer_token_size");
        std::vector<std::uint8_t> bytes(size);
        check(GetTokenInformation(token,TokenUser,bytes.data(),size,&size)!=FALSE,"peer_sid_failed");
        TOKEN_USER token_user{};std::memcpy(&token_user,bytes.data(),sizeof(token_user));identity_.sid=sid_text(token_user.User.Sid);
        check(GetTokenInformation(token,TokenSessionId,&identity_.session,sizeof(identity_.session),&actual)!=FALSE && actual==sizeof(identity_.session),"peer_session_failed");
        require_alive();
}
Peer::~Peer(){if(handle_)CloseHandle(handle_);}
Peer::Peer(Peer&& other) noexcept:handle_(std::exchange(other.handle_,nullptr)),identity_(std::move(other.identity_)){}
Peer& Peer::operator=(Peer&& other) noexcept{
    if(this!=&other){if(handle_)CloseHandle(handle_);handle_=std::exchange(other.handle_,nullptr);identity_=std::move(other.identity_);}return *this;
}
void Peer::require_alive() const{check(handle_ && WaitForSingleObject(handle_,0)==WAIT_TIMEOUT,"peer_exited_or_invalid");}
void Peer::require_match(const Identity& expected) const{
    require_alive();
    check(expected.pid!=0 && expected.created!=0 && !expected.sid.empty() && !expected.image.empty(),"incomplete_peer_expectation");
    check(identity_.pid==expected.pid && identity_.created==expected.created && identity_.session==expected.session &&
        identity_.sid==expected.sid && same_path(identity_.image,expected.image),"peer_identity_mismatch");
    require_alive();
}
std::wstring pipe_owner(HANDLE pipe){
    PSID owner=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
    const DWORD status=GetSecurityInfo(pipe,SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION,&owner,nullptr,nullptr,nullptr,&descriptor);
    if(status!=ERROR_SUCCESS || !descriptor){if(descriptor)LocalFree(descriptor);throw std::runtime_error("pipe_owner_query_failed");}
    try{auto value=sid_text(owner);LocalFree(descriptor);return value;}catch(...){LocalFree(descriptor);throw;}
}
Peer authenticate_pipe(HANDLE pipe,bool server_side,const Identity& expected,const std::wstring& expected_owner){
    check(!expected_owner.empty() && pipe_owner(pipe)==expected_owner,"pipe_owner_mismatch");
    ULONG pid=0;
    const BOOL obtained=server_side?GetNamedPipeClientProcessId(pipe,&pid):GetNamedPipeServerProcessId(pipe,&pid);
    check(obtained!=FALSE && pid==expected.pid,"pipe_peer_pid_mismatch");
    Peer peer(pid);peer.require_match(expected);return peer;
}
void require_effective_client(HANDLE pipe,const std::wstring& expected_sid){
    HANDLE previous=nullptr;
    if(OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&previous)){CloseHandle(previous);throw std::runtime_error("reader_already_impersonating");}
    check(GetLastError()==ERROR_NO_TOKEN,"reader_token_query_failed");
    check(ImpersonateNamedPipeClient(pipe)!=FALSE,"pipe_identification_failed");
    struct Revert{
        ~Revert(){if(!RevertToSelf()){TerminateProcess(GetCurrentProcess(),0xe0000001u);for(;;)Sleep(INFINITE);}}
    } revert;
    HANDLE token=nullptr;
    try{
        check(OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&token)!=FALSE,"pipe_client_token_failed");
        SECURITY_IMPERSONATION_LEVEL level{};DWORD actual=0;
        check(GetTokenInformation(token,TokenImpersonationLevel,&level,sizeof(level),&actual)!=FALSE &&
            actual==sizeof(level) && level==SecurityIdentification,"pipe_identification_level_required");
        DWORD size=0;GetTokenInformation(token,TokenUser,nullptr,0,&size);
        check(size>=sizeof(TOKEN_USER) && size<=65536,"pipe_client_token_size");
        std::vector<std::uint8_t> bytes(size);
        check(GetTokenInformation(token,TokenUser,bytes.data(),size,&size)!=FALSE,"pipe_client_sid_failed");
        TOKEN_USER user{};std::memcpy(&user,bytes.data(),sizeof(user));const auto sid=sid_text(user.User.Sid);
        CloseHandle(token);token=nullptr;check(!expected_sid.empty() && sid==expected_sid,"pipe_effective_sid_mismatch");
    }catch(...){if(token)CloseHandle(token);throw;}
}
}
