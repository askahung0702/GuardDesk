#include "windows_desktop.hpp"
#include "ipc_peer.hpp"
#include <wtsapi32.h>
#include <sddl.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <aclapi.h>
#include <array>
#include <vector>
#include <stdexcept>

namespace remote {
namespace {
void require(bool okay,const char* reason){if(!okay)throw std::runtime_error(reason);}
std::uint64_t number(LUID value){return (std::uint64_t(static_cast<DWORD>(value.HighPart))<<32)|value.LowPart;}
std::wstring sid_text(PSID sid){LPWSTR text=nullptr;require(ConvertSidToStringSidW(sid,&text)!=FALSE,"desktop_sid");std::wstring value(text);LocalFree(text);return value;}
class Privilege {
    HANDLE token_=nullptr;
public:
    Privilege(){
        HANDLE old=nullptr;
        if(OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&old)){CloseHandle(old);throw std::runtime_error("desktop_unexpected_impersonation");}
        require(GetLastError()==ERROR_NO_TOKEN,"desktop_thread_token");
        require(ImpersonateSelf(SecurityImpersonation)!=FALSE,"desktop_thread_identity");
        try{
            require(OpenThreadToken(GetCurrentThread(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,TRUE,&token_)!=FALSE,"desktop_privilege_token");
            TOKEN_PRIVILEGES wanted{};wanted.PrivilegeCount=1;
            require(LookupPrivilegeValueW(nullptr,SE_TCB_NAME,&wanted.Privileges[0].Luid)!=FALSE,"desktop_privilege_name");
            wanted.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;SetLastError(ERROR_SUCCESS);
            require(AdjustTokenPrivileges(token_,FALSE,&wanted,0,nullptr,nullptr)!=FALSE && GetLastError()==ERROR_SUCCESS,"desktop_privilege_unavailable");
        }catch(...){if(token_)CloseHandle(token_);token_=nullptr;if(!RevertToSelf())TerminateProcess(GetCurrentProcess(),0xe0000001u);throw;}
    }
    ~Privilege(){if(token_)CloseHandle(token_);if(!RevertToSelf()){TerminateProcess(GetCurrentProcess(),0xe0000001u);for(;;)Sleep(INFINITE);}}
};
bool session_info(DWORD session,WTSINFOEX_LEVEL1_W& result){
    LPWSTR bytes=nullptr;DWORD count=0;
    if(!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,session,WTSSessionInfoEx,&bytes,&count))return false;
    const bool okay=count>=sizeof(WTSINFOEXW) && reinterpret_cast<WTSINFOEXW*>(bytes)->Level==1;
    if(okay)result=reinterpret_cast<WTSINFOEXW*>(bytes)->Data.WTSInfoExLevel1;
    WTSFreeMemory(bytes);return okay;
}
std::wstring desktop_name(HDESK desktop){
    std::array<wchar_t,256> text{};DWORD count=0;
    require(GetUserObjectInformationW(desktop,UOI_NAME,text.data(),static_cast<DWORD>(text.size()*sizeof(wchar_t)),&count)!=FALSE && count<=text.size()*sizeof(wchar_t),"desktop_name");
    return text.data();
}
bool os_image(HANDLE file){
    PSID owner=nullptr;PACL dacl=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
    if(GetSecurityInfo(file,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&dacl,nullptr,&descriptor)!=ERROR_SUCCESS)return false;
    const std::array<std::wstring,3> trusted{L"S-1-5-18",L"S-1-5-32-544",L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"};
    const auto known=[&](PSID sid){const auto value=sid_text(sid);for(const auto& item:trusted)if(value==item)return true;return false;};
    bool okay=false;
    try{
        okay=owner && dacl && known(owner);
        constexpr DWORD writes=GENERIC_ALL|GENERIC_WRITE|WRITE_DAC|WRITE_OWNER|DELETE|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES;
        for(DWORD i=0;okay && i<dacl->AceCount;++i){void* raw=nullptr;if(!GetAce(dacl,i,&raw)){okay=false;break;}
            auto* header=static_cast<ACE_HEADER*>(raw);if(header->AceFlags&INHERIT_ONLY_ACE)continue;
            if(header->AceType==ACCESS_ALLOWED_ACE_TYPE){auto* ace=static_cast<ACCESS_ALLOWED_ACE*>(raw);if((ace->Mask&writes) && !known(&ace->SidStart))okay=false;}
            else if(header->AceType!=ACCESS_DENIED_ACE_TYPE)okay=false;
        }
    }catch(...){LocalFree(descriptor);throw;}
    LocalFree(descriptor);return okay;
}
bool microsoft_signed(HANDLE file,const std::wstring& path){
    WINTRUST_FILE_INFO info{sizeof(info),path.c_str(),file,nullptr};WINTRUST_DATA data{};data.cbStruct=sizeof(data);
    data.dwUIChoice=WTD_UI_NONE;data.fdwRevocationChecks=WTD_REVOKE_NONE;data.dwUnionChoice=WTD_CHOICE_FILE;data.pFile=&info;
    data.dwStateAction=WTD_STATEACTION_VERIFY;data.dwProvFlags=WTD_CACHE_ONLY_URL_RETRIEVAL|WTD_REVOCATION_CHECK_NONE;
    GUID policy=WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const auto status=WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE),&policy,&data);bool publisher=false;
    if(status==ERROR_SUCCESS){
        auto* provider=WTHelperProvDataFromStateData(data.hWVTStateData);
        auto* signer=provider?WTHelperGetProvSignerFromChain(provider,0,FALSE,0):nullptr;
        if(signer && signer->csCertChain && signer->pasCertChain[0].pCert){
            std::array<wchar_t,256> organization{};
            const auto length=CertGetNameStringW(signer->pasCertChain[0].pCert,CERT_NAME_ATTR_TYPE,0,
                const_cast<char*>(szOID_ORGANIZATION_NAME),organization.data(),static_cast<DWORD>(organization.size()));
            publisher=length>1 && std::wstring(organization.data())==L"Microsoft Corporation";
        }
    }
    data.dwStateAction=WTD_STATEACTION_CLOSE;WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE),&policy,&data);return status==ERROR_SUCCESS && publisher;
}
}
WindowsDesktop::WindowsDesktop(LogonBinding binding):logon_(std::move(binding)){
    require(logon_.session>0 && logon_.authentication && logon_.logon_time && logon_.consent_filetime && !logon_.sid.empty(),"desktop_binding");
    ipc::Peer self(GetCurrentProcessId());
    require(self.identity().session==logon_.session && (!logon_.administrator_assistance || self.identity().sid==L"S-1-5-18"),"desktop_worker_identity");
    original_=GetThreadDesktop(GetCurrentThreadId());require(original_!=nullptr,"desktop_original");
    if(logon_.administrator_assistance){
        std::array<wchar_t,32768> system{};const auto count=GetSystemDirectoryW(system.data(),static_cast<UINT>(system.size()));
        require(count>0 && count<system.size(),"desktop_system_directory");
        const auto path=std::wstring(system.data())+L"\\consent.exe";
        HANDLE image=CreateFileW(path.c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        require(image!=INVALID_HANDLE_VALUE,"desktop_consent_image");
        FILE_ATTRIBUTE_TAG_INFO tag{};
        try{
            require(GetFileInformationByHandleEx(image,FileAttributeTagInfo,&tag,sizeof(tag)) && !(tag.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) &&
                os_image(image) && microsoft_signed(image,path),"desktop_consent_trust");
            consent_image_=image;
        }catch(...){CloseHandle(image);throw;}
    }
}
WindowsDesktop::~WindowsDesktop(){if(attached_ && SetThreadDesktop(original_))CloseDesktop(attached_);if(consent_image_!=INVALID_HANDLE_VALUE)CloseHandle(consent_image_);}
bool WindowsDesktop::same_logon(){
    WTSINFOEX_LEVEL1_W info{};
    if(!session_info(logon_.session,info) || info.SessionId!=logon_.session || info.SessionState!=WTSActive ||
        info.SessionFlags!=WTS_SESSIONSTATE_UNLOCK || static_cast<std::uint64_t>(info.LogonTime.QuadPart)!=logon_.logon_time)return false;
    // WTS handle and AuthenticationId prevent session-number reuse or A->B
    // fast-user-switch from inheriting the original grant. No user names logged.
    HANDLE token=nullptr;
    if(logon_.administrator_assistance){Privilege privilege;if(!WTSQueryUserToken(logon_.session,&token))return false;}
    else if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return false;
    bool okay=false;
    try{
        TOKEN_STATISTICS statistics{};DWORD count=0,size=0;
        okay=GetTokenInformation(token,TokenStatistics,&statistics,sizeof(statistics),&count)!=FALSE && number(statistics.AuthenticationId)==logon_.authentication;
        GetTokenInformation(token,TokenUser,nullptr,0,&size);
        if(!size || size>65536)okay=false;
        else{std::vector<std::uint8_t> data(size);okay=okay && GetTokenInformation(token,TokenUser,data.data(),size,&count)!=FALSE &&
            sid_text(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid)==logon_.sid;}
    }catch(...){CloseHandle(token);throw;}
    CloseHandle(token);
    PWTS_SESSION_INFOW sessions=nullptr;DWORD count=0;
    if(!okay || !WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE,0,1,&sessions,&count))return false;
    unsigned active=0;
    if(count>64)okay=false;
    else for(DWORD i=0;i<count;++i)if(sessions[i].State==WTSActive){WTSINFOEX_LEVEL1_W other{};
        if(!session_info(sessions[i].SessionId,other)){okay=false;break;}
        if(other.SessionFlags==WTS_SESSIONSTATE_UNLOCK)++active;
    }
    WTSFreeMemory(sessions);return okay && active==1;
}
bool WindowsDesktop::actual_uac(){
    HWND foreground=GetForegroundWindow();DWORD pid=0;if(!foreground || !GetWindowThreadProcessId(foreground,&pid))return false;
    std::unique_ptr<ipc::Peer> process;
    try{process=std::make_unique<ipc::Peer>(pid);}catch(const std::exception&){return false;}
    const auto& actual=process->identity();std::array<wchar_t,32768> directory{};
    const auto count=GetSystemDirectoryW(directory.data(),static_cast<UINT>(directory.size()));if(!count || count>=directory.size())return false;
    const auto expected=std::wstring(directory.data())+L"\\consent.exe";
    if(actual.session!=logon_.session || actual.created<logon_.consent_filetime ||
        CompareStringOrdinal(actual.image.c_str(),-1,expected.c_str(),-1,TRUE)!=CSTR_EQUAL)return false;
    if(!prompt_ || actual.pid!=prompt_->identity().pid || actual.created!=prompt_->identity().created){
        if(consent_image_==INVALID_HANDLE_VALUE)return false;prompt_=std::move(process);
    }
    DWORD final_pid=0;return GetForegroundWindow()==foreground && GetWindowThreadProcessId(foreground,&final_pid) && final_pid==actual.pid;
}
DesktopObservation WindowsDesktop::select(){
    DesktopObservation result{};result.same_logon=same_logon();if(!result.same_logon)return result;
    HDESK handle=OpenInputDesktop(0,FALSE,DESKTOP_READOBJECTS|DESKTOP_WRITEOBJECTS|DESKTOP_SWITCHDESKTOP|DESKTOP_JOURNALPLAYBACK);
    if(!handle)return result;
    try{
        const auto name=desktop_name(handle);
        if(name!=L"Default" && name!=L"Winlogon"){CloseDesktop(handle);return result;}
        if(name!=name_){
            if(!SetThreadDesktop(handle)){CloseDesktop(handle);return result;}
            if(attached_)CloseDesktop(attached_);attached_=handle;handle=nullptr;name_=name;
        }
        if(handle){CloseDesktop(handle);handle=nullptr;}
        result.identity=name_==L"Default"?1:2;result.secure=name_==L"Winlogon";
        if(result.secure && (!logon_.administrator_assistance || !actual_uac()))return result;
        if(!result.secure)prompt_.reset();
        // One selected output, independent of the number/arrangement of other
        // monitors. Input is normalized against the full physical desktop.
        if(!primary_display_geometry(result.output,result.virtual_screen))return result;
        result.allowed=true;return result;
    }catch(...){if(handle)CloseDesktop(handle);throw;}
}
bool WindowsDesktop::input_guard(const DesktopObservation& expected){
    const auto current=select();return current.same_logon && current.allowed && expected.allowed && current.identity==expected.identity && current.secure==expected.secure &&
        EqualRect(&current.output,&expected.output) && EqualRect(&current.virtual_screen,&expected.virtual_screen);
}
}
