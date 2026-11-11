#include "cohort.hpp"
#include <shlobj.h>
#include <knownfolders.h>
#include <aclapi.h>
#include <sddl.h>
#include <filesystem>
#include <stdexcept>

namespace remote {
namespace {
void require(bool okay,const char* reason){if(!okay)throw std::runtime_error(reason);}
bool trusted(PSID sid,bool os_parent=false){LPWSTR text=nullptr;if(!sid || !ConvertSidToStringSidW(sid,&text))return false;
    const std::wstring value(text);LocalFree(text);return value==L"S-1-5-18" || value==L"S-1-5-32-544" ||
        (os_parent && value==L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
}
void protection(HANDLE file,bool os_parent){
    FILE_ATTRIBUTE_TAG_INFO tag{};require(GetFileInformationByHandleEx(file,FileAttributeTagInfo,&tag,sizeof(tag)) && !(tag.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT),"cohort_reparse");
    PSID owner=nullptr;PACL dacl=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
    require(GetSecurityInfo(file,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&dacl,nullptr,&descriptor)==ERROR_SUCCESS,"cohort_security_query");
    try{
        require(trusted(owner,os_parent) && dacl,"cohort_untrusted_owner_or_null_dacl");
        DWORD writes=GENERIC_ALL|GENERIC_WRITE|WRITE_DAC|WRITE_OWNER|DELETE|FILE_DELETE_CHILD;
        // Creating an unrelated entry at C:\ or Program Files does not permit
        // replacing the fixed protected descendant. Within the product tree,
        // creating DLLs is also forbidden to untrusted users.
        if(!os_parent)writes|=FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES;
        for(DWORD i=0;i<dacl->AceCount;++i){void* raw=nullptr;require(GetAce(dacl,i,&raw)!=FALSE,"cohort_ace");auto* header=static_cast<ACE_HEADER*>(raw);
            if(header->AceFlags&INHERIT_ONLY_ACE)continue;
            if(header->AceType==ACCESS_ALLOWED_ACE_TYPE){auto* ace=static_cast<ACCESS_ALLOWED_ACE*>(raw);require(!(ace->Mask&writes) || trusted(&ace->SidStart,os_parent),"cohort_untrusted_write");}
            else require(header->AceType==ACCESS_DENIED_ACE_TYPE,"cohort_unknown_ace");
        }
    }catch(...){LocalFree(descriptor);throw;}
    LocalFree(descriptor);
}
void inspect_directory(const std::filesystem::path& path,bool os_parent){
    HANDLE file=CreateFileW(path.c_str(),FILE_READ_ATTRIBUTES|READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    require(file!=INVALID_HANDLE_VALUE,"cohort_parent_open");
    try{protection(file,os_parent);}catch(...){CloseHandle(file);throw;}CloseHandle(file);
}
}
CohortPaths installed_cohort(){
    PWSTR path=nullptr;require(SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramFiles,KF_FLAG_DEFAULT,nullptr,&path)),"cohort_program_files");
    std::wstring root=std::wstring(path)+L"\\GuardDeskPilot\\USBControl";CoTaskMemFree(path);
    const auto sidecar=root+L"\\_internal\\remote\\";
    return {root,root+L"\\GuardDesk.exe",sidecar+L"GuardDeskRemoteWorker.exe",sidecar+L"GuardDeskRemoteMedia.exe",sidecar+L"GuardDeskRemoteBridge.dll"};
}
HANDLE pin_program_image(const std::wstring& image){
    const auto paths=installed_cohort();
    require(image==paths.broker || image==paths.worker || image==paths.media || image==paths.bridge,"cohort_fixed_image_required");
    const std::filesystem::path target(image);auto parent=target.root_path();unsigned count=0;inspect_directory(parent,true);
    for(const auto& component:target.relative_path()){
        require(++count<=16 && component!=L".." && component!=L".","cohort_path");parent/=component;
        if(parent==target)break;inspect_directory(parent,count==1);
    }
    HANDLE file=CreateFileW(image.c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    require(file!=INVALID_HANDLE_VALUE,"cohort_image_open");
    try{protection(file,false);}catch(...){CloseHandle(file);throw;}return file;
}
void require_fixed_peer(const ipc::Peer& peer,const std::wstring& image,const std::wstring& sid,DWORD session){
    const auto& actual=peer.identity();require(actual.sid==sid && actual.session==session &&
        CompareStringOrdinal(actual.image.c_str(),-1,image.c_str(),-1,TRUE)==CSTR_EQUAL,"cohort_peer_identity");peer.require_alive();
}
}
