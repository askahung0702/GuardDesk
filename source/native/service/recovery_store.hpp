#pragma once
#include "recovery_policy.hpp"
#include <windows.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <aclapi.h>
#include <sddl.h>
#include <filesystem>
#include <string>
#include <vector>
#include <cstddef>

namespace service_recovery {
inline std::uint64_t now(){FILETIME t{};GetSystemTimeAsFileTime(&t);ULARGE_INTEGER value{};
    value.LowPart=t.dwLowDateTime;value.HighPart=t.dwHighDateTime;return value.QuadPart/10000-11644473600000ull;}
inline void check(bool okay){if(!okay)throw std::runtime_error("recovery_store_unavailable_or_untrusted");}
class Store {
    std::vector<HANDLE> parents_;
    HANDLE state_=INVALID_HANDLE_VALUE;
    std::filesystem::path root_;
    std::array<char,24> device_{};
    bool owned_=false,read_only_=false;
    static bool trusted(PSID sid,bool os_parent,bool owned){
        if(!sid)return false;
        if(IsWellKnownSid(sid,WinLocalSystemSid) || IsWellKnownSid(sid,WinBuiltinAdministratorsSid))return true;
        LPWSTR text=nullptr;check(ConvertSidToStringSidW(sid,&text)!=FALSE);
        const std::wstring value(text);LocalFree(text);
        if(os_parent && value==L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")return true;
#ifdef GUARDDESK_OWNED_SERVICE_TEST
        if(owned){HANDLE raw=nullptr;check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw)!=FALSE);
            DWORD size=0;GetTokenInformation(raw,TokenUser,nullptr,0,&size);std::vector<BYTE> token(size);
            const bool okay=size && GetTokenInformation(raw,TokenUser,token.data(),size,&size) &&
                EqualSid(sid,reinterpret_cast<TOKEN_USER*>(token.data())->User.Sid);CloseHandle(raw);return okay;}
#else
        (void)owned;
#endif
        return false;
    }
    void protect(HANDLE file,bool os_parent,bool directory){
        FILE_ATTRIBUTE_TAG_INFO tag{};check(GetFileInformationByHandleEx(file,FileAttributeTagInfo,&tag,sizeof(tag))!=FALSE);
        check(!(tag.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT));
        check(static_cast<bool>(tag.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)==directory);
        BY_HANDLE_FILE_INFORMATION info{};check(GetFileInformationByHandle(file,&info)!=FALSE);
        if(!directory)check(info.nNumberOfLinks==1);
        PSID owner=nullptr;PACL dacl=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
        check(GetSecurityInfo(file,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
            &owner,nullptr,&dacl,nullptr,&descriptor)==ERROR_SUCCESS);
        try{
            check(trusted(owner,os_parent,owned_) && dacl);
            constexpr DWORD changes=GENERIC_ALL|GENERIC_WRITE|WRITE_DAC|WRITE_OWNER|DELETE|FILE_DELETE_CHILD|
                FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES;
            for(DWORD i=0;i<dacl->AceCount;++i){void* raw=nullptr;check(GetAce(dacl,i,&raw)!=FALSE);
                const auto* header=static_cast<ACE_HEADER*>(raw);if(header->AceFlags&INHERIT_ONLY_ACE)continue;
                if(header->AceType==ACCESS_DENIED_ACE_TYPE)continue;
                check(header->AceType==ACCESS_ALLOWED_ACE_TYPE);
                const auto* ace=static_cast<ACCESS_ALLOWED_ACE*>(raw);
                const DWORD writes=changes&~(os_parent?0x116u:0u);
                check(!(ace->Mask&writes) || trusted(const_cast<DWORD*>(&ace->SidStart),os_parent,owned_));
            }
        }catch(...){LocalFree(descriptor);throw;}LocalFree(descriptor);
    }
    HANDLE open(const std::filesystem::path& p,DWORD access,DWORD creation,bool directory=false){
        // Parent handles deny replacement/rename, not legitimate directory
        // writers (including other users of ProgramData). State stays single-writer.
        // Attribute-only handles do not participate in read/write/delete
        // sharing checks. Request LIST_DIRECTORY so the parent pin is effective.
        HANDLE h=CreateFileW(p.c_str(),access|READ_CONTROL|(directory?FILE_LIST_DIRECTORY:0),
            FILE_SHARE_READ|((directory || read_only_)?FILE_SHARE_WRITE:0),nullptr,creation,
            FILE_FLAG_OPEN_REPARSE_POINT|(directory?FILE_FLAG_BACKUP_SEMANTICS:0),nullptr);
        return h;
    }
    void initialize(const std::filesystem::path& root,const std::wstring& did){
        check(did.size()==24 && did.find_first_not_of(L"0123456789abcdef")==std::wstring::npos);
        for(std::size_t i=0;i<24;++i)device_[i]=static_cast<char>(did[i]);root_=root;
        auto parent=root.root_path();
        if(!owned_){auto h=open(parent,FILE_READ_ATTRIBUTES,OPEN_EXISTING,true);check(h!=INVALID_HANDLE_VALUE);
            parents_.push_back(h);protect(h,true,true);}
        unsigned index=0;
        for(const auto& part:root.relative_path()){
            check(part!=L".." && part!=L"." && ++index<=24);parent/=part;
            // Owned probe pins only its private test directory. Product pins all parents.
            if(owned_ && parent!=root)continue;
            auto h=open(parent,FILE_READ_ATTRIBUTES,OPEN_EXISTING,true);check(h!=INVALID_HANDLE_VALUE);
            parents_.push_back(h);protect(h,index==1,true);
        }
        state_=open(root/L"service-recovery.bin",GENERIC_READ|(read_only_?0:GENERIC_WRITE),read_only_?OPEN_EXISTING:OPEN_ALWAYS);
        check(state_!=INVALID_HANDLE_VALUE);const bool created=!read_only_ && GetLastError()!=ERROR_ALREADY_EXISTS;
        protect(state_,false,false);
        if(created){record.device=device_;record.window_start=record.updated=now();save();}
        else reload();
    }
public:
    Record record;
    explicit Store(const std::wstring& did,bool read_only=false):read_only_(read_only){
        PWSTR path=nullptr;check(SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData,KF_FLAG_DEFAULT,nullptr,&path)));
        const auto root=std::filesystem::path(path)/L"GuardDeskPilot"/L"USBControl"/did;CoTaskMemFree(path);
        try{initialize(root,did);}catch(...){close();throw;}
    }
#ifdef GUARDDESK_OWNED_SERVICE_TEST
    Store(const std::filesystem::path& root,const std::wstring& did,bool read_only=false):owned_(true),read_only_(read_only){try{initialize(root,did);}catch(...){close();throw;}}
#endif
    Store(const Store&)=delete;Store& operator=(const Store&)=delete;
    ~Store(){close();}
    void close(){if(state_!=INVALID_HANDLE_VALUE){CloseHandle(state_);state_=INVALID_HANDLE_VALUE;}
        for(auto h:parents_)CloseHandle(h);parents_.clear();}
    void reload(){LARGE_INTEGER size{};check(GetFileSizeEx(state_,&size) && size.QuadPart>=sizeof(Record) && size.QuadPart<=2*sizeof(Record));
        bool found=false;
        for(unsigned slot=0;slot<2;++slot){
            if(size.QuadPart<static_cast<LONGLONG>((slot+1)*sizeof(Record)))continue;
            LARGE_INTEGER start{};start.QuadPart=static_cast<LONGLONG>(slot*sizeof(Record));
            check(SetFilePointerEx(state_,start,nullptr,FILE_BEGIN)!=FALSE);DWORD got=0;Record candidate;
            check(ReadFile(state_,&candidate,sizeof(candidate),&got,nullptr) && got==sizeof(candidate));
            try{validate(candidate,device_);}catch(const std::exception&){continue;}
            if(!found || candidate.sequence>record.sequence){record=candidate;found=true;}
        }
        check(found);
    }
    void save(){check(!read_only_ && record.sequence<UINT64_MAX);++record.sequence;record.checksum=checksum(record);validate(record,device_);
        // Alternate slots: a torn write cannot destroy the last valid state.
        LARGE_INTEGER start{};start.QuadPart=static_cast<LONGLONG>(((record.sequence-1)%2)*sizeof(Record));
        check(SetFilePointerEx(state_,start,nullptr,FILE_BEGIN)!=FALSE);DWORD written=0;
        check(WriteFile(state_,&record,sizeof(record),&written,nullptr) && written==sizeof(record));
        check(FlushFileBuffers(state_)!=FALSE);}
    bool read_marker(std::array<unsigned char,32>& raw,bool remove=false,const std::array<unsigned char,32>* expected=nullptr){
        check(!remove || !read_only_);
        auto h=open(root_/L"service-security-hold.bin",GENERIC_READ|(remove?DELETE:0),OPEN_EXISTING);
        if(h==INVALID_HANDLE_VALUE){check(GetLastError()==ERROR_FILE_NOT_FOUND);return false;}
        try{
            protect(h,false,false);LARGE_INTEGER size{};check(GetFileSizeEx(h,&size) && size.QuadPart==32);
            DWORD got=0;check(ReadFile(h,raw.data(),32,&got,nullptr) && got==32);
            std::uint32_t error=0;std::memcpy(&error,raw.data()+4,4);
            check(std::memcmp(raw.data(),"GDS1",4)==0 && (error==225 || error==226) &&
                std::memcmp(raw.data()+8,device_.data(),24)==0);
            if(remove){check(expected && raw==*expected);FILE_DISPOSITION_INFO disposition{TRUE};check(SetFileInformationByHandle(h,FileDispositionInfo,&disposition,sizeof(disposition))!=FALSE);}
        }catch(...){CloseHandle(h);throw;}CloseHandle(h);return true;
    }
    bool security_marker(){
        std::array<unsigned char,32> raw{};if(!read_marker(raw))return false;
        if(!read_only_){std::uint32_t error=0;std::memcpy(&error,raw.data()+4,4);hold(record,security,error,now());save();}
        return true;
    }
    void require_review(bool security_reviewed){
        check(!read_only_);if(now()<record.updated)throw std::runtime_error("clock_review_required");
        // A host interruption after the OS fence but before its reason was
        // persisted is unknown, so ordinary fault review cannot clear it.
        const bool unknown=record.hold==none && (record.phase==active || record.phase==waiting || !record.first_error);
        const bool blocked=security_marker() || record.hold==security || unknown;
        if(blocked && !security_reviewed)throw std::runtime_error("security_review_required");
    }
    void reset_after_review(bool security_reviewed){
        require_review(security_reviewed);
        // Bounded, never overwritten, protected evidence before changing a hold.
        unsigned entries=0,archives=0;
        for(const auto& item:std::filesystem::directory_iterator(root_)){
            check(++entries<=4096);
            if(item.path().filename().wstring().rfind(L"service-recovery-review-",0)==0)++archives;
        }
        if(archives>=16)throw std::runtime_error("review_archive_limit"); // MIS must archive evidence first.
        struct ReviewRecord {
            std::uint32_t magic=0x31565247,version=1,security_reviewed=0,marker_present=0;
            std::uint64_t reviewed_at=0;Record before;std::array<unsigned char,32> marker{};
            std::uint32_t checksum=0,reserved=0;
        } audit;
        static_assert(sizeof(ReviewRecord)==168,"Review layout changed");
        audit.security_reviewed=security_reviewed?1u:0u;audit.reviewed_at=now();audit.before=record;
        audit.marker_present=read_marker(audit.marker)?1u:0u;
        auto* bytes=reinterpret_cast<unsigned char*>(&audit);
        // Use a zero checksum field in the calculation.
        const auto offset=offsetof(ReviewRecord,checksum);std::uint32_t hash=2166136261u;
        for(std::size_t i=0;i<sizeof(audit);++i)hash=(hash^((i>=offset && i<offset+4)?0:bytes[i]))*16777619u;
        audit.checksum=hash;
        const auto name=L"service-recovery-review-"+std::to_wstring(record.sequence)+L".bin";
        auto h=open(root_/name,GENERIC_READ|GENERIC_WRITE,CREATE_NEW);check(h!=INVALID_HANDLE_VALUE);
        try{
            protect(h,false,false);DWORD written=0;
            check(WriteFile(h,&audit,sizeof(audit),&written,nullptr) && written==sizeof(audit) && FlushFileBuffers(h));
            LARGE_INTEGER zero{};check(SetFilePointerEx(h,zero,nullptr,FILE_BEGIN)!=FALSE);
            std::array<unsigned char,sizeof(audit)> copy{};DWORD got=0;
            check(ReadFile(h,copy.data(),static_cast<DWORD>(copy.size()),&got,nullptr) && got==copy.size() && std::memcmp(copy.data(),&audit,sizeof(audit))==0);
        }catch(...){CloseHandle(h);throw;}CloseHandle(h);
        record.attempts=0;record.retry_at={};record.phase=idle;record.hold=none;
        record.window_start=record.updated=now();save();
        if(audit.marker_present){std::array<unsigned char,32> marker{};check(read_marker(marker,true,&audit.marker));}
        // first/last error remain visible; this does not rewrite identity/config/outbox.
    }
};
}
