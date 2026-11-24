#pragma once
#ifdef GUARDDESK_OWNED_SERVICE_TEST
#include "recovery_store.hpp"
#include "recovery_runtime.hpp"
#include <filesystem>
#include <iostream>

// This entry exists in the owned probe only. It operates solely on the empty
// disposable directory supplied by the build tool, never the installed root.
inline int recovery_store_probe(const std::filesystem::path& root){
    using namespace service_recovery;
    unsigned stage=0;
    try{
        check(root.is_absolute() && std::filesystem::is_directory(root) && std::filesystem::is_empty(root));
        const std::wstring did=L"ee5138c901b7ad6898b27c94";
        const auto path=root/L"service-recovery.bin";
        {
            stage=1;
            Store state(root,did);
            // Pinning parent identity must not block unrelated legitimate
            // directory writers, while replacement/rename remains denied.
            HANDLE writer=CreateFileW(root.c_str(),FILE_ADD_FILE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,nullptr);
            stage=11;check(writer!=INVALID_HANDLE_VALUE);CloseHandle(writer);
            HANDLE remover=CreateFileW(root.c_str(),DELETE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,nullptr);
            const DWORD removal_error=GetLastError();if(remover!=INVALID_HANDLE_VALUE)CloseHandle(remover);
            stage=12;check(remover==INVALID_HANDLE_VALUE && removal_error==ERROR_SHARING_VIOLATION);
            stage=2;
            state.record.phase=active;state.save();
            check(failure(state.record,0xc0000005u,now())==30000);state.save();state.reload();
            check(state.record.attempts==1 && state.record.first_error==0xc0000005u);
            bool rejected=false;try{Store other(root,did);}catch(...){rejected=true;}check(rejected);
            check(!state.security_marker());
        }
        // Simulate a torn latest slot: the previous active state must survive,
        // and the supervisor will reserve a retry before starting another child.
        {
            HANDLE torn=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);check(torn!=INVALID_HANDLE_VALUE);
            const BYTE corrupt=0;DWORD wrote=0;const bool okay=WriteFile(torn,&corrupt,1,&wrote,nullptr) && wrote==1;
            CloseHandle(torn);check(okay);
            Store state(root,did);check(state.record.phase==active && state.record.attempts==0);
            check(failure(state.record,0xc0000005u,now())==30000);state.save();
        }
        {
            stage=3;
            Store state(root,did);check(state.record.attempts==1);
            std::array<unsigned char,32> raw{};std::memcpy(raw.data(),"GDS1",4);
            const DWORD code=225;std::memcpy(raw.data()+4,&code,4);
            const std::string device="ee5138c901b7ad6898b27c94";std::memcpy(raw.data()+8,device.data(),24);
            HANDLE marker=CreateFileW((root/L"service-security-hold.bin").c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,0,nullptr);
            check(marker!=INVALID_HANDLE_VALUE);DWORD wrote=0;
            const bool okay=WriteFile(marker,raw.data(),32,&wrote,nullptr) && wrote==32;CloseHandle(marker);check(okay);
            check(state.security_marker() && state.record.hold==security && state.record.first_error==0xc0000005u);
        }
        stage=4;{Store state(root,did);check(state.record.hold==security);}
        check(DeleteFileW((root/L"service-security-hold.bin").c_str())!=FALSE);
        const auto alias=root/L"owned-link.bin";
        stage=5;
        check(CreateHardLinkW(alias.c_str(),path.c_str(),nullptr)!=FALSE);
        bool hardlink=false;try{Store state(root,did);}catch(...){hardlink=true;}check(hardlink);
        check(DeleteFileW(alias.c_str())!=FALSE);
        HANDLE file=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);check(file!=INVALID_HANDLE_VALUE);
        stage=6;
        const std::array<BYTE,2*sizeof(Record)> corrupt{};DWORD wrote=0;
        const bool okay=WriteFile(file,corrupt.data(),static_cast<DWORD>(corrupt.size()),&wrote,nullptr) && wrote==corrupt.size();
        CloseHandle(file);check(okay);
        bool rejected=false;try{Store state(root,did);}catch(...){rejected=true;}check(rejected);
        check(std::filesystem::file_size(path)==2*sizeof(Record)); // Invalid state was preserved, not reset.
        check(DeleteFileW(path.c_str())!=FALSE);
        std::cout<<"owned_recovery_store=passed; cases=8; SYSTEM=not_tested\n";return 0;
    }catch(const std::exception& error){std::cout<<"owned_recovery_store_failed_stage="<<stage<<" winerror="<<GetLastError()<<" reason="<<error.what()<<"\n"<<std::flush;return 1;}
}
#endif
