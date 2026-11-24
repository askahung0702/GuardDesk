#pragma once
#ifdef GUARDDESK_OWNED_SERVICE_TEST
#include "recovery_service.hpp"
#include <fstream>

inline int recovery_maintenance_probe(const std::filesystem::path& root){
    using namespace service_recovery;
    struct Gate {
        DWORD type=SERVICE_AUTO_START;bool running=false,fail_enable=false;unsigned disables=0,enables=0;
        void require_stopped(){check(!running);}
        void disable(){++disables;type=SERVICE_DISABLED;}
        void automatic(){require_stopped();check(type==SERVICE_DISABLED && !fail_enable);++enables;type=SERVICE_AUTO_START;}
    };
    try{
        check(root.is_absolute() && std::filesystem::is_directory(root) && std::filesystem::is_empty(root));
        const std::wstring did=L"ee5138c901b7ad6898b27c94";
        bool absent=false;try{Store missing(root,did,true);}catch(...){absent=true;}
        check(absent && std::filesystem::is_empty(root));
        Store state(root,did);
        for(unsigned i=0;i<4;++i)failure(state.record,27,now());state.save();
        check(state.record.hold==exhausted && state.record.attempts==3);
        {Store reader(root,did,true);check(reader.record.sequence==state.record.sequence && !reader.security_marker());
            bool refused=false;try{reader.save();}catch(...){refused=true;}check(refused);}
        std::ofstream(root/L"config.json",std::ios::binary)<<"owned-identity";
        std::ofstream(root/L"outbox-owned",std::ios::binary)<<"owned-unsent";
        Gate gate;reviewed_reset(state,gate,false);
        check(gate.type==SERVICE_AUTO_START && gate.disables==1 && gate.enables==1 && state.record.hold==none &&
            state.record.attempts==0 && state.record.phase==idle && state.record.first_error==27 && state.record.last_error==27);
        std::array<unsigned char,32> raw{};std::memcpy(raw.data(),"GDS1",4);const DWORD code=225;std::memcpy(raw.data()+4,&code,4);
        std::memcpy(raw.data()+8,"ee5138c901b7ad6898b27c94",24);
        {std::ofstream file(root/L"service-security-hold.bin",std::ios::binary);file.write(reinterpret_cast<const char*>(raw.data()),32);check(file.good());}
        Gate denied;bool needs_review=false;try{reviewed_reset(state,denied,false);}catch(...){needs_review=true;}
        check(needs_review && denied.disables==1 && denied.type==SERVICE_DISABLED && denied.enables==0 && state.record.hold==security && std::filesystem::exists(root/L"service-security-hold.bin"));
        Gate security_gate;reviewed_reset(state,security_gate,true);
        check(state.record.hold==none && !state.security_marker() && security_gate.enables==1);
        std::string identity,unsent;std::ifstream(root/L"config.json")>>identity;std::ifstream(root/L"outbox-owned")>>unsent;
        check(identity=="owned-identity" && unsent=="owned-unsent");
        unsigned archives=0;for(const auto& item:std::filesystem::directory_iterator(root))
            if(item.path().filename().wstring().rfind(L"service-recovery-review-",0)==0){check(std::filesystem::file_size(item.path())==168);++archives;}
        check(archives==2);
        Gate running;running.running=true;const auto sequence=state.record.sequence;
        bool stopped=false;try{reviewed_reset(state,running,false);}catch(...){stopped=true;}
        check(stopped && !running.disables && sequence==state.record.sequence);
        Gate failed;failed.fail_enable=true;bool disabled=false;try{reviewed_reset(state,failed,false);}catch(...){disabled=true;}
        check(disabled && failed.type==SERVICE_DISABLED && !failed.enables && state.record.hold==none);
        failed.fail_enable=false;reviewed_reset(state,failed,false);check(failed.type==SERVICE_AUTO_START && failed.enables==1);
        // Fill only the bounded evidence namespace; no previous review is erased.
        archives=0;for(const auto& item:std::filesystem::directory_iterator(root))
            if(item.path().filename().wstring().rfind(L"service-recovery-review-",0)==0)++archives;
        for(unsigned i=archives;i<16;++i)std::ofstream(root/(L"service-recovery-review-owned-"+std::to_wstring(i)+L".bin"))<<"kept";
        hold(state.record,review,5,now());state.save();Gate capacity;bool full=false;
        try{reviewed_reset(state,capacity,false);}catch(...){full=true;}
        check(full && capacity.type==SERVICE_DISABLED && !capacity.enables && state.record.hold==review);
        state.record.hold=none;state.record.phase=active;state.record.first_error=state.record.last_error=0;state.save();
        Gate unknown;bool unknown_refused=false;try{reviewed_reset(state,unknown,false);}catch(...){unknown_refused=true;}
        check(unknown_refused && unknown.type==SERVICE_DISABLED && !unknown.enables && state.record.phase==active);
        state.require_review(true); // Explicit security review is required for an unclassified fence interruption.
        std::cout<<"owned_recovery_maintenance=passed; cases=9; SCM=not_tested; SYSTEM=not_tested\n";return 0;
    }catch(const std::exception& e){std::cout<<"owned_recovery_maintenance_failed: "<<e.what()<<" winerror="<<GetLastError()<<"\n";return 1;}
}
#endif
