#include "broker_api.hpp"
#include <stdexcept>
#include <iostream>
int main(){
    try{
        GD_REMOTE_START spec{};spec.bytes=sizeof(spec);spec.format=1;
        // Rejected before any installed image, WTS token or process operation.
        for(unsigned i=0;i<8;++i){void* context=reinterpret_cast<void*>(1);
            if(GDRemoteReserve(&spec,&context)!=ERROR_FUNCTION_FAILED || context)throw std::runtime_error("invalid_reserve_accepted_or_leaked_capacity");}
        if(GDRemoteStop(reinterpret_cast<void*>(1))!=ERROR_INVALID_HANDLE || GDRemoteClose(reinterpret_cast<void*>(1))!=ERROR_INVALID_HANDLE)throw std::runtime_error("unbound_context_accepted");
        std::uint8_t status[384]{};std::uint32_t bytes=99;
        if(GDRemoteWorkerPoll(nullptr,status,31,&bytes)!=ERROR_INVALID_PARAMETER ||
           GDRemoteWorkerPoll(nullptr,status,384,&bytes)!=ERROR_FUNCTION_FAILED || bytes!=0)
            throw std::runtime_error("unbound_worker_status_accepted");
        // This probe is never the installed SYSTEM image, including when an
        // administrator launches it. Readiness must reject it before mutation.
        if(GDRemoteCheckTrust()!=ERROR_FUNCTION_FAILED)throw std::runtime_error("unbound_trust_accepted");
        char reason[128]{};if(GDRemoteLastError(reason,sizeof(reason)) || !reason[0])throw std::runtime_error("missing_error_stage");
        std::cout<<"broker_invalid_prelaunch_no_installed_access=true\n";return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
