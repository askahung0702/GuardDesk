#include "kernel_trust.hpp"
#include <sddl.h>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
unsigned count=0;
void check(const std::wstring& sddl,DWORD harmless,bool wanted){
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr))throw std::runtime_error("fixture_sddl");
    bool accepted=true;try{remote::require_kernel_descriptor(descriptor,harmless);}catch(const std::runtime_error&){accepted=false;}
    LocalFree(descriptor);++count;
    if(accepted!=wanted)throw std::runtime_error("kernel_fixture_"+std::to_string(count));
}
}
int main(){
    try{
        const DWORD process=PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE|READ_CONTROL,token=TOKEN_QUERY|READ_CONTROL;
        const std::wstring schedule=L"S-1-5-80-4125092361-1567024937-842823819-2091237918-836075745";
        // Exact LAB01 session-0 descriptor. Original predicate rejects this.
        check(L"O:SYD:(A;;0x1fffff;;;SY)(A;;RC;;;OW)(A;;0x1fffff;;;"+schedule+L")",process,true);
        check(L"O:SYD:(A;;GA;;;SY)(A;;GA;;;"+schedule+L")",token,true);
        check(L"O:SYD:(A;;GA;;;SY)(A;;GA;;;BA)",process,true);
        check(L"O:SYD:(A;;GA;;;SY)(A;;0x121000;;;WD)",process,true);
        check(L"O:SYD:(A;;GA;;;SY)(A;;0x20008;;;WD)",token,true);
        check(L"O:SYD:(A;;GA;;;SY)(A;;GA;;;WD)",process,false);
        check(L"O:SYD:(A;;GA;;;SY)(A;;GA;;;BU)",token,false);
        check(L"O:SYD:(A;;GA;;;SY)(A;;GA;;;S-1-5-80-1-2-3-4-5)",process,false);
        check(L"O:SYD:(A;;GA;;;SY)(A;;GA;;;"+schedule+L"0)",process,false);
        check(L"O:SYD:(A;;GA;;;SY)(A;;GA;;;"+schedule+L")(A;;GA;;;BU)",process,false);
        check(L"O:"+schedule+L"D:(A;;GA;;;SY)",process,false);
        check(L"O:WDD:(A;;GA;;;SY)",process,false);
        check(L"O:SYD:NO_ACCESS_CONTROL",process,false);
        check(L"O:SY",process,false);
        check(L"O:SYD:(A;;0x0008;;;WD)",process,false);
        check(L"O:SYD:(A;;0x0020;;;WD)",token,false);
        check(L"O:SYD:(A;;WD;;;WD)",process,false);
        check(L"O:SYD:(A;;WO;;;WD)",process,false);
        check(L"O:SYD:(A;CIIO;GA;;;WD)(A;;GA;;;SY)",process,true);
        check(L"O:SYD:(D;;GA;;;WD)(A;;GA;;;SY)",process,true);
        bool invalid=false;try{remote::require_query_only_kernel_trust(nullptr,process);}catch(const std::runtime_error& e){invalid=std::string(e.what()).find("kernel_security_query/win32=")==0;}
        if(!invalid)throw std::runtime_error("kernel_invalid_handle");++count;
        std::cout<<"kernel_trust_cases="<<count<<" no_OS_mutation=true\n";return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
