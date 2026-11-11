// Owned child only: no product start, capture, input, network or installed writes.
#include "ipc_peer.hpp"
#include "media_runtime_defaults.hpp"
#include "webrtc/media_entry_token.hpp"
#include <sddl.h>
#include <iostream>
#include <string>
struct H { HANDLE v=nullptr; ~H(){if(v && v!=INVALID_HANDLE_VALUE)CloseHandle(v);} };
void need(bool v){if(!v)throw std::runtime_error("probe_api");}
int child(){unsigned stage=1;try{
 H token;need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.v)!=FALSE);
 stage=2;remote::require_media_token(token.v);
 stage=3;remote::ipc::Peer self(GetCurrentProcessId());
 
 
 
 stage=7;H cancel;cancel.v=CreateEventW(nullptr,TRUE,FALSE,nullptr);need(cancel.v!=nullptr);
 return 0;
 }catch(const std::exception& e){std::cerr<<"stage="<<stage<<" reason="<<e.what()<<" win32="<<GetLastError()<<"\n";return static_cast<int>(0xe200000u|(stage<<16)|(GetLastError()&0xffff));}}
int wmain(int argc,wchar_t** argv){if(argc==2 && std::wstring(argv[1])==L"--owned-child")return child();
 if(argc!=1)return 2;unsigned parent_stage=1;try{
 H original;need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_ADJUST_DEFAULT|TOKEN_ASSIGN_PRIMARY,&original.v)!=FALSE);
 remote::ipc::Peer current(GetCurrentProcessId()); unsigned cases=0; for(unsigned strict : {0u,1u,2u,3u,4u,6u}){
 parent_stage=2;H restricted;PSID ba=nullptr,low=nullptr;need(ConvertStringSidToSidW(L"S-1-5-32-544",&ba)!=FALSE);
 SID_AND_ATTRIBUTES deny{ba,0};const bool created=CreateRestrictedToken(original.v,DISABLE_MAX_PRIVILEGE,1,&deny,0,nullptr,0,nullptr,&restricted.v)!=FALSE;LocalFree(ba);need(created);
 parent_stage=3;need(ConvertStringSidToSidW(L"S-1-16-4096",&low)!=FALSE);TOKEN_MANDATORY_LABEL label{{low,SE_GROUP_INTEGRITY}};
 const bool labeled=SetTokenInformation(restricted.v,TokenIntegrityLevel,&label,sizeof(label)+GetLengthSid(low))!=FALSE;LocalFree(low);need(labeled);
 parent_stage=4;PSECURITY_DESCRIPTOR sd=nullptr;need(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;RC;;;OW)",SDDL_REVISION_1,&sd,nullptr)!=FALSE);
 SECURITY_ATTRIBUTES security{sizeof(security),sd,FALSE};
 parent_stage=5;if(strict&1){PACL acl=nullptr;BOOL present=FALSE,def=FALSE;need(GetSecurityDescriptorDacl(sd,&present,&acl,&def)!=FALSE && present && acl);TOKEN_DEFAULT_DACL defaults{acl};need(SetTokenInformation(restricted.v,TokenDefaultDacl,&defaults,sizeof(defaults))!=FALSE);}
 if(strict&4){ bool refused=false; try{remote::set_media_runtime_defaults(restricted.v,L"S-1-0-0");}catch(...){refused=true;}need(refused); remote::set_media_runtime_defaults(restricted.v,current.identity().sid); } parent_stage=6;wchar_t path[32768]{};need(GetModuleFileNameW(nullptr,path,32768)!=0);std::wstring line=L"\""+std::wstring(path)+L"\" --owned-child";
 STARTUPINFOW start{};start.cb=sizeof(start);PROCESS_INFORMATION pi{};
 const BOOL launched=CreateProcessAsUserW(restricted.v,path,line.data(),(strict&2)?&security:nullptr,(strict&2)?&security:nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&start,&pi);const DWORD error=GetLastError();LocalFree(sd);
 if(!launched){std::cout<<"{\"strict\":"<<strict<<",\"launch_error\":"<<error<<"}\n";return 1;}
 H process,thread;process.v=pi.hProcess;thread.v=pi.hThread;
 if(WaitForSingleObject(process.v,2000)!=WAIT_OBJECT_0){TerminateProcess(process.v,0xe2000000);WaitForSingleObject(process.v,1000);}
 DWORD code=0;need(GetExitCodeProcess(process.v,&code)!=FALSE);
 std::cout<<"{\"strict\":"<<strict<<",\"exit\":"<<code<<",\"stage\":"<<((code>>16)&255)<<",\"win32\":"<<(code&65535)<<"}\n";
 need((strict==1 || strict==3)?code==0xc0000142u:code==0);++cases; }std::cout<<"{\"passed\":true,\"cases\":"<<cases<<",\"old_DLL_failure_reproduced\":true,\"SYSTEM_boundary\":false,\"desktop_capture\":false,\"OS_input\":false}\n";return 0;
 }catch(const std::exception& e){std::cerr<<"parent_stage="<<parent_stage<<" "<<e.what()<<" win32="<<GetLastError()<<"\n";return 1;}}
