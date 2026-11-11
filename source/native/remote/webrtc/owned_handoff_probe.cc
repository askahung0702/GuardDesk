// Test-only, current-user child and owned pixels. Never launch installed Agent,
// capture the desktop, request SYSTEM, or call SendInput. Real anonymous mapping
// handoff, SessionRuntime, WebRTC/MF and visible NativeViewer Present are used.
#include "media_peer.hpp"
#include "session.hpp"
#include "viewer.hpp"
#include "pointer_flow.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <thread>

namespace {
using namespace remote;
void need(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
struct Handle {HANDLE value=nullptr;~Handle(){if(value && value!=INVALID_HANDLE_VALUE)CloseHandle(value);}Handle()=default;Handle(const Handle&)=delete;};
ipc::Session id(){ipc::Session value{};value[0]=9;return value;}
struct Counts {std::uint64_t frames=0,inputs=0,clears=0,consumed=0;};
bool read_exact(HANDLE pipe,void* bytes,DWORD count){DWORD read=0;return ReadFile(pipe,bytes,count,&read,nullptr) && read==count;}
void write_exact(HANDLE pipe,const void* bytes,DWORD count){DWORD written=0;need(WriteFile(pipe,bytes,count,&written,nullptr) && written==count,"owned_pipe_write");}
void put(std::vector<std::uint8_t>& b,unsigned at,std::uint64_t value,unsigned size){for(unsigned i=0;i<size;++i)b.at(at+i)=static_cast<std::uint8_t>(value>>(8*i));}
HANDLE argument(const std::wstring& text){
    need(!text.empty() && text.size()<=20 && std::all_of(text.begin(),text.end(),[](auto c){return c>=L'0' && c<=L'9';}),"owned_handle_argument");
    const auto number=std::stoull(text);need(number>0 && number<=UINTPTR_MAX,"owned_handle_range");
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(number));
}
int child(const std::array<std::wstring,4>& arguments){
    Handle commands,status;commands.value=argument(arguments.at(0));status.value=argument(arguments.at(1));
    std::array<HANDLE,2> writable{argument(arguments.at(2)),argument(arguments.at(3))};
    FramePool pool(id(),1920,1080,writable);Counts counts;
    const auto started=GetTickCount64();
    DesktopObservation desktop{true,true,false,1,{0,0,1920,1080},{0,0,1920,1080}};
    SessionRuntime runtime(id(),7,started,started+60000,[&](const auto& batch){counts.inputs+=batch.size();return static_cast<UINT>(batch.size());},[&]{pool.clear();++counts.clears;});
    Pixels pixels{1920,1080,std::vector<std::uint8_t>(1920*1080*4,145)};
    std::uint64_t next_frame=0,sequence=0;bool granted=false;
    while(!runtime.ended() && GetTickCount64()-started<60000){
        DWORD available=0;if(!PeekNamedPipe(commands.value,nullptr,0,nullptr,&available,nullptr))break;
        unsigned budget=0;
        while(available>=ipc::control_header_bytes && budget++<16){
            std::array<std::uint8_t,ipc::control_header_bytes> header{};need(read_exact(commands.value,header.data(),static_cast<DWORD>(header.size())),"owned_header_read");
            auto decoded=ipc::control_header(header,ipc::Direction::broker_to_worker);need(decoded.payload_bytes<=24,"owned_payload_bound");
            std::vector<std::uint8_t> wire(header.begin(),header.end());wire.resize(header.size()+decoded.payload_bytes);
            if(decoded.payload_bytes)need(read_exact(commands.value,std::span<std::uint8_t>(wire).subspan(header.size()).data(),decoded.payload_bytes),"owned_payload_read");
            auto message=ipc::control_message(wire,ipc::Direction::broker_to_worker);
            // Controlled busy input guard; synthetic only, never WTS/SendInput.
            if(message.header.kind==ipc::Kind::input)std::this_thread::sleep_for(std::chrono::milliseconds(15));
            const bool accepted=runtime.command(message,GetTickCount64(),desktop);
            if(accepted && message.header.kind==ipc::Kind::lease)granted=true;
            if(accepted && message.header.kind==ipc::Kind::consumed){if(pool.release_sequence(message.header.desktop_generation,message.header.frame_sequence))++counts.consumed;}
            need(PeekNamedPipe(commands.value,nullptr,0,nullptr,&available,nullptr)!=FALSE,"owned_pipe_peek");
        }
        if(runtime.ended())break;
        const auto now=GetTickCount64();
        if(granted && runtime.observe(desktop,now) && now>=next_frame){
            next_frame=now+40;FrameTicket ticket;
            const auto row=static_cast<std::size_t>((sequence%1080)*1920*4);
            std::fill_n(pixels.bgra.begin()+row,1920*4,static_cast<std::uint8_t>(sequence*13));
            if(pool.publish(pixels,runtime.generation(),++sequence,now,ticket)){
                need(runtime.publish_frame(sequence,now),"owned_publish_gate");++counts.frames;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    runtime.close(desktop);write_exact(status.value,&counts,sizeof(counts));return 0;
}
int parent(){
    struct Window {HWND value=nullptr;~Window(){if(value)DestroyWindow(value);}} window;
    WNDCLASSW kind{};kind.lpfnWndProc=DefWindowProcW;kind.hInstance=GetModuleHandleW(nullptr);kind.lpszClassName=L"GuardDeskOwnedHandoff";
    need(RegisterClassW(&kind)!=0,"owned_window_class");
    window.value=CreateWindowExW(WS_EX_NOACTIVATE|WS_EX_TOOLWINDOW,kind.lpszClassName,L"GuardDesk owned synthetic media test",WS_OVERLAPPEDWINDOW,80,80,640,400,nullptr,nullptr,kind.hInstance,nullptr);
    need(window.value!=nullptr,"owned_window_create");ShowWindow(window.value,SW_SHOWNOACTIVATE);
    NativeViewer viewer(window.value,id(),true);
    auto options=[](bool endpoint){MediaPeerOptions value;value.session=id();value.transport=7;value.endpoint=endpoint;value.can_control=true;value.owned_loopback=true;value.local_ipv4=value.peer_ipv4={"127.0.0.1"};value.consent_deadline=GetTickCount64()+60000;return value;};
    MediaPeer receiver(options(false),[&](auto generation,bool active){viewer.state(generation,active);},[&](SharedFrame frame){return viewer.submit(std::move(frame));});
    MediaPeer sender(options(true),[](auto,bool){},[](auto){return false;});
    auto grant=[&]{need(receiver.grant(GetTickCount64()+3000) && sender.grant(GetTickCount64()+3000),"owned_media_lease");};grant();
    need(receiver.make_offer(),"owned_offer");auto offer=receiver.take_signal();need(offer && sender.signal(*offer),"owned_answer");auto answer=sender.take_signal();need(answer && receiver.signal(*answer),"owned_signal");
    FramePool storage(id(),1920,1080);std::array<Handle,2> read,write;
    for(unsigned i=0;i<2;++i){read.at(i).value=storage.duplicate_read(i,GetCurrentProcess());write.at(i).value=storage.duplicate_write(i,GetCurrentProcess());need(SetHandleInformation(write.at(i).value,HANDLE_FLAG_INHERIT,HANDLE_FLAG_INHERIT)!=FALSE,"owned_inherit_mapping");}
    SECURITY_ATTRIBUTES attributes{sizeof(attributes),nullptr,TRUE};Handle command_read,command_write,status_read,status_write;
    need(CreatePipe(&command_read.value,&command_write.value,&attributes,65536) && CreatePipe(&status_read.value,&status_write.value,&attributes,4096),"owned_pipes");
    need(SetHandleInformation(command_write.value,HANDLE_FLAG_INHERIT,0) && SetHandleInformation(status_read.value,HANDLE_FLAG_INHERIT,0),"owned_private_handles");
    std::array<HANDLE,4> inherited{command_read.value,status_write.value,write.at(0).value,write.at(1).value};
    SIZE_T size=0;InitializeProcThreadAttributeList(nullptr,1,0,&size);need(size>0 && size<65536,"owned_attribute_size");
    std::vector<std::uint8_t> buffer(size);auto* list=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer.data());need(InitializeProcThreadAttributeList(list,1,0,&size)!=FALSE,"owned_attribute_list");
    struct Attributes{LPPROC_THREAD_ATTRIBUTE_LIST value;~Attributes(){DeleteProcThreadAttributeList(value);}} scoped{list};
    need(UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited.data(),sizeof(inherited),nullptr,nullptr)!=FALSE,"owned_handle_list");
    std::array<wchar_t,32768> image{};const auto length=GetModuleFileNameW(nullptr,image.data(),static_cast<DWORD>(image.size()));need(length>0 && length<image.size(),"owned_image");
    std::wstring line=L"\""+std::wstring(image.data())+L"\" --owned-producer";
    for(auto handle:inherited)line+=L" "+std::to_wstring(reinterpret_cast<std::uintptr_t>(handle));
    STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.lpAttributeList=list;PROCESS_INFORMATION pi{};
    need(CreateProcessW(image.data(),line.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&startup.StartupInfo,&pi)!=FALSE,"owned_child_launch");
    Handle process,thread;process.value=pi.hProcess;thread.value=pi.hThread;
    struct ChildCleanup{HANDLE process;~ChildCleanup(){if(WaitForSingleObject(process,1000)!=WAIT_OBJECT_0){TerminateProcess(process,0xe2000001u);WaitForSingleObject(process,1000);}}} cleanup{process.value};
    CloseHandle(command_read.value);command_read.value=nullptr;CloseHandle(status_write.value);status_write.value=nullptr;
    for(auto& handle:write){CloseHandle(handle.value);handle.value=nullptr;}
    std::uint64_t command_sequence=0,last_grant=0,last_move=0,last_release=0,presented=0,last_generation=0;
    std::array<std::uint64_t,2> consumed{};unsigned sent_moves=0,releases=0,source_rejected=0;
    std::vector<std::uint64_t> presentation_latency;PointerPacer pointer_pacer;
    auto send=[&](ipc::Message message){message.header.sequence=++command_sequence;const auto bytes=ipc::encode_control(message,ipc::Direction::broker_to_worker);write_exact(command_write.value,bytes.data(),static_cast<DWORD>(bytes.size()));};
    auto iterate=[&](unsigned phase){
        const auto now=GetTickCount64();grant();
        if(now-last_grant>=300){last_grant=now;std::vector<std::uint8_t> payload(24);put(payload,0,now+3000,8);put(payload,8,1,8);put(payload,16,1,4);send({{ipc::Kind::lease,24,id(),0,0,0,7},payload});}
        MSG message{};unsigned budget=0;while(budget++<64 && PeekMessageW(&message,window.value,0,0,PM_REMOVE)){TranslateMessage(&message);DispatchMessageW(&message);}
        receiver.pump();sender.pump();need(!receiver.ended() && !sender.ended(),"owned_media_ended");
        while(auto command=sender.take_control())send(std::move(*command));
        try{if(sender.connected()){
            const std::array<FrameTicket,2> tickets{peek_shared_frame(read.at(0).value,storage.mapping_bytes(),id()),peek_shared_frame(read.at(1).value,storage.mapping_bytes(),id())};
            if(!tickets.at(0).generation && !tickets.at(1).generation && last_generation){sender.pause_source(last_generation);last_generation=0;}
            for(unsigned i=0;i<2;++i){const auto& ticket=tickets.at(i);if(!ticket.generation || !ticket.sequence || ticket.sequence<=consumed.at(i))continue;
                auto frame=read_shared_frame(read.at(i).value,storage.mapping_bytes(),id(),ticket.generation,GetTickCount64());
                if(frame.ticket.sequence<=consumed.at(i))continue;
                if(!sender.frame(frame))++source_rejected;last_generation=frame.ticket.generation;consumed.at(i)=frame.ticket.sequence;
                send({{ipc::Kind::consumed,0,id(),frame.ticket.generation,0,frame.ticket.sequence,7},{}});
            }
        }}catch(const FrameRetry&){}
        if(auto ticket=viewer.present()){
            need(receiver.presented(*ticket),"owned_present_ACK");++presented;
            need(GetTickCount64()>=ticket->tick,"owned_future_frame_tick");
            if(presentation_latency.size()<1024)presentation_latency.push_back(GetTickCount64()-ticket->tick);
        }
        if(phase && now-last_move>=10){last_move=now;std::vector<std::uint8_t> move(24);move.at(0)=3;move.at(4)=100;move.at(8)=80;pointer_pacer.replace(std::move(move),now);}
        if(auto move=pointer_pacer.take(now)){if(receiver.input(*move))++sent_moves;}
        if(phase==2 && now-last_release>=200){last_release=now;receiver.release_all();++releases;}
        need(WaitForSingleObject(process.value,0)==WAIT_TIMEOUT,"owned_producer_exited");
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    };
    const auto warmup=GetTickCount64()+12000;while(presented<3 && GetTickCount64()<warmup)iterate(0);
    need(presented>=3,"owned_visible_present_unavailable");
    for(unsigned phase=0;phase<3;++phase){const auto before=presented,start=GetTickCount64();const auto old_moves=sent_moves;presentation_latency.clear();
        while(GetTickCount64()-start<5000)iterate(phase);
        const auto tx=sender.stats(),rx=receiver.stats();
        need(!presentation_latency.empty(),"owned_no_latency_samples");std::sort(presentation_latency.begin(),presentation_latency.end());
        const auto p95=presentation_latency.at((presentation_latency.size()-1)*95/100);
        std::cout<<"{\"phase\":"<<phase<<",\"presented_delta\":"<<presented-before<<",\"encoded\":"<<tx.encoded<<",\"decoded\":"<<rx.decoded<<",\"moves\":"<<sent_moves-old_moves<<",\"source_rejected\":"<<source_rejected<<",\"frame_to_present_p95_ms\":"<<p95<<",\"latency_samples\":"<<presentation_latency.size()<<"}\n"<<std::flush;
        need(presented>=before+40 && p95<500 && tx.codec_failures==0 && rx.codec_failures==0,"owned_handoff_stalled");if(phase)need(sent_moves>=old_moves+40 && sent_moves<=old_moves+153,"owned_moves_not_paced");
    }
    send({{ipc::Kind::stop,0,id(),0,0,0,7},{}});need(WaitForSingleObject(process.value,3000)==WAIT_OBJECT_0,"owned_child_stop");
    Counts counts{};need(read_exact(status_read.value,&counts,sizeof(counts)),"owned_counts");DWORD code=1;need(GetExitCodeProcess(process.value,&code) && code==0,"owned_child_exit");
    receiver.request_stop();sender.request_stop();receiver.pump();sender.pump();
    need(counts.inputs>=20 && counts.clears==2 && counts.consumed>=20,"owned_core_progress");
    std::cout<<"{\"passed\":true,\"visible_HWND_Present\":true,\"child_FramePool_handoff\":true,\"SessionRuntime_input_batches\":"<<counts.inputs<<",\"clear_count\":"<<counts.clears<<",\"consumed\":"<<counts.consumed<<",\"releases\":"<<releases<<",\"synthetic_pixels\":true,\"actual_desktop_capture\":false,\"OS_input\":false,\"SYSTEM\":false}\n";return 0;
}
}
int wmain(int argc,wchar_t** argv){SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32|LOAD_LIBRARY_SEARCH_APPLICATION_DIR);try{
    if(argc==1)return parent();
    if(argc!=6)return 2;
#pragma clang unsafe_buffer_usage begin
    const std::wstring mode(argv[1]);const std::array<std::wstring,4> values{argv[2],argv[3],argv[4],argv[5]};
#pragma clang unsafe_buffer_usage end
    if(mode!=L"--owned-producer")return 2;return child(values);
}catch(const std::exception& error){std::cerr<<error.what()<<" win32="<<GetLastError()<<'\n';return 1;}}
