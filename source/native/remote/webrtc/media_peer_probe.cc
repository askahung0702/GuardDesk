#include "media_peer.hpp"
#include "mis_native.hpp"
#include "media_wire.hpp"
#include "session.hpp"
#include <atomic>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <mutex>
#include <optional>
namespace {
void require(bool value){if(!value)throw std::runtime_error("product_media_integration");}
remote::MediaPeerOptions options(bool endpoint){remote::MediaPeerOptions value;value.session[0]=9;value.transport=7;
    value.consent_deadline=GetTickCount64()+30000;value.endpoint=endpoint;value.can_control=true;value.owned_loopback=true;
    value.local_ipv4={"127.0.0.1"};value.peer_ipv4={"127.0.0.1"};return value;}
unsigned stage=0;
// Bounded local-only regression for the field's 1080p input/media interaction.
// A synthetic sink supplies ACKs; this does NOT test HWND Present, DXGI,
// SessionRuntime, SYSTEM launch, UAC or SendInput on an actual desktop.
void input_stress(bool backlog_reproduction=false){
    stage=20;
    std::atomic<unsigned> frames{0},pauses{0};
    std::mutex output_mutex;std::optional<remote::FrameTicket> latest;
    auto configured=[](bool endpoint){auto value=options(endpoint);value.consent_deadline=GetTickCount64()+60000;return value;};
    remote::MediaPeer receiver(configured(false),[&](auto,bool active){if(!active)++pauses;},[&](remote::SharedFrame frame){
        require(frame.ticket.width==1920 && frame.ticket.height==1080 && frame.pixels.bgra.size()==1920*1080*4);
        {std::lock_guard<std::mutex> lock(output_mutex);latest=frame.ticket;}++frames;return true;});
    remote::MediaPeer sender(configured(true),[](auto,bool){},[](auto){return false;});
    auto renew=[&]{require(receiver.grant(GetTickCount64()+3000));require(sender.grant(GetTickCount64()+3000));};renew();
    require(receiver.make_offer());auto offer=receiver.take_signal();require(offer && sender.signal(*offer));
    auto answer=sender.take_signal();require(answer && receiver.signal(*answer));
    remote::FramePool pool(options(true).session,1920,1080);
    struct Mappings{std::array<HANDLE,2> values{};~Mappings(){for(auto handle:values)if(handle)CloseHandle(handle);}} mappings;
    for(unsigned i=0;i<2;++i)mappings.values.at(i)=pool.duplicate_read(i,GetCurrentProcess());
    remote::Pixels pixels{1920,1080,std::vector<std::uint8_t>(1920*1080*4,100)};
    std::uint64_t sequence=0,last_push=0,last_move=0,last_release=0,last_ack=0;
    unsigned input_sent=0,input_received=0,release_sent=0,release_received=0,accepted=0,rejected=0;
    auto iteration=[&](unsigned phase){
        renew();receiver.pump();sender.pump();require(!receiver.ended() && !sender.ended());
        while(auto command=sender.take_control()){
            if(command->header.kind==remote::ipc::Kind::input)++input_received;
            if(command->header.kind==remote::ipc::Kind::release_all)++release_received;
        }
        const auto now=GetTickCount64();
        if(sender.connected() && now-last_push>=40){
            last_push=now;
            // Animate only an owned pattern; never read screen pixels.
            const auto offset=static_cast<std::size_t>((sequence%1080)*1920*4);
            std::fill_n(pixels.bgra.begin()+offset,1920*4,static_cast<std::uint8_t>(sequence*17));
            remote::FrameTicket ticket;require(pool.publish(pixels,2,++sequence,now,ticket));
            auto frame=remote::read_shared_frame(mappings.values.at(ticket.slot),pool.mapping_bytes(),ticket.session,2,GetTickCount64());
            if(sender.frame(frame))++accepted;else ++rejected;
            require(pool.release(ticket));
        }
        std::optional<remote::FrameTicket> decoded;
        {std::lock_guard<std::mutex> lock(output_mutex);decoded=latest;}
        if(decoded && decoded->sequence>last_ack && receiver.presented(*decoded))last_ack=decoded->sequence;
        if(phase && now-last_move>=(phase==2?16u:50u)){
            last_move=now;std::vector<std::uint8_t> move(24);move.at(0)=3;
            // Fixed in-bounds pointer fixture, transmitted but never applied.
            move.at(4)=100;move.at(8)=80;if(receiver.input(move))++input_sent;
        }
        if(phase==2 && now-last_release>=200){last_release=now;receiver.release_all();++release_sent;}
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    };
    const auto warmup=GetTickCount64()+10000;
    while(frames<3 && GetTickCount64()<warmup)iteration(0);
    require(frames>=3);const auto pauses_before=pauses.load();
    if(backlog_reproduction){
        // Reproduce the current failure policy using real local WebRTC and
        // synthetic pixels only. This is evidence of a code path, not proof
        // that a particular field session hit it. No SendInput or capture.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        while(sender.take_control()){}
        require(!sender.ended());
        std::vector<std::uint8_t> move(24);move.at(0)=3;move.at(4)=100;move.at(8)=80;
        require(receiver.input(move));
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        const auto command=sender.take_control();
        require(command && command->header.kind==remote::ipc::Kind::release_all && command->payload.empty() &&
            command->header.payload_bytes==0 && command->header.desktop_generation==0 && command->header.frame_sequence==0 && !sender.ended());
        // Converted packets must still pass the real wire contract.
        require(remote::ipc::control_message(remote::ipc::encode_control(*command,remote::ipc::Direction::broker_to_worker),
            remote::ipc::Direction::broker_to_worker).header.sequence==command->header.sequence);
        std::optional<remote::FrameTicket> old_ack;{std::lock_guard<std::mutex> lock(output_mutex);old_ack=latest;}
        require(old_ack && receiver.presented(*old_ack));
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        require(!sender.take_control() && !sender.ended()); // expired ACK discarded
        receiver.release_all();
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        const auto cleanup=sender.take_control();
        require(cleanup && cleanup->header.kind==remote::ipc::Kind::release_all && !sender.ended() && !receiver.input(move));
        const auto before=frames.load();const auto resume_until=GetTickCount64()+1500;
        while(GetTickCount64()<resume_until)iteration(1);
        require(frames>=before+3 && input_received>=10 && !sender.ended() && !receiver.ended());
        // An actual authority loss still terminates; recovery does not renew it.
        require(!sender.grant(GetTickCount64()) && sender.ended());
        std::cout<<"{\"stale_input_became_cleanup\":true,\"stale_ack_discarded\":true,\"late_cleanup_preserved\":true,\"queued_input_wait_ms\":250,\"media_and_fresh_input_resumed\":true,\"expired_authority_still_terminal\":true,\"real_local_webrtc\":true,\"os_input\":false,\"desktop_capture\":false,\"field_cause_confirmed\":false}\n";
        receiver.request_stop();sender.request_stop();receiver.pump();sender.pump();return;
    }
    for(unsigned phase=0;phase<3;++phase){
        stage=21+phase;const auto start=GetTickCount64();const auto before=frames.load();
        const auto sent_before=input_sent,received_before=input_received,releases_before=release_received;
        const auto encoded_before=sender.stats().encoded;
        while(GetTickCount64()-start<5000)iteration(phase);
        const auto tx=sender.stats(),rx=receiver.stats();
        std::cout<<"{\"phase\":"<<phase<<",\"milliseconds\":"<<GetTickCount64()-start
            <<",\"decoded_delta\":"<<frames-before<<",\"encoded_delta\":"<<tx.encoded-encoded_before
            <<",\"input_sent_delta\":"<<input_sent-sent_before<<",\"input_received_delta\":"<<input_received-received_before
            <<",\"release_received_delta\":"<<release_received-releases_before<<",\"source_accepted\":"<<accepted
            <<",\"source_rejected\":"<<rejected<<",\"codec_errors\":"<<tx.codec_failures+rx.codec_failures
            <<",\"unknown_timestamps\":"<<tx.unknown_timestamps+rx.unknown_timestamps<<"}\n"<<std::flush;
        const auto queue=receiver.send_diagnostics();require(queue[0]==1 && queue[5]<=32);
        std::cout<<"{\"phase\":"<<phase<<",\"native_send_queued\":"<<queue[1]<<",\"native_send_transmitted\":"<<queue[2]
            <<",\"native_send_discarded\":"<<queue[3]<<",\"native_send_high_water\":"<<queue[5]<<",\"send_queue_max_us\":"<<queue[7]<<",\"queue_us_bins\":[";
        for(unsigned i=8;i<16;++i)std::cout<<(i==8?"":",")<<queue[i];std::cout<<"]}\n"<<std::flush;
        require(frames>=before+10 && tx.encoded>=encoded_before+10 && pauses==pauses_before);
        require(tx.codec_failures+rx.codec_failures==0 && tx.unknown_timestamps+rx.unknown_timestamps==0);
        if(phase)require(input_sent>=sent_before+10 && input_received>=received_before+10);
        if(phase==2)require(release_received>=releases_before+10);
    }
    receiver.request_stop();sender.request_stop();receiver.pump();sender.pump();
    std::cout<<"{\"passed\":true,\"owned_1080p_input_stress\":true,\"synthetic_sink_ack\":true,\"os_input\":false,\"desktop_capture\":false,\"LAB01_tested\":false}\n";
}
BOOL CALLBACK find_owned_view(HWND window,LPARAM value){
    wchar_t name[64]{};GetClassNameW(window,name,64);
    if(std::wstring(name)==L"GuardDeskNativeMediaViewerV1")*reinterpret_cast<HWND*>(value)=window;
    return TRUE;
}
WNDPROC owned_original_proc=nullptr;unsigned owned_modal_entered=0,owned_modal_exited=0,owned_modal_ticks=0;
LRESULT CALLBACK owned_modal_proc(HWND w,UINT m,WPARAM a,LPARAM b){
    if(m==WM_ENTERSIZEMOVE)++owned_modal_entered;if(m==WM_EXITSIZEMOVE)++owned_modal_exited;
    if(m==WM_TIMER && a==0x4744)++owned_modal_ticks;
    return CallWindowProcW(owned_original_proc,w,m,a,b);
}
void modal_window_test(){
    stage=41;GD_MIS_CONFIG c{};c.bytes=sizeof(c);c.version=c.can_control=c.owned_loopback=c.hidden=c.software=1;
    c.session[0]=31;c.transport=1;c.consent_deadline=remote::ipc::no_session_deadline;
    c.local_count=c.peer_count=1;c.local_ipv4[0]=c.peer_ipv4[0]=0x0100007f;
    void* view=nullptr;require(GDMisCreate(&c,&view)==0);struct Close{void* v;~Close(){GDMisClose(v);}} close{view};
    HWND window=nullptr;EnumThreadWindows(GetCurrentThreadId(),find_owned_view,reinterpret_cast<LPARAM>(&window));require(window!=nullptr);
    ShowWindow(window,SW_SHOWNOACTIVATE);
    owned_original_proc=reinterpret_cast<WNDPROC>(SetWindowLongPtrW(window,GWLP_WNDPROC,reinterpret_cast<LONG_PTR>(&owned_modal_proc)));require(owned_original_proc!=nullptr);
    for(WPARAM command:{WPARAM(SC_MOVE),WPARAM(SC_SIZE)}){
        require(GDMisPostReply(view,GetTickCount64()+3000,nullptr,0)==0);
        std::atomic<bool> returned{false};
        std::thread cancel([&]{
            std::this_thread::sleep_for(std::chrono::milliseconds(40));
            // Messages go only to this test's HWND. No SendInput/global hook.
            PostMessageW(window,WM_KEYDOWN,VK_ESCAPE,0);
            for(unsigned i=0;i<30 && !returned;++i)std::this_thread::sleep_for(std::chrono::milliseconds(10));
            if(!returned)PostMessageW(window,WM_CLOSE,0,0);
        });
        SendMessageW(window,WM_SYSCOMMAND,command,0);returned=true;cancel.join();
        require(GDMisPump(view)==0);
    }
    require(owned_modal_entered>=2 && owned_modal_exited>=2 && owned_modal_ticks>0);
    require(GDMisPostReply(view,GetTickCount64()+60,nullptr,0)==0);std::uint32_t expired_before_cancel=0;
    std::thread expired_cancel([&]{std::this_thread::sleep_for(std::chrono::milliseconds(150));
        GDMisEndReason(view,&expired_before_cancel);PostMessageW(window,WM_KEYDOWN,VK_ESCAPE,0);PostMessageW(window,WM_CLOSE,0,0);});
    SendMessageW(window,WM_SYSCOMMAND,SC_MOVE,0);expired_cancel.join();
    SetWindowLongPtrW(window,GWLP_WNDPROC,reinterpret_cast<LONG_PTR>(owned_original_proc));ShowWindow(window,SW_HIDE);
    require(expired_before_cancel==2 && GDMisPump(view)==ERROR_CANCELLED);
    std::cout<<"{\"actual_Windows_modal_move_size\":true,\"entered\":"<<owned_modal_entered<<",\"exited\":"<<owned_modal_exited
        <<",\"modal_timer_ticks\":"<<owned_modal_ticks<<",\"expiry_inside_modal\":true,\"OS_input\":false,\"center_started\":false,\"desktop_capture\":false}\n";
}
void preconnect_test(){
    stage=40;GD_MIS_CONFIG c{};c.bytes=sizeof(c);c.version=c.can_control=c.owned_loopback=c.hidden=c.software=1;
    c.session[0]=31;c.transport=1;c.consent_deadline=remote::ipc::no_session_deadline;
    c.local_count=c.peer_count=1;c.local_ipv4[0]=c.peer_ipv4[0]=0x0100007f;
    void* view=nullptr;require(GDMisCreate(&c,&view)==0);struct Close{void* v;~Close(){GDMisClose(v);}} close{view};
    HWND window=nullptr;EnumThreadWindows(GetCurrentThreadId(),find_owned_view,reinterpret_cast<LPARAM>(&window));require(window!=nullptr);
    // Before any grant, and with grant but no offer/open channel. No real
    // desktop, activation, input injection or endpoint connection occurs.
    for(unsigned i=0;i<100;++i){
        if(i>=10)require(GDMisPostReply(view,GetTickCount64()+3000,nullptr,0)==0);
        for(UINT m:{WM_CANCELMODE,WM_KILLFOCUS,WM_CAPTURECHANGED}){
            SendMessageW(window,m,0,0);require(GDMisPump(view)==0);
        }
        SendMessageW(window,WM_SIZE,i%2?SIZE_MINIMIZED:SIZE_RESTORED,MAKELPARAM(960,600));require(GDMisPump(view)==0);
    }
    std::uint32_t reason=99;require(GDMisEndReason(view,&reason)==0 && reason==0);
    require(GDMisStop(view)==0 && GDMisPump(view)==ERROR_CANCELLED);
    require(GDMisEndReason(view,&reason)==0 && reason==1);
    require(GDMisPostReply(view,GetTickCount64()+1000,nullptr,0)==ERROR_ACCESS_DENIED);
    require(GDMisEndReason(view,&reason)==0 && reason==1); // teardown/late grant cannot overwrite first cause
    std::cout<<"{\"preconnect_focus_cycles\":100,\"live_after_cleanup\":true,\"first_stop_cause_preserved\":true,\"hidden_owned_HWND\":true,\"OS_input\":false,\"center_started\":false}\n";
}
void grant_stall_test(){
    stage=30;GD_MIS_CONFIG config{};config.bytes=sizeof(config);config.version=1;config.owned_loopback=1;config.session[0]=3;
    config.transport=4;config.consent_deadline=GetTickCount64()+10000;config.local_count=config.peer_count=1;
    config.local_ipv4[0]=config.peer_ipv4[0]=0x0100007f;config.hidden=config.software=1;void* view=nullptr;
    require(GDMisCreate(&config,&view)==0 && view);
    struct Close{void* value;~Close(){GDMisClose(value);}} close{view};
    require(GDMisGrant(view,GetTickCount64()+1000)==0);
    HANDLE posted_event=CreateEventW(nullptr,TRUE,FALSE,nullptr);require(posted_event!=nullptr);
    DWORD posted=ERROR_GEN_FAILURE;
    std::thread manager([&]{posted=GDMisPostReply(view,GetTickCount64()+3000,nullptr,0);SetEvent(posted_event);});
    // Simulate a busy native UI/SDP owner. A genuine fresh grant arrives while
    // the old grant is still valid; neither arbitrary extension nor retry.
    const auto delivered=WaitForSingleObject(posted_event,500);manager.join();CloseHandle(posted_event);
    require(delivered==WAIT_OBJECT_0 && posted==0);
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    const auto resumed=GDMisPump(view);
    std::cout<<"{\"grant_posted\":true,\"resumed_pump_code\":"<<resumed<<"}\n"<<std::flush;
    require(resumed==0);
    require(GDMisPostReply(view,GetTickCount64(),nullptr,0)==ERROR_ACCESS_DENIED);
    require(GDMisStop(view)==0 && GDMisPump(view)==ERROR_CANCELLED);
    require(GDMisPostReply(view,GetTickCount64()+1000,nullptr,0)==ERROR_ACCESS_DENIED);
    stage=31;void* expired_view=nullptr;require(GDMisCreate(&config,&expired_view)==0 && expired_view);
    Close expired_close{expired_view};
    stage=32;require(GDMisGrant(expired_view,GetTickCount64()+100)==0);
    std::this_thread::sleep_for(std::chrono::milliseconds(180));
    stage=33;const auto late_code=GDMisPostReply(expired_view,GetTickCount64()+1000,nullptr,0);
    const auto expired_pump=GDMisPump(expired_view);
    std::cout<<"{\"late_grant_code\":"<<late_code<<",\"expired_pump_code\":"<<expired_pump<<"}\n"<<std::flush;
    require(late_code==ERROR_ACCESS_DENIED && expired_pump==ERROR_CANCELLED);
    std::cout<<"{\"native_ui_stall_ms\":1100,\"fresh_grant_applied_before_prior_expiry\":true,\"expired_grant_refused\":true,\"stop_cannot_be_revived\":true,\"hidden_owned_window\":true,\"os_input\":false,\"desktop_capture\":false}\n";
}
void test(){
    stage=1;
    // Owned metadata/shape fixture, never an output/desktop capture.
    remote::CursorUpdate cursor;cursor.session=options(true).session;cursor.transport=7;cursor.generation=2;cursor.sequence=1;
    cursor.source_width=640;cursor.source_height=360;cursor.x=100;cursor.y=80;cursor.shape=1;
    require(remote::convert_cursor_shape(cursor,2,2,2,8,0,0,std::vector<std::uint8_t>(16,255)));
    auto encoded_cursor=remote::encode_cursor(cursor);require(remote::decode_cursor(encoded_cursor).bgra==cursor.bgra);
    auto malformed=encoded_cursor;malformed.at(88)=1;bool refused=false;try{remote::decode_cursor(malformed);}catch(...){refused=true;}require(refused);
    auto unsupported=cursor;require(!remote::convert_cursor_shape(unsupported,2,65,1,260,0,0,std::vector<std::uint8_t>(260)) && unsupported.mode==remote::CursorMode::unsupported);
    {remote::FramePool pool(cursor.session,640,360);auto read=pool.duplicate_read(0,GetCurrentProcess());require(read!=nullptr);
        struct Close{HANDLE value;~Close(){CloseHandle(value);}} close{read};
        require(!MapViewOfFile(read,FILE_MAP_WRITE,0,0,pool.mapping_bytes()));
        require(pool.publish_cursor(cursor,GetTickCount64()));
        require(remote::read_shared_cursor(read,pool.mapping_bytes(),cursor.session,7,2,GetTickCount64()).has_value());
        require(!remote::read_shared_cursor(read,pool.mapping_bytes(),cursor.session,7,3,GetTickCount64()));
        pool.clear();require(!remote::read_shared_cursor(read,pool.mapping_bytes(),cursor.session,7,2,GetTickCount64()));
        std::atomic<bool> done{false};std::thread writer([&]{for(unsigned i=0;i<100;++i){pool.publish_cursor(cursor,GetTickCount64());pool.clear();}done=true;});
        unsigned reads=0;try{while(!done || reads<100){remote::read_shared_cursor(read,pool.mapping_bytes(),cursor.session,7,2,GetTickCount64());++reads;}}
        catch(...){writer.join();throw;}writer.join();}
    auto mono=cursor;require(remote::convert_cursor_shape(mono,1,1,2,1,0,0,{0,0}) && mono.bgra.at(3)==255);
    require(remote::convert_cursor_shape(mono,1,1,2,1,0,0,{128,128}) && !mono.xor_mask.empty());
    mono.x=mono.y=0;mono=remote::compose_cursor(mono,remote::Pixels{1,1,{17,34,51,255}},1,1);
    require(mono.xor_mask.empty() && mono.bgra==std::vector<std::uint8_t>({238,221,204,255}));
    std::atomic<unsigned> frames{0},paused{0},cursors{0};std::mutex decoded_mutex;std::optional<remote::FrameTicket> decoded_ticket;
    remote::MediaPeer receiver(options(false),[&](auto,bool active){if(!active)++paused;},[&](remote::SharedFrame frame){
        require(frame.ticket.session[0]==9 && frame.ticket.width==640 && frame.ticket.height==360 && frame.pixels.bgra.size()==640*360*4);{std::lock_guard<std::mutex> lock(decoded_mutex);decoded_ticket=frame.ticket;}++frames;return true;},[&](remote::CursorUpdate value){require(value.generation==2 && value.shape==1 && value.bgra.size()==16);++cursors;return true;});
    stage=2;remote::MediaPeer sender(options(true),[](auto,bool){},[](auto){return false;});
    require(!sender.cursor(cursor));
    auto renew=[&]{require(receiver.grant(GetTickCount64()+3000));require(sender.grant(GetTickCount64()+3000));};renew();
    stage=3;require(receiver.make_offer());auto offer=receiver.take_signal();require(offer && offer->offer);renew();
    stage=4;require(sender.signal(*offer));auto answer=sender.take_signal();require(answer && !answer->offer);renew();stage=5;require(receiver.signal(*answer));
    stage=6;std::uint64_t sequence=0,last_frame=0;const auto until=GetTickCount64()+10000;
    while(GetTickCount64()<until && frames<3){renew();receiver.pump();sender.pump();
        if(sender.connected() && GetTickCount64()-last_frame>=70){last_frame=GetTickCount64();remote::SharedFrame frame;
            frame.ticket={options(true).session,2,++sequence,last_frame,static_cast<unsigned>(sequence%2),640,360};
            frame.pixels={640,360,std::vector<std::uint8_t>(640*360*4,static_cast<std::uint8_t>(sequence*17))};require(sender.frame(frame));}
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    stage=7;if(frames<3 || !receiver.connected() || !sender.connected()){
        const auto tx=sender.stats(),rx=receiver.stats();std::cerr<<"peer_diagnostics frames="<<frames<<" tx_encoded="<<tx.encoded<<" rx_decoded="<<rx.decoded
        <<" failures="<<tx.codec_failures+rx.codec_failures<<" unknown="<<tx.unknown_timestamps+rx.unknown_timestamps
        <<" tx_open="<<tx.channel_open<<" rx_open="<<rx.channel_open<<" tx_connected="<<tx.peer_connected<<" rx_connected="<<rx.peer_connected<<"\n";}
    require(frames>=3 && receiver.connected() && sender.connected());
    auto wrong_epoch=cursor;wrong_epoch.generation=999;require(!sender.cursor(wrong_epoch));
    for(unsigned i=0;i<100 && !cursors;++i){renew();receiver.pump();sender.pump();sender.cursor(cursor);std::this_thread::sleep_for(std::chrono::milliseconds(5));}
    require(cursors>0);
    remote::FrameTicket forged{options(true).session,2,999,GetTickCount64(),0,640,360};require(!receiver.presented(forged));
    {std::lock_guard<std::mutex> lock(decoded_mutex);require(decoded_ticket && receiver.presented(*decoded_ticket));}
    require(!receiver.release_up(2,4) && !receiver.release_up(1,231) && !receiver.release_up(3,1));
    // Exercise media_entry's real serializer and broker parser before the
    // SessionRuntime ledger. This sink never invokes an OS input API.
    const auto started=GetTickCount64();unsigned injected=0;
    remote::SessionRuntime runtime(options(true).session,7,started,started+10000,
        [&](const auto& batch){injected+=static_cast<unsigned>(batch.size());return static_cast<UINT>(batch.size());},[]{});
    remote::DesktopObservation desk{true,true,false,1,{0,0,640,360},{0,0,640,360}};
    std::uint64_t broker_sequence=1,media_sequence=0;
    std::vector<std::uint8_t> lease(24);auto put=[&](unsigned at,std::uint64_t value,unsigned n){for(unsigned i=0;i<n;++i)lease.at(at+i)=static_cast<std::uint8_t>(value>>(8*i));};
    put(0,started+5000,8);put(8,1,8);put(16,1,4);
    require(runtime.command({{remote::ipc::Kind::lease,24,options(true).session,0,broker_sequence,0,7},lease},started,desk));
    require(runtime.observe(desk,started));desk.identity=2;require(runtime.observe(desk,started) && runtime.generation()==2);
    {std::lock_guard<std::mutex> lock(decoded_mutex);require(runtime.publish_frame(decoded_ticket->sequence,GetTickCount64()));}
    auto forward=[&](remote::ipc::Message command){
        auto packet=remote::ipc::encode_control(command,remote::ipc::Direction::broker_to_worker);
        const auto wire=remote::ipc::encode_media({remote::ipc::MediaKind::network_control,options(true).session,7,++media_sequence,packet},remote::ipc::MediaDirection::media_to_broker);
        const auto decoded=remote::ipc::media_message(wire,remote::ipc::MediaDirection::media_to_broker);
        auto worker=remote::ipc::control_message(decoded.payload,remote::ipc::Direction::broker_to_worker);
        worker.header.sequence=++broker_sequence;return runtime.command(worker,GetTickCount64(),desk);
    };
    for(unsigned i=0;i<100 && broker_sequence==1;++i){receiver.pump();sender.pump();while(auto command=sender.take_control())require(forward(*command));std::this_thread::sleep_for(std::chrono::milliseconds(2));}
    require(broker_sequence>1);
    std::vector<std::uint8_t> down(24);down[0]=2;down[1]=1;down[2]=1;require(receiver.input(down));
    for(unsigned i=0;i<100 && !runtime.held();++i){receiver.pump();sender.pump();while(auto command=sender.take_control())require(forward(*command));std::this_thread::sleep_for(std::chrono::milliseconds(2));}
    require(runtime.held() && injected==2); // position plus button-down
    require(receiver.release_up(2,1));bool targeted=false;
    for(unsigned i=0;i<100 && !targeted;++i){renew();receiver.pump();sender.pump();auto command=sender.take_control();
        targeted=command && command->header.kind==remote::ipc::Kind::release_all && command->payload.size()==8 && command->payload[0]==2 && command->payload[2]==1 && command->header.desktop_generation==2;
        if(targeted)require(forward(*command));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));}
    require(targeted && !runtime.held() && injected==3 && !runtime.ended());std::cout<<"targeted_cleanup_real_datachannel_media_wire_broker_session_ledger=true\n";
    stage=8;receiver.release_all();require(!receiver.release_up(2,1));bool release=false;
    for(unsigned i=0;i<100 && !release;++i){renew();receiver.pump();sender.pump();auto command=sender.take_control();release=command && command->header.kind==remote::ipc::Kind::release_all && command->payload.empty();std::this_thread::sleep_for(std::chrono::milliseconds(5));}
    stage=9;require(release);
    // Focus cleanup itself must not pause the authenticated video stream.
    // Exercise the real source/encoder/channel/decoder after cleanup while
    // keeping this test limited to owned synthetic pixels and no OS input.
    const auto before_cleanup_frames=frames.load(),before_cleanup_pauses=paused.load();
    const auto cleanup_deadline=GetTickCount64()+5000;
    while(GetTickCount64()<cleanup_deadline && frames<before_cleanup_frames+3){
        renew();receiver.pump();sender.pump();
        remote::SharedFrame frame;
        frame.ticket={options(true).session,2,++sequence,GetTickCount64(),0,640,360};
        frame.pixels={640,360,std::vector<std::uint8_t>(640*360*4,71)};
        require(sender.frame(frame));std::this_thread::sleep_for(std::chrono::milliseconds(70));
    }
    require(frames>=before_cleanup_frames+3 && paused==before_cleanup_pauses);
    std::cout<<"focus_release_preserves_real_media_stream=true\n";
    sender.pause_source(2);
    for(unsigned i=0;i<100 && paused==0;++i){receiver.pump();sender.pump();std::this_thread::sleep_for(std::chrono::milliseconds(5));}
    require(paused>0);const auto before_cursor=cursors.load();
    for(unsigned i=0;i<5;++i){++cursor.sequence;sender.cursor(cursor);std::this_thread::sleep_for(std::chrono::milliseconds(5));}
    require(cursors==before_cursor);
    // Actual authenticated video and control channels can arrive in opposite
    // orders. A delayed pause for epoch 2 must not invalidate decoded epoch 3.
    auto send_epoch=[&](std::uint64_t epoch,unsigned wanted){
        const auto start_frames=frames.load();const auto deadline=GetTickCount64()+5000;
        while(GetTickCount64()<deadline && frames<start_frames+wanted){
            renew();receiver.pump();sender.pump();
            remote::SharedFrame frame;frame.ticket={options(true).session,epoch,++sequence,GetTickCount64(),0,640,360};
            frame.pixels={640,360,std::vector<std::uint8_t>(640*360*4,91)};
            require(sender.frame(frame));std::this_thread::sleep_for(std::chrono::milliseconds(70));
        }
        return frames>=start_frames+wanted;
    };
    stage=12;require(send_epoch(3,3));
    const auto before_late_pause=paused.load();sender.pause_source(2);
    for(unsigned i=0;i<40;++i){renew();receiver.pump();sender.pump();std::this_thread::sleep_for(std::chrono::milliseconds(10));}
    stage=13;require(paused==before_late_pause && send_epoch(3,3));
    stage=14;sender.pause_source(3);
    for(unsigned i=0;i<100 && paused==before_late_pause;++i){renew();receiver.pump();sender.pump();std::this_thread::sleep_for(std::chrono::milliseconds(5));}
    require(paused>before_late_pause);require(!send_epoch(3,1));require(send_epoch(4,3));
    receiver.request_stop();sender.request_stop();require(receiver.ended() && sender.ended());
    receiver.pump();sender.pump();
    // Actual product DLL creates only its own hidden, synthetic-test window.
    stage=10;GD_MIS_CONFIG config{};config.bytes=sizeof(config);config.version=1;config.owned_loopback=1;config.session[0]=3;
    config.transport=4;config.consent_deadline=GetTickCount64()+10000;config.local_count=config.peer_count=1;
    config.local_ipv4[0]=config.peer_ipv4[0]=0x0100007f;config.hidden=config.software=1;void* view=nullptr;
    require(GDMisCreate(&config,&view)==0 && view);require(GDMisGrant(view,GetTickCount64()+2000)==0);
    require(GDMisPump(view)==0);require(GDMisSignal(view,0,nullptr,0)==ERROR_INVALID_PARAMETER);
    std::array<std::uint32_t,32> scalar{};
    require(GDMisDiagnostics(view,scalar.data(),31)==ERROR_INVALID_PARAMETER && GDMisDiagnostics(view,scalar.data(),32)==0);
    require(scalar[0]==1 && scalar[1]==0 && scalar[2]==0 && scalar[3]==0);
    std::atomic<bool> notified=false;DWORD wrong_thread=0;
    std::thread notify([&]{wrong_thread=GDMisWait(view);std::this_thread::sleep_for(std::chrono::milliseconds(20));require(GDMisWake(view)==0);notified=true;});
    const auto wait_started=GetTickCount64();
    while(!notified && GetTickCount64()-wait_started<300){require(GDMisPump(view)==0 && GDMisWait(view)==0);}
    notify.join();require(notified && wrong_thread==ERROR_INVALID_THREAD_ID && GetTickCount64()-wait_started<300);
    std::thread stop([&]{require(GDMisStop(view)==0);});stop.join();require(GDMisPump(view)==ERROR_CANCELLED);
    require(GDMisClose(view)==0);require(GDMisStop(view)==ERROR_INVALID_HANDLE);
    require(GDMisWake(view)==ERROR_INVALID_HANDLE && GDMisWait(view)==ERROR_INVALID_HANDLE);
    // One blocking DLL call owns all Windows dispatch. The other thread only
    // publishes bounded management commands; no Python pump exists here.
    config.consent_deadline=remote::ipc::no_session_deadline;
    require(GDMisCreate(&config,&view)==0);
    require(GDMisPostReply(view,GetTickCount64()+2000,nullptr,0)==0);
    DWORD run_wrong_thread=0;std::atomic<unsigned> snapshots=0;
    std::thread manager([&]{
        run_wrong_thread=GDMisRun(view);
        for(unsigned i=0;i<12;++i){
            require(GDMisActivate(view,i%2)==0);
            require(GDMisDiagnostics(view,scalar.data(),32)==0 && scalar[0]==1);++snapshots;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        require(GDMisPostReply(view,GetTickCount64()+6000,nullptr,0)==ERROR_ACCESS_DENIED);
        require(GDMisStop(view)==0);
    });
    require(GDMisRun(view)==ERROR_CANCELLED);manager.join();
    require(run_wrong_thread==ERROR_INVALID_THREAD_ID && snapshots==12 && GDMisClose(view)==0);
    // No Python or manager is needed to enforce short-lease expiry.
    require(GDMisCreate(&config,&view)==0 && GDMisPostReply(view,GetTickCount64()+60,nullptr,0)==0);
    const auto autonomous_started=GetTickCount64();require(GDMisRun(view)==ERROR_CANCELLED);
    require(GetTickCount64()-autonomous_started<500 && GDMisClose(view)==0);
    stage=11;remote::MediaPeer expiring(options(false),[&](auto,bool active){if(!active)++paused;},[](auto){return true;});
    require(expiring.grant(GetTickCount64()+40));std::this_thread::sleep_for(std::chrono::milliseconds(60));expiring.pump();require(expiring.ended());
    std::cout<<"{\"passed\":true,\"product_peer_decoded_frames\":"<<frames<<",\"paused_callbacks\":"<<paused
        <<",\"independent_cursor_received\":"<<cursors<<",\"cursor_pause_epoch_refused\":true,\"readonly_cursor_mapping\":true,\"cursor_limits_schema_checked\":true,\"forged_ack_rejected\":true,\"dll_hidden_window\":true,\"lease_expired_terminal\":true,\"os_input\":false,\"desktop_capture\":false}\n";
}
}
int main(int argc,char** argv){SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32|LOAD_LIBRARY_SEARCH_APPLICATION_DIR);try{
    if(argc==1)test();
    else if(argc==2){
#pragma clang unsafe_buffer_usage begin
        const std::string mode(argv[1]);
#pragma clang unsafe_buffer_usage end
        if(mode=="--owned-input-stress")input_stress();
        else if(mode=="--owned-backlog-repro")input_stress(true);
        else if(mode=="--owned-grant-stall")grant_stall_test();
        else if(mode=="--owned-preconnect-focus")preconnect_test();
        else if(mode=="--owned-window-modal")modal_window_test();
        else return 2;
    }
    else return 2;
    return 0;}catch(...){std::cerr<<"product_media_integration_failed_stage_"<<stage<<"\n";return 1;}}
