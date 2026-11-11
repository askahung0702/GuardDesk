#include "session.hpp"
#include "pointer_flow.hpp"
#include "frame_pool.hpp"
#include "frame_binding.hpp"
#include "launch_capsule.hpp"
#include <algorithm>
#include "ipc_peer.hpp"
#include "h264_frame_binding.hpp"
#include <iostream>
#include <stdexcept>
#include <thread>
#include <atomic>

namespace {
using namespace remote;
void require(bool okay,const char* reason){if(!okay)throw std::runtime_error(reason);}
void put(std::vector<std::uint8_t>& bytes,std::size_t offset,std::uint64_t value,unsigned count){for(unsigned i=0;i<count;++i)bytes.at(offset+i)=static_cast<std::uint8_t>(value>>(8*i));}
ipc::Session sid(){ipc::Session value{};value.at(0)=7;return value;}
ipc::Message command(ipc::Kind kind,std::uint64_t sequence,std::uint64_t generation=0,std::uint64_t frame=0){
    const unsigned count=kind==ipc::Kind::lease || kind==ipc::Kind::input?24:0;
    return {{kind,count,sid(),generation,sequence,frame,1},std::vector<std::uint8_t>(count)};
}
ipc::Message lease(std::uint64_t sequence,std::uint64_t deadline=5000,bool control=true){auto value=command(ipc::Kind::lease,sequence);put(value.payload,0,deadline,8);put(value.payload,8,1,8);put(value.payload,16,control?1:0,4);return value;}
ipc::Message key(std::uint64_t sequence,std::uint64_t generation,std::uint64_t frame,bool down){auto value=command(ipc::Kind::input,sequence,generation,frame);value.payload.at(0)=1;value.payload.at(1)=down?1:0;put(value.payload,2,VK_CONTROL,2);return value;}
DesktopObservation desktop(std::uint64_t identity=1,bool secure=false){return {true,true,secure,identity,{0,0,320,180},{0,0,1920,1080}};}
void targeted_cleanup_test(){
    std::vector<INPUT> injected;
    SessionRuntime runtime(sid(),1,100,10100,[&](const auto& batch){injected.insert(injected.end(),batch.begin(),batch.end());return static_cast<UINT>(batch.size());},[]{});
    auto cleanup=[](std::uint64_t seq,unsigned type,unsigned code,std::uint64_t generation=1){
        auto value=command(ipc::Kind::release_all,seq,generation);value.header.payload_bytes=8;value.payload.resize(8);value.payload[0]=static_cast<std::uint8_t>(type);put(value.payload,2,code,2);return value;
    };
    require(runtime.command(lease(1),101,desktop()) && runtime.observe(desktop(),102) && runtime.publish_frame(1,103),"up_setup");
    require(runtime.command(command(ipc::Kind::presented,2,1,1),104,desktop()) && runtime.command(key(3,1,1,true),105,desktop()),"up_ctrl_down");
    auto button=command(ipc::Kind::input,4,1,1);button.payload[0]=2;button.payload[1]=1;put(button.payload,2,1,2);
    require(runtime.command(button,106,desktop()),"up_mouse_down");
    const auto before=injected.size();button.header.sequence=5;button.payload[1]=0;
    require(!runtime.command(button,1200,desktop()) && injected.size()==before,"up_stale_raw_accepted");
    require(runtime.command(cleanup(6,2,1),1201,desktop()) && injected.size()==before+1 && injected.back().mi.dwFlags==MOUSEEVENTF_LEFTUP && runtime.held(),"up_only_tracked_mouse");
    auto move=command(ipc::Kind::input,7,1,1);move.payload[0]=3;
    require(!runtime.command(move,1202,desktop()),"up_refreshed_ACK");
    require(!runtime.command(cleanup(8,1,VK_CONTROL,2),1203,desktop()) && injected.size()==before+1,"up_wrong_generation");
    require(!runtime.command(cleanup(9,1,VK_CONTROL),1204,desktop(2)),"up_wrong_desktop");
    require(runtime.command(cleanup(10,1,VK_CONTROL),1205,desktop()) && !runtime.held() && injected.back().ki.dwFlags==KEYEVENTF_KEYUP,"up_key_cleanup");
    const auto done=injected.size();require(runtime.command(cleanup(11,2,1),1206,desktop()) && injected.size()==done,"up_untracked_injected");
    require(runtime.command(cleanup(12,2,1),5001,desktop()) && !runtime.command(move,5002,desktop()),"up_revived_lease");
    std::cout<<"targeted_up_only_cleanup_preserves_other_held_inputs_and_ACK_expiry=true\n";
}
void session_test(){
    // Keep Ctrl held across a successful click, without inventing another ACK.
    // Real self-ReleaseCapture message delivery is tested by pointer_flow_probe.
    {
        SessionRuntime gesture(sid(),1,100,10100,[](const auto& batch){return static_cast<UINT>(batch.size());},[]{});
        require(gesture.command(lease(1),101,desktop()) && gesture.observe(desktop(),102) && gesture.publish_frame(1,103),"gesture_start");
        require(gesture.command(command(ipc::Kind::presented,2,1,1),104,desktop()) && gesture.command(key(3,1,1,true),105,desktop()),"gesture_ctrl_down");
        CaptureGesture capture;capture.button(1,true,true);
        auto button=command(ipc::Kind::input,4,1,1);button.payload[0]=2;button.payload[1]=1;put(button.payload,2,1,2);
        require(gesture.command(button,106,desktop()),"gesture_button_down");button.header.sequence=5;button.payload[1]=0;
        require(gesture.command(button,107,desktop()),"gesture_button_up");const bool completed=capture.button(1,false,true);
        require(capture.release_completed(completed,[&]{return !capture.capture_changed(false);}),"gesture_self_capture_cleanup");
        auto move=command(ipc::Kind::input,6,1,1);move.payload[0]=3;
        require(gesture.command(move,108,desktop()) && gesture.held(),"gesture_click_lost_ctrl_or_ack");
        require(gesture.command(key(7,1,1,false),109,desktop()) && !gesture.held(),"gesture_ctrl_up");
        require(capture.capture_changed(true) && gesture.command(command(ipc::Kind::release_all,8),110,desktop()),"gesture_real_focus_loss_cleanup");
        move.header.sequence=9;require(!gesture.command(move,111,desktop()),"gesture_focus_loss_kept_old_ack");
        require(gesture.publish_frame(2,112) && gesture.command(command(ipc::Kind::presented,10,1,2),113,desktop()),"gesture_new_ack");
        move.header.sequence=11;move.header.frame_sequence=2;require(gesture.command(move,114,desktop()),"gesture_recovery");
    }
    std::vector<INPUT> inputs;unsigned clears=0;
    auto sink=[&inputs](const std::vector<INPUT>& batch){inputs.insert(inputs.end(),batch.begin(),batch.end());return static_cast<UINT>(batch.size());};
    SessionRuntime runtime(sid(),1,100,10100,sink,[&clears]{++clears;});
    require(runtime.command(lease(1),101,desktop()),"initial_lease");require(runtime.observe(desktop(),102),"initial_desktop");
    require(runtime.generation()==1 && runtime.publish_frame(1,103),"first_frame");
    require(!runtime.command(key(2,1,1,true),104,desktop()),"input_before_ack");
    require(runtime.command(command(ipc::Kind::presented,3,1,1),105,desktop()),"first_ack");
    require(!runtime.command(key(2,1,1,true),106,desktop()),"refused_sequence_replayed");
    require(runtime.command(key(4,1,1,true),107,desktop()) && runtime.held(),"tracked_down");
    require(runtime.command(key(5,1,1,false),108,desktop()) && !runtime.held(),"tracked_up");
    require(runtime.observe(desktop(2,true),109) && runtime.generation()==2,"secure_switch_same_session");
    require(!runtime.command(key(6,1,1,true),110,desktop(2,true)),"old_epoch_input");
    require(runtime.publish_frame(2,111),"secure_frame");
    require(runtime.command(command(ipc::Kind::presented,7,2,2),112,desktop(2,true)),"secure_presented");
    require(runtime.command(key(8,2,2,true),113,desktop(2,true)),"secure_key");
    require(runtime.command(command(ipc::Kind::stop,9),114,desktop(2,true)),"stop");
    require(runtime.ended() && !runtime.held() && inputs.size()==4 && clears>=3,"stop_releases");
    require(!runtime.command(lease(10),115,desktop()),"stop_revived");
    // A logon change must not even send a cleanup key into the new user.
    SessionRuntime changed(sid(),1,100,10100,sink,[]{ });
    require(changed.command(lease(1),101,desktop()) && changed.observe(desktop(),102) && changed.publish_frame(1,103),"changed_setup");
    require(changed.command(command(ipc::Kind::presented,2,1,1),104,desktop()) && changed.command(key(3,1,1,true),105,desktop()),"changed_down");
    const auto before=inputs.size();auto other=desktop();other.same_logon=false;
    require(!changed.observe(other,106) && changed.ended() && inputs.size()==before,"cross_logon_cleanup_injected");
    SessionRuntime expires(sid(),1,100,10100,sink,[]{});
    require(expires.command(lease(1,200),101,desktop()) && expires.observe(desktop(),102),"expiry_setup");
    require(!expires.observe(desktop(),200) && expires.ended() && !expires.command(lease(2),201,desktop()),"expiry_terminal");
    SessionRuntime view(sid(),1,100,10100,sink,[]{});
    require(view.command(lease(1),101,desktop()) && view.observe(desktop(),102) && view.publish_frame(1,103) &&
        view.command(command(ipc::Kind::presented,2,1,1),104,desktop()) && view.command(key(3,1,1,true),105,desktop()),"downgrade_setup");
    require(view.command(lease(4,5000,false),106,desktop()) && !view.held(),"view_downgrade_kept_keys");
    require(view.observe(desktop(),107) && view.publish_frame(2,108) && view.command(command(ipc::Kind::presented,5,2,2),109,desktop()) &&
        !view.command(key(6,2,2,true),110,desktop()),"view_mode_input");
    SessionRuntime switch_held(sid(),1,100,10100,sink,[]{});
    require(switch_held.command(lease(1),101,desktop()) && switch_held.observe(desktop(),102) && switch_held.publish_frame(1,103) &&
        switch_held.command(command(ipc::Kind::presented,2,1,1),104,desktop()) && switch_held.command(key(3,1,1,true),105,desktop()),"held_switch_setup");
    const auto held_before=inputs.size();
    require(switch_held.observe(desktop(2,true),106) && !switch_held.held() && inputs.size()==held_before+1 &&
        inputs.back().ki.dwFlags==KEYEVENTF_KEYUP && !switch_held.command(key(4,2,1,true),107,desktop(2,true)),"held_switch_release_or_ACK");
}
void focus_release_preserves_capture_test(){
    // Focus changes and expired input queue entries are cleanup, not a
    // desktop transition. Use the production state machine with a synthetic
    // input sink: no desktop pixels or OS input are involved.
    unsigned clears=0;std::vector<INPUT> inputs;
    SessionRuntime runtime(sid(),1,100,10100,[&](const auto& batch){
        inputs.insert(inputs.end(),batch.begin(),batch.end());return static_cast<UINT>(batch.size());
    },[&]{++clears;});
    require(runtime.command(lease(1),101,desktop()) && runtime.observe(desktop(),102) && runtime.publish_frame(1,103),"focus_setup");
    require(runtime.command(command(ipc::Kind::presented,2,1,1),104,desktop()) && runtime.command(key(3,1,1,true),105,desktop()),"focus_down");
    const auto before=clears;
    require(runtime.command(command(ipc::Kind::release_all,4),106,desktop()) && !runtime.held() &&
        inputs.size()==2 && inputs.back().ki.dwFlags==KEYEVENTF_KEYUP,"focus_cleanup_failed");
    require(clears==before && runtime.state()==DesktopState::active_default && runtime.generation()==1,"focus_cleanup_reset_capture");
    require(!runtime.command(key(5,1,1,true),107,desktop()) &&
        !runtime.command(command(ipc::Kind::presented,6,1,1),108,desktop()),"focus_reused_old_ACK");
    require(runtime.publish_frame(2,109) && runtime.command(command(ipc::Kind::presented,7,1,2),110,desktop()) &&
        runtime.command(key(8,1,2,true),111,desktop()),"focus_new_frame_not_usable");
    require(runtime.command(command(ipc::Kind::release_all,9),112,desktop()),"focus_second_release");
    for(unsigned seq=10;seq<42;++seq)require(runtime.command(command(ipc::Kind::release_all,seq),120+seq,desktop()),"focus_burst_release");
    require(clears==before && runtime.observe(desktop(),170) && runtime.generation()==1 && runtime.publish_frame(3,171),"focus_burst_reopened_capture");
    auto blocked=desktop();blocked.allowed=false;
    require(runtime.command(command(ipc::Kind::release_all,42),172,blocked) && clears>before &&
        runtime.state()==DesktopState::paused && !runtime.publish_frame(4,173),"focus_unsafe_desktop_not_paused");
    require(runtime.observe(desktop(2,true),174) && runtime.generation()==2 &&
        !runtime.command(command(ipc::Kind::presented,43,1,3),175,desktop(2,true)),"focus_transition_old_ACK");
    require(!runtime.observe(desktop(2,true),5000) && runtime.ended(),"focus_release_revived_lease");
    std::cout<<"focus_release_keeps_capture_and_requires_fresh_presented_frame=true\n";
}
void rejected_input_keeps_verified_desktop_test(){
    unsigned clears=0,sent=0;
    SessionRuntime runtime(sid(),1,100,10100,[&](const auto& batch){sent+=static_cast<unsigned>(batch.size());return static_cast<UINT>(batch.size());},[&]{++clears;});
    require(runtime.command(lease(1),101,desktop()) && runtime.observe(desktop(),102) && runtime.publish_frame(1,103),"rejected_input_setup");
    require(runtime.command(command(ipc::Kind::presented,2,1,1),104,desktop()),"rejected_input_ACK");
    const auto before=clears;
    // Win32 can deliver an up after focus/capture loss with no matching down.
    // It must remain rejected, without destroying a verified screen/epoch.
    require(!runtime.command(key(3,1,1,false),105,desktop()),"untracked_up_was_injected");
    require(sent==0 && clears==before && runtime.state()==DesktopState::active_default && runtime.generation()==1,"rejected_up_reset_capture");
    require(runtime.command(key(4,1,1,true),106,desktop()) && runtime.command(key(5,1,1,false),107,desktop()),"rejected_up_broke_next_valid_input");
    std::cout<<"untracked_up_rejected_without_capture_reset=true\n";
}
void input_test(){
    std::vector<INPUT> observed;
    InputLedger ledger([&observed](const auto& batch){observed=batch;return static_cast<UINT>(batch.size());});
    auto click=command(ipc::Kind::input,1,1,1);click.payload.at(0)=2;click.payload.at(1)=1;put(click.payload,2,1,2);put(click.payload,4,319,4);put(click.payload,8,179,4);
    require(ledger.apply(click,{-320,0,0,180},{-320,0,1920,1080}),"negative_origin_click");
    require(observed.size()==2 && observed.at(0).mi.dx>=0 && observed.at(0).mi.dx<65535 && observed.at(1).mi.dwFlags==MOUSEEVENTF_LEFTDOWN,"click_coordinates");
    require(!ledger.release_all(false) && ledger.held(),"release_cross_desktop");
    require(ledger.release_all(true) && !ledger.held() && observed.at(0).mi.dwFlags==MOUSEEVENTF_LEFTUP,"mouse_release");
    auto scaled=click;put(scaled.payload,4,1919,4);put(scaled.payload,8,1079,4);
    require(ledger.apply(scaled,{-3840,-2160,0,0},{-3840,-2160,0,0},1920,1080) && observed.at(0).mi.dx==65535 && observed.at(0).mi.dy==65535,"scaled_4K_physical_endpoint");
    require(ledger.release_all(true),"scaled_cleanup");
    auto up=key(2,1,1,false);require(!ledger.apply(up,{0,0,320,180},{0,0,1920,1080}),"untracked_keyup");
    InputLedger partial([](const auto&){return 0u;});require(!partial.apply(key(1,1,1,true),{0,0,320,180},{0,0,1920,1080}) && partial.held() && partial.failed(),"failed_down_lost_ledger");
    unsigned attempts=0;InputLedger transient([&](const auto& batch){return ++attempts==1?0u:static_cast<UINT>(batch.size());});
    require(!transient.apply(key(1,1,1,true),{0,0,320,180},{0,0,1920,1080}) && transient.failed(),"transient_input_setup");
    require(!transient.release_all(false) && transient.failed(),"transient_unsafe_reset");
    require(transient.release_all(true) && !transient.failed() && !transient.held() && transient.apply(key(2,1,1,true),{0,0,320,180},{0,0,1920,1080}),"transient_input_resync_after_cleanup");
}
void concurrent_frame_test(){
    FramePool pool(sid(),320,180);HANDLE reader=pool.duplicate_read(0,GetCurrentProcess());
    struct Close{HANDLE value;~Close(){CloseHandle(value);}} close{reader};
    std::atomic<bool> done=false;
    std::thread writer([&]{Pixels image{320,180,std::vector<std::uint8_t>(320*180*4,61)};
        for(unsigned i=1;i<=500;++i){pool.clear();FrameTicket ticket{};pool.publish(image,i,i,GetTickCount64(),ticket);Sleep(0);}done=true;});
    bool fatal=false;
    while(!done){try{
        auto value=peek_shared_frame(reader,pool.mapping_bytes(),sid());
        if(value.sequence){auto image=read_shared_frame(reader,pool.mapping_bytes(),sid(),value.generation,GetTickCount64());
            require(std::all_of(image.pixels.bgra.begin(),image.pixels.bgra.end(),[](auto c){return c==61;}),"torn_frame_delivered");}
    }catch(const FrameRetry&){/* pause/reuse race drops latest sample only */}catch(...){fatal=true;break;}}
    writer.join();require(!fatal,"frame_pause_race_terminated_session");
    pool.clear();bool retry=false;try{read_shared_frame(reader,pool.mapping_bytes(),sid(),1,GetTickCount64());}catch(const FrameRetry&){retry=true;}
    require(retry,"empty_frame_not_resync");
}
void frame_test(){
    FramePool pool(sid(),320,180);HANDLE readonly=pool.duplicate_read(0,GetCurrentProcess());
    struct Close{HANDLE handle;~Close(){CloseHandle(handle);}} close{readonly};
    void* write=MapViewOfFile(readonly,FILE_MAP_WRITE,0,0,pool.mapping_bytes());
    require(write==nullptr && GetLastError()==ERROR_ACCESS_DENIED,"media_mapping_writable");
    Pixels pixels{320,180,std::vector<std::uint8_t>(320*180*4,41)};FrameTicket first{},second{},third{};
    require(pool.publish(pixels,1,1,100,first),"publish_first");
    auto actual=read_shared_frame(readonly,pool.mapping_bytes(),sid(),1,101);
    require(actual.pixels.bgra==pixels.bgra && actual.ticket.sequence==1,"mapping_read_pixels");
    require(pool.publish(pixels,1,2,102,second) && !pool.publish(pixels,1,3,103,third),"third_frame_allocated");
    auto wrong=first;wrong.generation=2;require(!pool.release(wrong),"wrong_generation_release");
    require(pool.release(first) && !pool.release(first) && pool.publish(pixels,2,3,104,third),"slot_release_reuse");
    unsigned rejected=0;
    try{read_shared_frame(readonly,pool.mapping_bytes(),sid(),3,105);}catch(const std::runtime_error&){++rejected;}
    try{read_shared_frame(readonly,pool.mapping_bytes(),sid(),1,1105);}catch(const std::runtime_error&){++rejected;}
    auto other=sid();other.at(0)=8;
    try{read_shared_frame(readonly,pool.mapping_bytes(),other,1,105);}catch(const std::runtime_error&){++rejected;}
    pool.clear();
    try{read_shared_frame(readonly,pool.mapping_bytes(),sid(),1,105);}catch(const std::runtime_error&){++rejected;}
    require(rejected==4,"stale_mapping_accepted");
}
void delayed_media_start_test(){
    // Real anonymous mappings with synthetic pixels. Capture may start before
    // ICE completes; two stale, unconsumed slots must not stop capture forever.
    FramePool pool(sid(),320,180);auto reader=pool.duplicate_read(0,GetCurrentProcess());
    struct Close{HANDLE value;~Close(){CloseHandle(value);}} close{reader};
    Pixels pixels{320,180,std::vector<std::uint8_t>(320*180*4,77)};
    FrameTicket first{},second{},next{};
    require(pool.publish(pixels,1,1,100,first) && pool.publish(pixels,1,2,133,second),"delayed_fill");
    bool stale=false;try{read_shared_frame(reader,pool.mapping_bytes(),sid(),1,1200);}catch(const FrameRetry&){stale=true;}
    require(stale,"delayed_old_pixels_accepted");
    require(!pool.publish(pixels,1,3,1100,next),"unexpired_slot_overwritten");
    require(pool.publish(pixels,1,4,1200,next),"expired_slots_block_capture_forever");
    require(!pool.release(first) && !pool.release_sequence(1,first.sequence),"late_consumed_freed_new_frame");
    auto current=read_shared_frame(reader,pool.mapping_bytes(),sid(),1,1201);
    require(current.ticket.sequence==4 && current.pixels.bgra==pixels.bgra,"fresh_frame_after_delayed_start");
    require(pool.publish(pixels,1,5,1234,next) && !pool.publish(pixels,1,6,1235,next),"two_slot_bound_lost");
    pool.clear();require(pool.publish(pixels,2,7,1236,next),"pause_generation_did_not_recover");
    require(!pool.release_sequence(1,4),"old_epoch_released_current");
    ipc::ControlGate gate(sid(),1,100,10000);require(gate.accept_broker(lease(1),101) && gate.set_desktop(1,320,180) && gate.frame(1,102),"delayed_gate_setup");
    require(!gate.accept_broker(command(ipc::Kind::presented,2,1,1),1200),"expired_frame_became_input_ack");
    require(!gate.accept_broker(key(3,1,1,true),1201),"stale_frame_allowed_input");
    std::cout<<"delayed_media_start_recovers_two_slots_without_stale_ACK=true\n";
}
void binding_test(){
    FrameBindings bindings(sid(),1);
    for(unsigned i=1;i<=200;++i){VideoBinding value{{sid(),1,i,100,0,320,180},1,i};
        const auto packet=encode_video_binding(value);auto decoded=decode_video_binding(packet);
        require(decoded.frame.sequence==i && bindings.record(decoded,100),"frame_binding_roundtrip");}
    require(!bindings.find(1,101) && bindings.find(200,101).has_value() && !bindings.find(200,1101),"frame_binding_bound_or_expiry");
    VideoBinding next{{sid(),2,201,100,0,320,180},1,201};require(bindings.record(next,100) && !bindings.find(200,101),"old_epoch_binding_retained");
    auto old=next;old.frame.generation=1;old.frame.sequence=202;require(!bindings.record(old,101),"late_old_binding");
    auto packet=encode_video_binding(next);packet.at(84)=1;
    bool bad=false;try{decode_video_binding(packet);}catch(const std::invalid_argument&){bad=true;}require(bad,"binding_reserved");
    bindings.clear();require(!bindings.find(201,101) && !bindings.record(next,102),"paused_binding_replayed");
}
void sei_test(){
    const std::vector<std::uint8_t> packet{0,0,0,1,0x67,0x42,0,0x28,0,0,0,1,0x68,0xce,0x0f,0,0,0,1,0x65,0x88,0x84};
    const auto metadata=encode_video_binding({{sid(),1,1,100,0,320,180},1,123});
    const auto bound=bind_h264_frame(packet,metadata);const auto actual=h264_frame_metadata(bound);
    require(actual && *actual==metadata && !h264_frame_metadata(packet),"SEI_frame_binding_roundtrip");
    bool rejected=false;try{bind_h264_frame(bound,metadata);}catch(const std::invalid_argument&){rejected=true;}require(rejected,"duplicate_SEI_binding");
    auto malformed=bound;const std::vector<std::uint8_t> prefix{0,0,0,1,6,5,104};
    const auto at=std::search(malformed.begin(),malformed.end(),prefix.begin(),prefix.end());require(at!=malformed.end(),"SEI_prefix");
    *(at+6)=255;rejected=false;try{h264_frame_metadata(malformed);}catch(const std::invalid_argument&){rejected=true;}require(rejected,"SEI_length_bound");
    std::vector<std::uint8_t> many;for(unsigned i=0;i<257;++i)many.insert(many.end(),{0,0,1,6,0x80});
    rejected=false;try{h264_frame_metadata(many);}catch(const std::invalid_argument&){rejected=true;}require(rejected,"SEI_NAL_capacity");
}
void launch_test(){
    LaunchCapsule capsule{};capsule.bytes=sizeof(capsule);capsule.spec.bytes=sizeof(capsule.spec);capsule.spec.format=1;
    capsule.spec.wts_session=1;capsule.spec.authentication=capsule.spec.logon_time=capsule.spec.consent_filetime=capsule.spec.transport=1;
    capsule.spec.consent_tick_deadline=1000;capsule.spec.session[0]=7;capsule.spec.user_sid[0]=L'x';
    capsule.parent_pid=10;capsule.parent_process=1;capsule.parent_query_token=2;capsule.parent_created=3;capsule.stop=4;capsule.frames={5,6};
    validate_launch_capsule(capsule,100);
    auto invalid=capsule;invalid.spec.consent_tick_deadline=600101;
    bool bad=false;try{validate_launch_capsule(invalid,100);}catch(const std::invalid_argument&){bad=true;}require(bad,"launch_long_consent");
    HANDLE token=nullptr,process=nullptr;require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)!=FALSE,"launch_owned_token");
    require(DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),GetCurrentProcess(),&process,PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,0)!=FALSE,"launch_owned_process");
    ipc::Peer peer(process,token);ipc::Peer current(GetCurrentProcessId());peer.require_match(current.identity());
    require(WaitForSingleObject(peer.wait_handle(),0)==WAIT_TIMEOUT,"launch_retained_query_peer");
}
}
void display_topology_test(){
    unsigned clears=0;std::vector<INPUT> inputs;
    SessionRuntime runtime(sid(),1,100,10000,[&](const auto& b){inputs.insert(inputs.end(),b.begin(),b.end());return static_cast<UINT>(b.size());},[&]{++clears;});
    auto first=desktop();first.output={0,0,1920,1080};first.virtual_screen={-1920,0,1920,1080};
    require(runtime.command(lease(1),101,first) && runtime.observe(first,102) && runtime.publish_frame(1,103),"topology_setup");
    const auto generation=runtime.generation();
    require(runtime.command(command(ipc::Kind::presented,2,generation,1),104,first),"topology_presented");
    auto changed=first;changed.virtual_screen={0,0,3840,1080};
    require(runtime.observe(changed,105) && runtime.generation()>generation && clears>=2,"virtual_layout_did_not_reset_epoch");
    require(!runtime.command(key(3,generation,1,true),106,changed) && inputs.empty(),"old_layout_input_accepted");
}
int main(){
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    try{sei_test();}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
    try{display_topology_test();targeted_cleanup_test();session_test();focus_release_preserves_capture_test();rejected_input_keeps_verified_desktop_test();input_test();frame_test();delayed_media_start_test();concurrent_frame_test();binding_test();launch_test();std::cout<<"{\"passed\":true,\"production_session_core\":true,\"anonymous_readonly_frames\":true,\"bounded_RTP_epoch_binding\":true,\"minimal_launch_query_handles\":true,\"desktop_capture\":false,\"OS_input\":false,\"SYSTEM_boundary\":false}\n";return 0;}
    catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
