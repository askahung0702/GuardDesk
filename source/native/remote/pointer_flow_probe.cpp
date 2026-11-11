// Deterministic scheduler overload and ordering tests; no pixels, WTS or OS input.
#include "pointer_flow.hpp"
#include "latest_task.hpp"
#include "latency.hpp"
#include <atomic>
#include <windows.h>
#include <iostream>
#include <stdexcept>
namespace {
using namespace remote;
void need(bool value,const char* why){if(!value)throw std::runtime_error(why);}
ipc::Message message(std::uint64_t sequence,ipc::Kind kind=ipc::Kind::input,unsigned type=3){
    ipc::Session id{};id[0]=1;std::vector<std::uint8_t> payload(kind==ipc::Kind::input?24:0);
    if(!payload.empty()){payload[0]=static_cast<std::uint8_t>(type);if(type==1 || type==2){payload[1]=1;payload[2]=1;}}
    return {{kind,static_cast<std::uint32_t>(payload.size()),id,1,sequence,1,1},std::move(payload)};
}
void ordering(){
    WorkerCommandQueue q;need(q.push(message(1),1) && q.push(message(2),2),"move_enqueue");
    auto latest=q.pop();need(latest && latest->message.header.sequence==2 && latest->arrived==2 && q.coalesced==1,"latest_move_not_kept");
    need(!q.push(message(2),3),"replay_coalesced_away");
    need(q.push(message(3,ipc::Kind::presented),3) && q.push(message(4),4) && q.push(message(5),5),"ack_barrier_enqueue");
    need(q.pop()->message.header.kind==ipc::Kind::presented && q.pop()->message.header.sequence==5,"ack_order_lost");
    std::uint64_t sequence=6;
    for(auto barrier:{ipc::Kind::release_all,ipc::Kind::lease,ipc::Kind::consumed,ipc::Kind::stop}){
        need(q.push(message(sequence++),6),"barrier_before");need(q.push(message(sequence++,barrier),7),"barrier");need(q.push(message(sequence++),8),"barrier_after");
        need(q.pop()->message.header.kind==ipc::Kind::input && q.pop()->message.header.kind==barrier && q.pop()->message.header.kind==ipc::Kind::input,"barrier_crossed");
    }
    for(unsigned type:{1u,2u,4u}){
        need(q.push(message(sequence++),1) && q.push(message(sequence++,ipc::Kind::input,type),2) && q.push(message(sequence++),3),"transition_enqueue");
        need(q.pop()->message.payload[0]==3 && q.pop()->message.payload[0]==type && q.pop()->message.payload[0]==3,"key_button_wheel_lost");
    }
    for(unsigned boundary=0;boundary<4;++boundary){
        auto first=message(sequence++),second=message(sequence++);
        if(boundary==0)second.header.desktop_generation=2;
        if(boundary==1)second.header.frame_sequence=2;
        if(boundary==2)second.header.transport_generation=2;
        if(boundary==3)second.header.session[0]=2;
        need(q.push(first,1) && q.push(second,2) && q.pop()->message.header.sequence==first.header.sequence && q.pop()->message.header.sequence==second.header.sequence,"identity_boundary_coalesced");
    }
    for(unsigned i=0;i<32;++i)need(q.push(message(sequence++,ipc::Kind::presented),100+i),"bounded_enqueue");
    need(q.high_water==32 && !q.push(message(sequence++,ipc::Kind::presented),132),"unbounded_queue");
    WorkerCommandQueue flood;
    for(unsigned i=0;i<ipc::control_commands_per_second;++i)need(flood.push(message(i+1),i),"rate_admission");
    need(!flood.push(message(241),240),"coalescing_bypassed_rate_limit");
    need(flood.push(message(242),1000) && !flood.push(message(243),999),"rate_clock_boundary");
}
void pacing(){
    PointerPacer p;unsigned sent=0;
    for(unsigned tick=0;tick<1000;++tick){if(tick%10==0)p.replace(message(tick+1).payload,tick);if(p.take(tick))++sent;}
    need(sent==31,"pointer_pump_rate_unbounded");
    p.replace(message(1001).payload,1000);need(p.take(1001)==std::nullopt,"cadence_bypassed");
    need(p.take(1101)==std::nullopt,"stale_pointer_sent");
    p.replace(message(1002).payload,1200);p.reset();need(!p.take(1250),"focus_loss_replayed_move");
    p.replace(message(1003).payload,1300);need(!p.take(1299),"future_pointer_sent");
    PointerPacer experimental(16);unsigned faster=0;
    for(unsigned tick=0;tick<1000;++tick){if(tick%10==0)experimental.replace(message(tick+1).payload,tick);if(experimental.take(tick))++faster;}
    need(faster==63 && sent==31,"16_33_comparison");
    PointerPacer due;due.replace(message(1).payload,0);need(due.take(0).has_value(),"first_move_delayed");
    due.replace(message(2).payload,10);need(due.wait_ms(10)==23 && due.wait_ms(32)==1 && due.wait_ms(33)==0 && due.take(33).has_value(),"native_deadline_wait_quantized");
    for(unsigned interval:{0u,15u,34u,1000u}){bool refused=false;try{PointerPacer bad(interval);}catch(const std::invalid_argument&){refused=true;}need(refused,"unsafe_pointer_rate");}
}
void independent_slow_capture(){
    struct Result{unsigned value=0;};using Task=LatestTask<unsigned,Result>;
    HANDLE entered=CreateEventW(nullptr,TRUE,FALSE,nullptr),proceed=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    need(entered && proceed,"owned_async_events");std::atomic<unsigned> owner{0},finished{0};std::atomic<bool> destroyed_on_owner=false;
    struct Resource {DWORD thread;std::atomic<bool>& result;Resource(DWORD id,std::atomic<bool>& value):thread(id),result(value){}~Resource(){result=GetCurrentThreadId()==thread;}};
    const auto caller=GetCurrentThreadId();
    {
        Task task([&]()->Task::Processor{
            owner=GetCurrentThreadId();auto resource=std::make_shared<Resource>(GetCurrentThreadId(),destroyed_on_owner);
            return [&,resource](unsigned value){if(value==1){SetEvent(entered);need(WaitForSingleObject(proceed,1000)==WAIT_OBJECT_0,"owned_capture_release");}return Result{value};};
        });
        task.submit(1);need(WaitForSingleObject(entered,1000)==WAIT_OBJECT_0,"owned_capture_enter");
        const auto begin=monotonic_us();
        for(unsigned i=2;i<10000;++i){task.submit(i);++finished;}
        need(monotonic_us()-begin<100000 && finished==9998 && !task.take(),"input_waited_for_capture");
        task.invalidate();task.submit(20000);SetEvent(proceed);
        std::optional<Result> result;const auto until=GetTickCount64()+1000;
        need(WaitForSingleObject(task.ready_event(),1000)==WAIT_OBJECT_0,"capture_completion_did_not_wake_owner");
        while(GetTickCount64()<until){result=task.take();if(result)break;Sleep(1);}
        need(result && result->value==20000 && owner!=caller,"old_epoch_result_escaped");
        need(WaitForSingleObject(task.ready_event(),0)==WAIT_TIMEOUT,"completion_event_not_drained");
    }
    need(destroyed_on_owner,"capture_resources_destroyed_on_wrong_thread");
    CloseHandle(entered);CloseHandle(proceed);
    LatencyHistogram histogram;for(auto us:{0u,250u,251u,1000u,1001u,128001u})histogram.record(us);
    need(histogram.count==6 && histogram.max_us==128001 && histogram.bins[0]==2 && histogram.bins[1]==2 && histogram.bins[2]==1 && histogram.bins[7]==1,"latency_bins");
    histogram.count=UINT32_MAX;histogram.bins[0]=UINT32_MAX;histogram.record(1);need(histogram.count==UINT32_MAX && histogram.bins[0]==UINT32_MAX,"histogram_overflow");
}
struct CaptureFixture {CaptureGesture state;unsigned cleanup=0;bool baseline=false;};
LRESULT CALLBACK owned_window(HWND window,UINT message,WPARAM wparam,LPARAM lparam){
    auto* fixture=reinterpret_cast<CaptureFixture*>(GetWindowLongPtrW(window,GWLP_USERDATA));
    if(message==WM_CAPTURECHANGED && fixture){if(fixture->baseline || fixture->state.capture_changed(lparam!=0))++fixture->cleanup;return 0;}
    return DefWindowProcW(window,message,wparam,lparam);
}
void capture_lifecycle(){
    const auto instance=GetModuleHandleW(nullptr);WNDCLASSW klass{};klass.lpfnWndProc=owned_window;klass.hInstance=instance;klass.lpszClassName=L"GuardDeskOwnedCaptureFlow";
    need(RegisterClassW(&klass)!=0,"owned_capture_class");
    HWND a=CreateWindowW(klass.lpszClassName,L"Owned capture fixture",WS_OVERLAPPED,0,0,100,100,nullptr,nullptr,instance,nullptr);
    HWND b=CreateWindowW(klass.lpszClassName,L"Owned second fixture",WS_OVERLAPPED,0,0,100,100,nullptr,nullptr,instance,nullptr);
    need(a && b,"owned_capture_window");
    struct Windows {HWND a,b;~Windows(){if(GetCapture()==a || GetCapture()==b)ReleaseCapture();DestroyWindow(a);DestroyWindow(b);}} windows{a,b};
    CaptureFixture fixture;SetWindowLongPtrW(a,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(&fixture));
    fixture.baseline=true;SetCapture(a);need(GetCapture()==a && ReleaseCapture()!=FALSE && fixture.cleanup==1,"old_capture_cleanup_not_reproduced");
    fixture.baseline=false;fixture.cleanup=0;
    fixture.state.button(1,true,true);SetCapture(a);need(GetCapture()==a,"new_capture_not_owned");
    const bool completed=fixture.state.button(1,false,true);
    need(completed && fixture.state.release_completed(completed,[&]{return ReleaseCapture()!=FALSE;}) && fixture.cleanup==0,"normal_up_invalidated_ack");
    fixture.state.button(1,true,true);fixture.state.button(2,true,true);need(!fixture.state.button(1,false,true) && fixture.state.held(),"chord_released_early");
    SetCapture(a);SetCapture(b);need(fixture.cleanup==1 && !fixture.state.held(),"unexpected_capture_loss_not_cleaned");ReleaseCapture();
    fixture.state.button(1,true,true);need(!fixture.state.button(1,false,false) && fixture.state.held(),"failed_up_claimed_complete");
    need(fixture.state.capture_changed(false) && !fixture.state.held(),"failed_up_cleanup_missing");
    SetWindowLongPtrW(a,GWLP_USERDATA,0);
}
struct Result{unsigned offered=0,applied=0,stale=0,max_age=0,first_age=0;bool overflow=false;};
Result overload(bool corrected){
    // Identical synthetic 100Hz positions + 20Hz frame ACKs. The injected
    // 15ms command cost is a fixture, NOT measured Windows/LAB01 performance.
    PointerPacer pacer;WorkerCommandQueue bounded;std::deque<QueuedCommand> old;
    std::uint64_t seq=0;unsigned busy_until=0;Result r;
    auto send=[&](ipc::Message m,unsigned tick){++r.offered;if(corrected)need(bounded.push(std::move(m),tick),"fixture_queue_overflow");
        else if(old.size()>=32)r.overflow=true;else old.push_back({std::move(m),tick});};
    for(unsigned tick=0;tick<3000;++tick){
        if(tick%10==0){if(corrected)pacer.replace(message(1).payload,tick);else send(message(++seq),tick);}
        if(corrected){if(auto move=pacer.take(tick)){auto m=message(++seq);m.payload=std::move(*move);send(std::move(m),tick);}}
        if(tick%50==0)send(message(++seq,ipc::Kind::presented),tick);
        if(r.overflow)break; // Same bound as the original product queue.
        if(tick<busy_until)continue;
        std::optional<QueuedCommand> next;
        if(corrected)next=bounded.pop();else if(!old.empty()){next=std::move(old.front());old.pop_front();}
        if(!next)continue;const auto age=tick-static_cast<unsigned>(next->arrived);r.max_age=std::max(r.max_age,age);
        if(next->message.header.kind==ipc::Kind::input){if(age>100)++r.stale;else {if(r.applied==0)r.first_age=age;++r.applied;}}
        busy_until=tick+15;
    }
    return r;
}
}
int main(){try{
    ordering();pacing();capture_lifecycle();independent_slow_capture();const auto old=overload(false),now=overload(true);
    need(old.overflow && old.stale>0 && !now.overflow && now.stale==0 && now.applied>=80 && now.max_age<100 && now.first_age<34,"overload_not_improved");
    std::cout<<"{\"passed\":true,\"synthetic_command_cost_ms\":15,\"baseline_bounded_queue_overflow\":true,\"baseline_offered\":"<<old.offered<<",\"baseline_stale_inputs\":"<<old.stale<<",\"baseline_max_queue_age_ms\":"<<old.max_age
        <<",\"paced_offered\":"<<now.offered<<",\"paced_applied\":"<<now.applied<<",\"paced_stale_inputs\":"<<now.stale<<",\"paced_max_queue_age_ms\":"<<now.max_age<<",\"normal_up_cleanup_before\":1,\"normal_up_cleanup_after\":0,\"real_owned_HWND_capture\":true,\"OS_input\":false,\"LAB01_measured\":false}\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
