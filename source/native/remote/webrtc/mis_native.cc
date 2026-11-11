#define GD_MIS_NATIVE_BUILD
#include "mis_native.hpp"
#include "media_peer.hpp"
#include "viewer.hpp"
#include "pointer_flow.hpp"
#include "latency.hpp"
#include <windowsx.h>
#include <algorithm>
#include <map>
#include <shared_mutex>
#include <stdexcept>

namespace {
using namespace remote;
struct View;
LRESULT CALLBACK window_proc(HWND,UINT,WPARAM,LPARAM);
struct Context {std::shared_mutex mutex;View* view=nullptr;};
struct Registry {std::shared_mutex mutex;std::map<void*,std::shared_ptr<Context>> values;unsigned creating=0;std::uintptr_t next=1;};
Registry& registry(){static auto* value=new Registry;return *value;}
void require(bool value){if(!value)throw std::invalid_argument("mis_native_argument");}
std::string ipv4(std::uint32_t value){return std::to_string(value&255)+"."+std::to_string((value>>8)&255)+"."+std::to_string((value>>16)&255)+"."+std::to_string(value>>24);}
struct Wake {
    HANDLE value=CreateEventW(nullptr,FALSE,FALSE,nullptr);
    Wake(){require(value!=nullptr);}~Wake(){CloseHandle(value);}
};
struct View {
    Wake wake;
    DWORD owner=GetCurrentThreadId();HWND window=nullptr;
    DPI_AWARENESS_CONTEXT prior_dpi=nullptr;
    std::unique_ptr<NativeViewer> viewer;
    std::unique_ptr<MediaPeer> peer;
    unsigned frame_width=0,frame_height=0;bool closing=false,cursor_warning=false,modal=false,servicing=false;
    std::uint64_t status_tick=0,presented_frames=0;
    std::optional<MediaSignal> pending;
    std::mutex mailbox_mutex;
    std::optional<std::string> answer_mail;
    std::optional<bool> activate_mail;
    std::array<std::uint32_t,32> diagnostic_snapshot{};
    PointerPacer pointer_move{16};CaptureGesture capture_gesture;
    LatencyHistogram input_send,ui_event_age;std::uint32_t input_offered=0,input_sent=0;
    bool send_input(const std::vector<std::uint8_t>& payload){
        LatencyHistogram::add(input_offered);const auto started=monotonic_us();const bool sent=peer->input(payload);
        input_send.record(monotonic_us()-started);if(sent)LatencyHistogram::add(input_sent);return sent;
    }
    explicit View(const GD_MIS_CONFIG& config){
        require(config.bytes==sizeof(config) && config.version==1 && config.can_control<=1 && config.owned_loopback<=1 && config.hidden<=1 && config.software<=1);
        require(config.local_count>=1 && config.local_count<=8 && config.peer_count>=1 && config.peer_count<=8);
        // Hidden mode is a self-owned test surface, never a way to ACK unseen pixels.
        require(!config.hidden || config.owned_loopback);
        MediaPeerOptions options;options.session=config.session;options.transport=config.transport;
        options.consent_deadline=config.consent_deadline;options.can_control=config.can_control!=0;options.owned_loopback=config.owned_loopback!=0;
        for(unsigned i=0;i<8;++i){if(i<config.local_count)options.local_ipv4.push_back(ipv4(config.local_ipv4.at(i)));else require(config.local_ipv4.at(i)==0);
            if(i<config.peer_count)options.peer_ipv4.push_back(ipv4(config.peer_ipv4.at(i)));else require(config.peer_ipv4.at(i)==0);}
        HMODULE module=nullptr;require(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&window_proc),&module)!=FALSE);
        WNDCLASSW klass{};klass.lpfnWndProc=window_proc;klass.hInstance=module;klass.lpszClassName=L"GuardDeskNativeMediaViewerV1";klass.hCursor=LoadCursorW(nullptr,IDC_ARROW);
        require(RegisterClassW(&klass)!=0 || GetLastError()==ERROR_CLASS_ALREADY_EXISTS);
        prior_dpi=SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        require(prior_dpi!=nullptr);
        window=CreateWindowExW(0,klass.lpszClassName,L"GuardDesk 遠端協助",WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,1100,720,nullptr,nullptr,module,this);
        if(!window){SetThreadDpiAwarenessContext(prior_dpi);prior_dpi=nullptr;require(false);}
        try {
            viewer=std::make_unique<NativeViewer>(window,options.session,config.software!=0);
            peer=std::make_unique<MediaPeer>(options,[this](auto generation,bool active){viewer->state(generation,active);SetEvent(wake.value);},
                [this](SharedFrame frame){const bool accepted=viewer->submit(std::move(frame));SetEvent(wake.value);return accepted;},
                [this](CursorUpdate cursor){const bool accepted=viewer->cursor(std::move(cursor));SetEvent(wake.value);return accepted;});
            if(!config.hidden)ShowWindow(window,SW_SHOW);
        }catch(...){DestroyWindow(window);window=nullptr;SetThreadDpiAwarenessContext(prior_dpi);prior_dpi=nullptr;throw;}
    }
    ~View(){if(peer)peer->request_stop();peer.reset();viewer.reset();if(window)DestroyWindow(window);if(prior_dpi)SetThreadDpiAwarenessContext(prior_dpi);}
    void input(UINT message,WPARAM wparam,LPARAM lparam){
        if(!peer || closing)return;
        if((message>=WM_KEYFIRST && message<=WM_KEYLAST) || (message>=WM_MOUSEFIRST && message<=WM_MOUSELAST))
            ui_event_age.record(std::uint64_t(static_cast<DWORD>(GetTickCount()-static_cast<DWORD>(GetMessageTime())))*1000);
        if(message==WM_CAPTURECHANGED && !capture_gesture.capture_changed(lparam!=0))return;
        if(message==WM_KILLFOCUS || message==WM_CAPTURECHANGED || message==WM_CANCELMODE){capture_gesture.reset();pointer_move.reset();peer->release_all();return;}
        std::vector<std::uint8_t> payload(24);
        auto put=[&](unsigned at,std::uint32_t value,unsigned bytes){for(unsigned i=0;i<bytes;++i)payload.at(at+i)=static_cast<std::uint8_t>(value>>(8*i));};
        if(message==WM_KEYDOWN || message==WM_KEYUP || message==WM_SYSKEYDOWN || message==WM_SYSKEYUP){
            if(wparam==0 || wparam>254 || wparam==231)return;
            payload[0]=1;payload[1]=message==WM_KEYDOWN || message==WM_SYSKEYDOWN;put(2,static_cast<std::uint32_t>(wparam),2);
        }else{
            if(!frame_width || !frame_height)return;POINT point{GET_X_LPARAM(lparam),GET_Y_LPARAM(lparam)};
            if(message==WM_MOUSEWHEEL)ScreenToClient(window,&point);
            RECT rect{};if(!GetClientRect(window,&rect))return;
            const auto scale=std::min(double(rect.right)/frame_width,double(rect.bottom)/frame_height);
            if(scale<=0)return;
            const double x=(point.x-(rect.right-frame_width*scale)*.5)/scale,y=(point.y-(rect.bottom-frame_height*scale)*.5)/scale;
            if(x<0 || y<0 || x>=frame_width || y>=frame_height){
                if(message==WM_LBUTTONUP || message==WM_RBUTTONUP || message==WM_MBUTTONUP){capture_gesture.reset();pointer_move.reset();peer->release_all();if(GetCapture()==window)ReleaseCapture();}
                return;
            }
            put(4,static_cast<unsigned>(x),4);put(8,static_cast<unsigned>(y),4);
            if(message==WM_MOUSEMOVE)payload[0]=3;
            else if(message==WM_MOUSEWHEEL){payload[0]=4;const auto delta=GET_WHEEL_DELTA_WPARAM(wparam);if(!delta || delta%120 || delta< -1200 || delta>1200)return;put(12,static_cast<std::uint32_t>(delta),4);}
            else {payload[0]=2;payload[1]=message==WM_LBUTTONDOWN || message==WM_RBUTTONDOWN || message==WM_MBUTTONDOWN;
                put(2,message==WM_LBUTTONDOWN || message==WM_LBUTTONUP?1:message==WM_RBUTTONDOWN || message==WM_RBUTTONUP?2:3,2);}
        }
        if(message==WM_MOUSEMOVE)pointer_move.replace(std::move(payload),GetTickCount64());
        else {pointer_move.reset();const bool sent=send_input(payload);
            const bool up=(payload.at(0)==1 || payload.at(0)==2) && !payload.at(1);
            const bool cleanup_sent=up && peer->release_up(payload.at(0),unsigned(payload.at(2))|(unsigned(payload.at(3))<<8));
            if(up && !cleanup_sent){capture_gesture.reset();peer->release_all();}
            if(payload.at(0)==2){
                const bool down=payload.at(1)!=0;const auto code=payload.at(2);
                const bool completed=capture_gesture.button(code,down,sent || cleanup_sent) && cleanup_sent;
                if(down && sent)SetCapture(window);
                else if(!down && (!capture_gesture.held() || !cleanup_sent)){
                    if(GetCapture()==window && !capture_gesture.release_completed(completed,[&]{return ReleaseCapture()!=FALSE;})){
                        capture_gesture.reset();pointer_move.reset();peer->release_all();
                    }
                }
            }}
    }
    DWORD pump(bool dispatch=true){
        if(servicing)return ERROR_SUCCESS;
        struct Service {bool& value;explicit Service(bool& v):value(v){value=true;}~Service(){value=false;}} service(servicing);
        std::optional<std::string> answer;std::optional<bool> activation;
        {std::lock_guard<std::mutex> lock(mailbox_mutex);answer.swap(answer_mail);activation.swap(activate_mail);}
        if(answer && !peer->signal({false,std::move(*answer)}))return ERROR_INVALID_DATA;
        if(activation){
            DWORD process=0;const auto foreground=GetForegroundWindow();
            if(foreground && GetWindowThreadProcessId(foreground,&process) && process==GetCurrentProcessId()){
                if(*activation)ShowWindow(window,IsZoomed(window)?SW_RESTORE:SW_MAXIMIZE);
                else if(IsIconic(window))ShowWindow(window,SW_RESTORE);
                if(SetForegroundWindow(window))SetFocus(window);
            }
        }
        // DefWindowProc's move/size loop dispatches WM_TIMER itself. Release
        // this guard only around dispatch so its owner-thread timer can render
        // current pixels and enforce expiry without nested GPU work.
        MSG message{};unsigned count=0;
        if(dispatch)while(count++<64 && PeekMessageW(&message,window,0,0,PM_REMOVE)){
            servicing=false;TranslateMessage(&message);DispatchMessageW(&message);servicing=true;
        }
        if(closing || peer->ended())return ERROR_CANCELLED;
        peer->pump();if(peer->ended())return ERROR_CANCELLED;
        if(!cursor_warning && peer->stats().cursor_unsupported){cursor_warning=true;SetWindowTextW(window,L"GuardDesk 遠端協助 · 游標形狀不支援，暫停獨立游標顯示");}
        if(auto payload=pointer_move.take(GetTickCount64()))send_input(*payload);
        auto presented=viewer->present();
        // A stale frame/temporarily busy channel is not session revocation.
        // Input remains fenced until a fresh presentation ACK is admitted.
        if(presented){frame_width=presented->width;frame_height=presented->height;peer->presented(*presented);++presented_frames;}
        if(GetTickCount64()-status_tick>=1000){status_tick=GetTickCount64();const auto stats=peer->stats();
            const auto title=std::wstring(L"GuardDesk 遠端協助 · ")+(stats.peer_connected && stats.channel_open?(stats.decoded?L"影像通道已連線":L"通道已連線，等待端點首張畫面"):L"等待影像通道")+
                L" · 解碼 "+std::to_wstring(stats.decoded)+L" · 顯示 "+std::to_wstring(presented_frames)+
                L" · 編解碼錯誤 "+std::to_wstring(stats.codec_failures)+(cursor_warning?L" · 游標形狀不支援":L"");
            const auto detail=viewer->diagnostics();
            SetWindowTextW(window,(title+L" · 暫停 "+std::to_wstring(detail[0])+L" · 擷取代次 "+std::to_wstring(detail[1])+L" · 顯示忙碌 "+std::to_wstring(detail[4])).c_str());
        }
        std::array<std::uint32_t,32> values{};values[0]=1;values[1]=input_offered;values[2]=input_sent;
        auto append=[&](const LatencyHistogram& h,unsigned at){values[at]=h.count;values[at+1]=h.max_us;std::copy(h.bins.begin(),h.bins.end(),values.begin()+at+2);};
        append(ui_event_age,4);append(input_send,14);const auto reasons=viewer->diagnostics();std::copy(reasons.begin(),reasons.end(),values.begin()+24);
        {std::lock_guard<std::mutex> lock(mailbox_mutex);diagnostic_snapshot=values;}
        return ERROR_SUCCESS;
    }
};
LRESULT CALLBACK window_proc(HWND window,UINT message,WPARAM wparam,LPARAM lparam){
    auto* view=reinterpret_cast<View*>(GetWindowLongPtrW(window,GWLP_USERDATA));
    if(message==WM_NCCREATE){view=static_cast<View*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(view));}
    if(view){try{
        if(message==WM_ENTERSIZEMOVE){view->modal=true;if(!SetTimer(window,0x4744,16,nullptr))throw std::runtime_error("native_modal_timer");}
        if(message==WM_EXITSIZEMOVE){KillTimer(window,0x4744);view->modal=false;}
        if(message==WM_TIMER && wparam==0x4744 && view->modal){
            if(view->pump(false)!=ERROR_SUCCESS){PostMessageW(window,WM_CANCELMODE,0,0);ShowWindow(window,SW_HIDE);}
            return 0;
        }
        if(message==WM_DPICHANGED){auto* rect=reinterpret_cast<RECT*>(lparam);
            if(rect)SetWindowPos(window,nullptr,rect->left,rect->top,rect->right-rect->left,rect->bottom-rect->top,SWP_NOACTIVATE|SWP_NOZORDER);return 0;}
        if(message==WM_CLOSE){view->closing=true;if(view->peer)view->peer->request_stop();ShowWindow(window,SW_HIDE);return 0;}
        if(message==WM_KILLFOCUS || message==WM_CAPTURECHANGED || message==WM_CANCELMODE || (message>=WM_KEYFIRST && message<=WM_KEYLAST) || (message>=WM_MOUSEFIRST && message<=WM_MOUSELAST)){
            view->input(message,wparam,lparam);
            if(message!=WM_KILLFOCUS)return 0;
        }
    }catch(...){if(view->peer)view->peer->request_stop(MediaEndReason::callback_failed);}}
    return DefWindowProcW(window,message,wparam,lparam);
}
std::shared_ptr<Context> lookup(void* key){auto& values=registry();std::shared_lock<std::shared_mutex> lock(values.mutex);
    auto found=values.values.find(key);return found==values.values.end()?nullptr:found->second;}
template<class Function> DWORD call(void* key,Function function,bool any_thread=false){
    try{auto context=lookup(key);if(!context)return ERROR_INVALID_HANDLE;
        std::shared_lock<std::shared_mutex> lock(context->mutex);if(!context->view)return ERROR_INVALID_HANDLE;auto& view=*context->view;
        if(!any_thread && view.owner!=GetCurrentThreadId())return ERROR_INVALID_THREAD_ID;
        return function(view);
    }catch(...){return ERROR_INVALID_DATA;}
}
}
DWORD __stdcall GDMisCreate(const GD_MIS_CONFIG* config,void** output){
    if(!config || !output)return ERROR_INVALID_PARAMETER;*output=nullptr;
    HMODULE pinned=nullptr;
    if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(&GDMisCreate),&pinned))return ERROR_DLL_INIT_FAILED;
    auto& values=registry();
    {std::unique_lock<std::shared_mutex> lock(values.mutex);if(values.values.size()+values.creating>=4)return ERROR_BUSY;++values.creating;}
    try{auto view=std::make_unique<View>(*config);
        std::unique_lock<std::shared_mutex> lock(values.mutex);
        require(values.next<0x7fffffffffffffffull);
        void* key=reinterpret_cast<void*>(values.next++);auto context=std::make_shared<Context>();context->view=view.get();values.values.emplace(key,std::move(context));--values.creating;
        *output=key;view.release();return ERROR_SUCCESS;
    }catch(...){std::unique_lock<std::shared_mutex> lock(values.mutex);--values.creating;return ERROR_INVALID_DATA;}
}
DWORD __stdcall GDMisGrant(void* key,std::uint64_t deadline){return call(key,[&](View& view){return view.peer->grant(deadline)?DWORD(ERROR_SUCCESS):DWORD(ERROR_ACCESS_DENIED);});}
DWORD __stdcall GDMisRelay(void* key,const std::uint8_t* bytes,std::uint32_t size){
    if(!bytes || size<128 || size>1152)return ERROR_INVALID_PARAMETER;
    return call(key,[&](View& view){std::vector<std::uint8_t> policy(size);std::memcpy(policy.data(),bytes,size);
        return view.peer->relay(policy)?DWORD(ERROR_SUCCESS):DWORD(ERROR_INVALID_DATA);});
}
DWORD __stdcall GDMisOffer(void* key){return call(key,[](View& view){return view.peer->make_offer()?DWORD(ERROR_SUCCESS):DWORD(ERROR_INVALID_DATA);});}
DWORD __stdcall GDMisSignal(void* key,std::uint32_t offer,const std::uint8_t* bytes,std::uint32_t size){
    if(offer>1 || !bytes || !size || size>65528)return ERROR_INVALID_PARAMETER;
    return call(key,[&](View& view){return view.peer->signal({offer!=0,std::string(reinterpret_cast<const char*>(bytes),size)})?DWORD(ERROR_SUCCESS):DWORD(ERROR_INVALID_DATA);});
}
DWORD __stdcall GDMisTakeSignal(void* key,std::uint32_t* offer,std::uint8_t* bytes,std::uint32_t* size){
    if(!offer || !size)return ERROR_INVALID_PARAMETER;
    return call(key,[&](View& view)->DWORD{if(!view.pending)view.pending=view.peer->take_signal();if(!view.pending)return ERROR_NO_MORE_ITEMS;
        if(!bytes || *size<view.pending->sdp.size()){*size=static_cast<std::uint32_t>(view.pending->sdp.size());return ERROR_INSUFFICIENT_BUFFER;}
        *offer=view.pending->offer?1:0;*size=static_cast<std::uint32_t>(view.pending->sdp.size());std::memcpy(bytes,view.pending->sdp.data(),*size);view.pending.reset();return ERROR_SUCCESS;});
}
DWORD __stdcall GDMisPump(void* key){return call(key,[](View& view){return view.pump();});}
DWORD __stdcall GDMisRun(void* key){return call(key,[](View& view)->DWORD{
    for(;;){const auto result=view.pump();if(result)return result;
        const auto waited=MsgWaitForMultipleObjectsEx(1,&view.wake.value,view.pointer_move.wait_ms(GetTickCount64()),QS_ALLINPUT,MWMO_INPUTAVAILABLE);
        if(waited==WAIT_FAILED)return GetLastError();
    }
});}
DWORD __stdcall GDMisPostReply(void* key,std::uint64_t deadline,const std::uint8_t* bytes,std::uint32_t size){
    if(size>65528 || (size && !bytes) || (!size && bytes))return ERROR_INVALID_PARAMETER;
    return call(key,[&](View& view)->DWORD{
        const auto now=GetTickCount64();if(deadline && (deadline<=now || deadline-now>5000))return ERROR_ACCESS_DENIED;
        std::lock_guard<std::mutex> lock(view.mailbox_mutex);
        if(size && view.answer_mail)return ERROR_BUSY;
        std::optional<std::string> answer;
        if(size){answer=std::string(reinterpret_cast<const char*>(bytes),size);if(answer->find('\0')!=std::string::npos)return ERROR_INVALID_DATA;}
        // grant() is explicitly thread-safe. Apply an authenticated fresh grant
        // at receipt, not after UI/SDP work returns. The exact received expiry,
        // consent limit and already-expired/terminal refusal remain unchanged.
        if(deadline && !view.peer->grant(deadline))return ERROR_ACCESS_DENIED;
        if(answer)view.answer_mail=std::move(answer);
        return SetEvent(view.wake.value)?DWORD(ERROR_SUCCESS):GetLastError();
    },true);
}
DWORD __stdcall GDMisActivate(void* key,std::uint32_t toggle){
    if(toggle>1)return ERROR_INVALID_PARAMETER;
    return call(key,[&](View& view)->DWORD{std::lock_guard<std::mutex> lock(view.mailbox_mutex);view.activate_mail=toggle!=0;
        return SetEvent(view.wake.value)?DWORD(ERROR_SUCCESS):GetLastError();},true);
}
DWORD __stdcall GDMisWait(void* key){return call(key,[](View& view){
    const auto result=MsgWaitForMultipleObjectsEx(1,&view.wake.value,view.pointer_move.wait_ms(GetTickCount64()),QS_ALLINPUT,MWMO_INPUTAVAILABLE);
    return result==WAIT_FAILED?GetLastError():DWORD(ERROR_SUCCESS);
});}
DWORD __stdcall GDMisWake(void* key){return call(key,[](View& view){return SetEvent(view.wake.value)?DWORD(ERROR_SUCCESS):GetLastError();},true);}
DWORD __stdcall GDMisDiagnostics(void* key,std::uint32_t* output,std::uint32_t count){
    if(!output || count!=32)return ERROR_INVALID_PARAMETER;
    return call(key,[&](View& view){std::lock_guard<std::mutex> lock(view.mailbox_mutex);auto values=view.diagnostic_snapshot;values[0]=1;
        std::copy(values.begin(),values.end(),output);return DWORD(ERROR_SUCCESS);
    },true);
}
DWORD __stdcall GDMisEndReason(void* key,std::uint32_t* reason){
    if(!reason)return ERROR_INVALID_PARAMETER;
    return call(key,[&](View& view){*reason=static_cast<std::uint32_t>(view.peer->end_reason());return DWORD(ERROR_SUCCESS);},true);
}
DWORD __stdcall GDMisTransportDiagnostics(void* key,std::uint32_t* output,std::uint32_t count){
    if(!output || count!=20)return ERROR_INVALID_PARAMETER;
    return call(key,[&](View& view){const auto v=view.peer->send_diagnostics();std::copy(v.begin(),v.end(),output);return DWORD(ERROR_SUCCESS);},true);
}
DWORD __stdcall GDMisStop(void* key){return call(key,[](View& view){view.peer->request_stop();SetEvent(view.wake.value);return DWORD(ERROR_SUCCESS);},true);}
DWORD __stdcall GDMisClose(void* key){
    auto context=lookup(key);if(!context)return ERROR_INVALID_HANDLE;View* view=nullptr;
    {std::unique_lock<std::shared_mutex> lock(context->mutex);
        if(!context->view)return ERROR_INVALID_HANDLE;
        if(context->view->owner!=GetCurrentThreadId())return ERROR_INVALID_THREAD_ID;
        view=context->view;view->peer->request_stop();context->view=nullptr;}
    // Keep its capacity reservation until all WebRTC/Win32/GPU teardown ended.
    // Neither registry nor per-context lock spans the destructor.
    delete view;auto& values=registry();std::unique_lock<std::shared_mutex> lock(values.mutex);values.values.erase(key);return ERROR_SUCCESS;
}
