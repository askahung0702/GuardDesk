// Included in broker_api.cpp's anonymous namespace. No DLL detach destructor
// waits for processes; explicit close owns teardown outside the loader lock.
struct Context {
    GD_REMOTE_START spec{};
    Handle image,media_image,bridge_image,broker_image,cancel,stop,job,process,media_process,bootstrap,media_bootstrap;
    std::unique_ptr<FramePool> frames;
    std::unique_ptr<ipc::Channel> channel,media_channel;
    std::wstring nonce,media_nonce;
    std::uint64_t sequence=0,local_sequence=0,viewer_sequence=0,media_sequence=0,media_write_sequence=0;
    std::atomic<bool> terminal{false};
    bool launched=false,configured=false,owned_loopback=false,relay_configured=false,media_signaled=false;
    std::mutex operation;
    struct Outbound{
        bool media;std::vector<std::uint8_t> packet;
        Outbound(bool value,std::vector<std::uint8_t> bytes):media(value),packet(std::move(bytes)){}
        Outbound(Outbound&&)=default;Outbound(const Outbound&)=delete;
        ~Outbound(){if(!packet.empty())SecureZeroMemory(packet.data(),packet.size());}
        Outbound& operator=(Outbound&& other){if(!packet.empty())SecureZeroMemory(packet.data(),packet.size());media=other.media;packet=std::move(other.packet);return *this;}
    };
    std::mutex mailbox;std::deque<Outbound> outbound;std::deque<std::vector<std::uint8_t>> signals;
    std::optional<std::vector<std::uint8_t>> worker_snapshot,media_snapshot;
    Handle wake;std::thread pump;std::string pump_error;
#ifdef GUARDDESK_OWNED_BROKER_FIXTURES
    bool owned_fixture=false;
    Context():owned_fixture(true){} // separate probe target only, no installed paths
#endif
    explicit Context(const GD_REMOTE_START& input):spec(input){
        phase="broker_reserve_validation";
        require(input.bytes==sizeof(input) && input.format==1 && input.wts_session>0 && input.administrator<=1 && input.can_control<=1 && !input.reserved && (!input.administrator || input.can_control) && input.logon_time && input.consent_filetime && input.transport);
        const auto now=GetTickCount64();require(ipc::valid_consent(input.consent_tick_deadline,now));
        require(std::find(std::begin(input.user_sid),std::end(input.user_sid),L'\0')!=std::end(input.user_sid));
        PSID sid=nullptr;require(ConvertStringSidToSidW(input.user_sid,&sid)!=FALSE);LocalFree(sid);
        const auto id=session();require(std::any_of(id.begin(),id.end(),[](auto c){return c!=0;}));
        require_broker_trust();phase="broker_image_pin";const auto paths=installed_cohort();
        broker_image.value=pin_program_image(paths.broker);image.value=pin_program_image(paths.worker);
        media_image.value=pin_program_image(paths.media);bridge_image.value=pin_program_image(paths.bridge);
        Security security;
        auto random_nonce=[](){std::array<std::uint8_t,16> random{};require(BCryptGenRandom(nullptr,random.data(),static_cast<ULONG>(random.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0);return hexadecimal(random.data(),random.size());};
        nonce=random_nonce();media_nonce=random_nonce();require(nonce!=media_nonce);
        cancel.value=CreateEventW(&security.attributes,TRUE,FALSE,nullptr);require(cancel.value!=nullptr);
        wake.value=CreateEventW(&security.attributes,FALSE,FALSE,nullptr);require(wake.value!=nullptr);
        stop.value=CreateEventW(&security.attributes,TRUE,FALSE,nullptr);require(stop.value!=nullptr);
        channel=ipc::Channel::listen(nonce,input.administrator?L"S-1-5-18":input.user_sid,cancel.value);
        media_channel=ipc::Channel::listen(media_nonce,input.user_sid,cancel.value,true);
        frames=std::make_unique<FramePool>(id,1920,1080);
        job.value=CreateJobObjectW(&security.attributes,nullptr);require(job.value!=nullptr);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit=2;require(SetInformationJobObject(job.value,JobObjectExtendedLimitInformation,&limits,sizeof(limits))!=FALSE);
    }
    ipc::Session session()const{ipc::Session id{};std::copy_n(spec.session,id.size(),id.begin());return id;}
    void live(){
        if(terminal){std::lock_guard<std::mutex> lock(mailbox);throw std::runtime_error(pump_error.empty()?"native_broker_stopped":pump_error);}
        require(GetTickCount64()<spec.consent_tick_deadline);
    }
    void check_logon(HANDLE token){
        DWORD bytes=0;GetTokenInformation(token,TokenUser,nullptr,0,&bytes);require(bytes>0 && bytes<65536);
        std::vector<std::uint8_t> raw(bytes);require(GetTokenInformation(token,TokenUser,raw.data(),bytes,&bytes)!=FALSE);
        TOKEN_USER user{};std::memcpy(&user,raw.data(),sizeof(user));LPWSTR text=nullptr;require(ConvertSidToStringSidW(user.User.Sid,&text)!=FALSE);
        const bool sid=std::wstring(text)==spec.user_sid;LocalFree(text);require(sid);
        TOKEN_STATISTICS stats{};require(GetTokenInformation(token,TokenStatistics,&stats,sizeof(stats),&bytes)!=FALSE && stats.TokenType==TokenPrimary);
        const auto authentication=(std::uint64_t(static_cast<DWORD>(stats.AuthenticationId.HighPart))<<32)|stats.AuthenticationId.LowPart;
        require(authentication && (!spec.authentication || authentication==spec.authentication));spec.authentication=authentication;
        LPWSTR info=nullptr;DWORD count=0;
        require(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,spec.wts_session,WTSSessionInfoEx,&info,&count)!=FALSE);
        const auto* value=reinterpret_cast<WTSINFOEXW*>(info);
        const bool okay=count>=sizeof(WTSINFOEXW) && value->Level==1 && value->Data.WTSInfoExLevel1.SessionState==WTSActive &&
            value->Data.WTSInfoExLevel1.SessionFlags==WTS_SESSIONSTATE_UNLOCK && static_cast<std::uint64_t>(value->Data.WTSInfoExLevel1.LogonTime.QuadPart)==spec.logon_time;
        WTSFreeMemory(info);require(okay);
    }
    void secure_defaults(HANDLE token,Security& security){
        PACL dacl=nullptr;BOOL present=FALSE,defaulted=FALSE;
        require(GetSecurityDescriptorDacl(security.attributes.lpSecurityDescriptor,&present,&dacl,&defaulted) && present && dacl);
        TOKEN_DEFAULT_DACL defaults{dacl};require(SetTokenInformation(token,TokenDefaultDacl,&defaults,sizeof(defaults))!=FALSE);
    }
    void launch_child(bool media,HANDLE token){
        phase=media?"media_process_launch":"worker_process_launch";live();const auto paths=installed_cohort();Security security;const auto& path=media?paths.media:paths.worker;
        const auto& name=media?media_nonce:nonce;auto& target=media?media_process:process;auto& section=media?media_bootstrap:bootstrap;
        auto& pipe=media?media_channel:channel;
        std::wostringstream command;command<<L'"'<<path<<L"\" "<<(media?L"--broker-media ":L"--broker-worker ")<<name;
        auto line=command.str();STARTUPINFOW startup{};startup.cb=sizeof(startup);wchar_t desktop[]=L"winsta0\\default";startup.lpDesktop=desktop;
        PROCESS_INFORMATION child{};
        win(CreateProcessAsUserW(token,path.c_str(),line.data(),&security.attributes,&security.attributes,FALSE,
            CREATE_SUSPENDED|CREATE_NO_WINDOW|NORMAL_PRIORITY_CLASS,nullptr,paths.root.c_str(),&startup,&child),"create_process");
        target.value=child.hProcess;Handle thread(child.hThread);
        try{
            require(AssignProcessToJobObject(job.value,target.value)!=FALSE);live();
            ipc::Peer self(GetCurrentProcessId()),peer(child.dwProcessId);
            require_fixed_peer(peer,path,!media && spec.administrator?L"S-1-5-18":spec.user_sid,spec.wts_session);
            require(ipc::pipe_owner(target.value)==L"S-1-5-18" && ipc::pipe_owner(thread.value)==L"S-1-5-18");
            LaunchCapsule capsule{};capsule.bytes=sizeof(capsule);capsule.spec=spec;capsule.role=media?2:1;
            capsule.parent_pid=self.identity().pid;capsule.parent_created=self.identity().created;
            auto duplicate=[&](HANDLE source,DWORD access){HANDLE result=nullptr;require(DuplicateHandle(GetCurrentProcess(),source,target.value,&result,access,FALSE,0)!=FALSE);return reinterpret_cast<std::uintptr_t>(result);};
            capsule.parent_process=duplicate(GetCurrentProcess(),PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE);
            Handle parent_token;require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|READ_CONTROL,&parent_token.value)!=FALSE);
            require_query_only_kernel_trust(parent_token.value,TOKEN_QUERY|READ_CONTROL);capsule.parent_query_token=duplicate(parent_token.value,TOKEN_QUERY);
            capsule.stop=duplicate(stop.value,SYNCHRONIZE|READ_CONTROL);
            for(unsigned i=0;i<2;++i)capsule.frames.at(i)=reinterpret_cast<std::uintptr_t>(media?frames->duplicate_read(i,target.value):frames->duplicate_write(i,target.value));
            validate_launch_capsule(capsule,GetTickCount64());Security section_security(spec.user_sid);
            section.value=CreateFileMappingW(INVALID_HANDLE_VALUE,&section_security.attributes,PAGE_READWRITE,0,sizeof(capsule),(L"Global\\GuardDesk-Remote-Launch-"+name).c_str());
            require(section.value && GetLastError()!=ERROR_ALREADY_EXISTS);
            void* view=MapViewOfFile(section.value,FILE_MAP_WRITE,0,0,sizeof(capsule));require(view!=nullptr);std::memcpy(view,&capsule,sizeof(capsule));UnmapViewOfFile(view);
            phase=media?"media_pipe_handshake":"worker_pipe_handshake";live();require(ResumeThread(thread.value)!=MAXDWORD);
            try{pipe->accept(peer.identity(),L"S-1-5-18",5000);live();}
            catch(const std::exception& error){
                // Read before job cleanup; otherwise our termination masks the
                // loader/entry failure with the cleanup exit code. Fixed scalar
                // diagnostics only: no stderr, paths, SDP or credentials.
                DWORD code=0;
                const bool exited=WaitForSingleObject(target.value,0)==WAIT_OBJECT_0;
                const bool read=exited && GetExitCodeProcess(target.value,&code)!=FALSE;
                throw std::runtime_error(std::string(error.what())+(read?"/child_exit="+std::to_string(code):exited?"/child_exit_unreadable":"/child_running"));
            }
            if(!media){const auto hello=pipe->read(5000);require(hello.header.kind==ipc::Kind::hello && hello.header.session==session() && hello.header.transport_generation==spec.transport);}
            CloseHandle(section.value);section.value=nullptr;
        }catch(...){
            stop_now();TerminateJobObject(job.value,1);
            if(WaitForSingleObject(target.value,1000)!=WAIT_OBJECT_0){TerminateProcess(target.value,1);WaitForSingleObject(target.value,1000);}throw;
        }
    }
    void launch(){
        phase="user_logon_token";live();require(!launched);Security security;Handle user;
        {Tcb privilege;win(WTSQueryUserToken(spec.wts_session,&user.value),"query_user_token");}check_logon(user.value);
        constexpr DWORD rights=TOKEN_ASSIGN_PRIMARY|TOKEN_DUPLICATE|TOKEN_QUERY|TOKEN_ADJUST_DEFAULT|TOKEN_ADJUST_SESSIONID;
        Handle worker_token;
        if(spec.administrator){Handle system;require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE,&system.value)!=FALSE);
            require(DuplicateTokenEx(system.value,rights,nullptr,SecurityImpersonation,TokenPrimary,&worker_token.value)!=FALSE);
            DWORD id=spec.wts_session;Tcb privilege;require(SetTokenInformation(worker_token.value,TokenSessionId,&id,sizeof(id))!=FALSE);
        }else require(DuplicateTokenEx(user.value,rights,nullptr,SecurityImpersonation,TokenPrimary,&worker_token.value)!=FALSE);
        if(spec.administrator)secure_defaults(worker_token.value,security);
        else set_user_runtime_defaults(worker_token.value,spec.user_sid);
        launch_child(false,worker_token.value);
        phase="media_restricted_token";Handle restricted,media_token;PSID administrators=nullptr;require(ConvertStringSidToSidW(L"S-1-5-32-544",&administrators)!=FALSE);
        SID_AND_ATTRIBUTES deny{administrators,0};const auto created=CreateRestrictedToken(user.value,DISABLE_MAX_PRIVILEGE,1,&deny,0,nullptr,0,nullptr,&restricted.value);LocalFree(administrators);require(created!=FALSE);
        require(DuplicateTokenEx(restricted.value,rights,nullptr,SecurityImpersonation,TokenPrimary,&media_token.value)!=FALSE);
        PSID low=nullptr;require(ConvertStringSidToSidW(L"S-1-16-4096",&low)!=FALSE);TOKEN_MANDATORY_LABEL label{{low,SE_GROUP_INTEGRITY}};
        const auto labeled=SetTokenInformation(media_token.value,TokenIntegrityLevel,&label,sizeof(label)+GetLengthSid(low));LocalFree(low);require(labeled!=FALSE);
        // A user-mode media runtime must be able to create/use its own objects
        // during Windows DLL initialization. SYSTEM-only token defaults abort
        // before main (0xC0000142). Process/thread security remains SYSTEM-only.
        set_media_runtime_defaults(media_token.value,spec.user_sid);
        launch_child(true,media_token.value);live();launched=true;
        pump=std::thread([this]{pump_loop();});
    }
    std::uint64_t worker_status_sequence=1;
    void send(ipc::Message message){
        live();require(launched && local_sequence<std::numeric_limits<std::uint64_t>::max());
        message.header.sequence=++local_sequence;channel->write(ipc::encode_control(message,ipc::Direction::broker_to_worker),100);
    }
    void enqueue(bool media,std::vector<std::uint8_t> packet){
        live();require(launched);std::lock_guard<std::mutex> lock(mailbox);require(outbound.size()<32);
        outbound.push_back({media,std::move(packet)});SetEvent(wake.value);
    }
    void pump_loop(){
        try{while(!terminal){
            live();
            for(unsigned i=0;i<8;++i){
                std::optional<Outbound> item;
                {std::lock_guard<std::mutex> lock(mailbox);if(!outbound.empty()){item=std::move(outbound.front());outbound.pop_front();}}
                if(!item)break;
                if(item->media)media_channel->write_media(item->packet,100);
                else send(ipc::control_message(item->packet,ipc::Direction::broker_to_worker));
            }
            for(auto child:{std::make_pair(process.value,"worker_exit/"),std::make_pair(media_process.value,"media_exit/")}){
                if(WaitForSingleObject(child.first,0)!=WAIT_TIMEOUT){DWORD code=0;GetExitCodeProcess(child.first,&code);throw std::runtime_error(std::string(child.second)+std::to_string(code));}
            }
            for(unsigned i=0;i<16 && media_channel->available();++i){
                const auto m=media_channel->read_media(100);require(m.session==session() && m.transport==spec.transport && m.sequence>media_sequence);media_sequence=m.sequence;
                if(m.kind==ipc::MediaKind::network_control){
                    auto command=ipc::control_message(m.payload,ipc::Direction::broker_to_worker);require(command.header.sequence>viewer_sequence);viewer_sequence=command.header.sequence;
                    require(command.header.kind!=ipc::Kind::input || spec.can_control);const bool stop_command=command.header.kind==ipc::Kind::stop;
                    send(std::move(command));if(stop_command){stop_now();break;}
                }else if(m.kind==ipc::MediaKind::consumed){
                    auto number=[&](unsigned offset){std::uint64_t n=0;for(unsigned j=0;j<8;++j)n|=std::uint64_t(m.payload.at(offset+j))<<(j*8);return n;};
                    send({{ipc::Kind::consumed,0,session(),number(0),1,number(8),spec.transport},{}});
                }else{
                    auto wire=ipc::encode_media(m,ipc::MediaDirection::media_to_broker);std::lock_guard<std::mutex> lock(mailbox);
                    if(m.kind==ipc::MediaKind::stats)media_snapshot=std::move(wire);
                    else{require(signals.size()<4);signals.push_back(std::move(wire));}
                }
            }
            if(terminal)break;
            if(channel->available()){
                const auto m=channel->read(100);require(m.header.kind==ipc::Kind::stats && m.header.session==session() && m.header.transport_generation==spec.transport && m.header.sequence>worker_status_sequence && valid_worker_status(m.payload));
                worker_status_sequence=m.header.sequence;std::lock_guard<std::mutex> lock(mailbox);worker_snapshot=m.payload;
            }
            bool pending=false;{std::lock_guard<std::mutex> lock(mailbox);pending=!outbound.empty();}
            if(!pending && !media_channel->available())media_channel->wait_readable(20,wake.value);
        }}catch(const std::exception& error){
            std::string text=error.what();if(text.size()>90 || !std::all_of(text.begin(),text.end(),[](char c){return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || std::string("_/:=.-").find(c)!=std::string::npos;}))text="native_pump_failure";
            {std::lock_guard<std::mutex> lock(mailbox);pump_error="pump/"+text;}stop_now();
        }catch(...){stop_now();}
    }
    void stop_now(){terminal=true;if(wake.value)SetEvent(wake.value);if(stop.value)SetEvent(stop.value);if(cancel.value)SetEvent(cancel.value);}
    ~Context(){
        stop_now();
        if(pump.joinable())pump.join(); // only explicit owner teardown, never DLL detach
#ifdef GUARDDESK_OWNED_BROKER_FIXTURES
        if(owned_fixture)return;
#endif
        // Kill/close the cohort job before pixel mappings or image pins go away.
        HANDLE children[]{process.value,media_process.value};
        for(auto child:children)if(child && WaitForSingleObject(child,500)!=WAIT_OBJECT_0){TerminateJobObject(job.value,1);break;}
        if(job.value){CloseHandle(job.value);job.value=nullptr;}
        for(auto child:children)if(child)WaitForSingleObject(child,500);
        channel.reset();media_channel.reset();frames.reset();
    }
};
struct Registry {std::mutex mutex;std::map<void*,std::shared_ptr<Context>> entries;std::uintptr_t next=0;unsigned reservations=0;};
Registry& contexts(){
    // Pinned DLL + deliberate process-lifetime registry avoids invoking STL/job
    // teardown under DllMain. Explicit close removes every normal live entry.
    static Registry* value=[](){HMODULE module=nullptr;require(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(&contexts),&module)!=FALSE);return new Registry;}();return *value;
}
std::shared_ptr<Context> find(void* value){auto& r=contexts();std::lock_guard<std::mutex> lock(r.mutex);auto i=r.entries.find(value);require(i!=r.entries.end());return i->second;}
thread_local std::string failure;
DWORD failed(){try{throw;}catch(const std::exception& error){failure=std::string(phase)+":"+error.what();}catch(...){failure="native_broker_unknown_exception";}return ERROR_FUNCTION_FAILED;}
