// Compiles the actual pump into a separate standard-user fixture. No installed
// images, SYSTEM token, desktop, center, or OS input. Production has no fixture.
#define GUARDDESK_OWNED_BROKER_FIXTURES
#include "broker_api.cpp"
#include <objbase.h>
#include <iostream>

namespace {
std::wstring owned_nonce(){GUID id{};if(FAILED(CoCreateGuid(&id)))throw std::runtime_error("owned_guid");return hexadecimal(reinterpret_cast<const std::uint8_t*>(&id),sizeof(id));}
std::unique_ptr<ipc::Channel> connect_owned(const std::wstring& nonce,Context& context,bool media){
    return ipc::Channel::listen(nonce,ipc::Peer(GetCurrentProcessId()).identity().sid,context.cancel.value,media);
}
}
int main(){
    try{
        auto context=std::make_shared<Context>();context->spec.transport=1;context->spec.session[0]=7;context->spec.can_control=1;
        context->spec.consent_tick_deadline=GetTickCount64()+5000;context->launched=true;
        context->cancel.value=CreateEventW(nullptr,TRUE,FALSE,nullptr);context->stop.value=CreateEventW(nullptr,TRUE,FALSE,nullptr);context->wake.value=CreateEventW(nullptr,FALSE,FALSE,nullptr);
        require(context->cancel.value && context->stop.value && context->wake.value);
        context->process.value=context->media_process.value=GetCurrentProcess();
        const auto control=owned_nonce(),media=owned_nonce();
        context->channel=connect_owned(control,*context,false);context->media_channel=connect_owned(media,*context,true);
        const auto identity=ipc::Peer(GetCurrentProcessId()).identity();std::atomic<bool> received=false,worker_ok=false,media_ok=false;
        std::thread worker([&]{try{
            auto pipe=ipc::Channel::open(control,identity,identity.sid,context->cancel.value,2000);
            auto message=pipe->read(2000);require(message.header.kind==ipc::Kind::input && message.header.sequence==1 && message.payload.at(2)==27);
            received=true;WorkerStatus status;status.input_received=status.input_accepted=1;const auto body=status.encode();
            pipe->write(ipc::encode_control({{ipc::Kind::stats,static_cast<std::uint32_t>(body.size()),context->session(),0,2,0,1},{body.begin(),body.end()}},ipc::Direction::worker_to_broker),1000);
            worker_ok=true;WaitForSingleObject(context->cancel.value,2000);
        }catch(...){worker_ok=false;SetEvent(context->cancel.value);}});
        std::thread client([&]{try{
            auto pipe=ipc::Channel::open(media,identity,identity.sid,context->cancel.value,2000);
            std::vector<std::uint8_t> payload(24);payload[0]=1;payload[1]=1;payload[2]=27;
            ipc::Message input{{ipc::Kind::input,24,context->session(),1,1,1,1},std::move(payload)};
            const auto bytes=ipc::encode_control(input,ipc::Direction::broker_to_worker);
            pipe->write_media(ipc::encode_media({ipc::MediaKind::network_control,context->session(),1,1,bytes},ipc::MediaDirection::media_to_broker),1000);
            media_ok=true;WaitForSingleObject(context->cancel.value,2000);
        }catch(...){media_ok=false;SetEvent(context->cancel.value);}});
        bool okay=false;
        try{
            context->channel->accept(identity,identity.sid,2000);context->media_channel->accept(identity,identity.sid,2000);
            context->pump=std::thread([&]{context->pump_loop();});
            const auto started=GetTickCount64();
            // Python/ABI polling is deliberately absent while forwarding.
            while(!(received && worker_ok && media_ok) && GetTickCount64()-started<1000)Sleep(1);
            require(received && worker_ok && media_ok);
            while(GetTickCount64()-started<1000){
                {std::lock_guard<std::mutex> lock(context->mailbox);if(context->worker_snapshot){okay=valid_worker_status(*context->worker_snapshot);break;}}
                Sleep(1);
            }
        }catch(...){context->stop_now();worker.join();client.join();throw;}
        context->stop_now();worker.join();client.join();context.reset();require(okay);
        std::cout<<"{\"passed\":true,\"actual_native_pump_without_python_poll\":true,\"authenticated_owned_pipes\":true,\"status_v3\":true,\"SYSTEM_boundary\":false,\"desktop_capture\":false,\"OS_input\":false}\n";return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
