#include "input.hpp"
#include <algorithm>
#include <stdexcept>

namespace remote {
namespace {
std::uint32_t number(const std::vector<std::uint8_t>& bytes,std::size_t offset,unsigned count){
    std::uint32_t result=0;for(unsigned i=0;i<count;++i)result|=std::uint32_t(bytes.at(offset+i))<<(8*i);return result;
}
INPUT key(unsigned code,bool down){
    INPUT value{};value.type=INPUT_KEYBOARD;value.ki.wVk=static_cast<WORD>(code);
    value.ki.dwFlags=down?0:KEYEVENTF_KEYUP;
    switch(code){case VK_RCONTROL:case VK_RMENU:case VK_INSERT:case VK_DELETE:
    case VK_HOME:case VK_END:case VK_PRIOR:case VK_NEXT:case VK_LEFT:case VK_RIGHT:
    case VK_UP:case VK_DOWN:case VK_DIVIDE:case VK_NUMLOCK:case VK_SNAPSHOT:
    case VK_LWIN:case VK_RWIN:case VK_APPS:value.ki.dwFlags|=KEYEVENTF_EXTENDEDKEY;}
    return value;
}
INPUT button(unsigned code,bool down){
    INPUT value{};value.type=INPUT_MOUSE;
    constexpr std::array<DWORD,3> downs{MOUSEEVENTF_LEFTDOWN,MOUSEEVENTF_RIGHTDOWN,MOUSEEVENTF_MIDDLEDOWN};
    constexpr std::array<DWORD,3> ups{MOUSEEVENTF_LEFTUP,MOUSEEVENTF_RIGHTUP,MOUSEEVENTF_MIDDLEUP};
    value.mi.dwFlags=down?downs.at(code-1):ups.at(code-1);return value;
}
}
InputLedger::InputLedger(std::function<UINT(const std::vector<INPUT>&)> send):send_(std::move(send)){
    if(!send_)throw std::invalid_argument("input_sink_missing");
}
bool InputLedger::held() const{
    return std::any_of(keys_.begin(),keys_.end(),[](bool value){return value;}) ||
        std::any_of(buttons_.begin(),buttons_.end(),[](bool value){return value;});
}
void InputLedger::abandon_logon(){keys_={};buttons_={};failed_=true;}
bool InputLedger::apply(const ipc::Message& m,const RECT& output,const RECT& screen,unsigned stream_width,unsigned stream_height){
    if(failed_ || m.header.kind!=ipc::Kind::input || m.payload.size()!=24)return false;
    const auto type=m.payload.at(0),down=m.payload.at(1);const auto code=number(m.payload,2,2);
    const auto x=number(m.payload,4,4),y=number(m.payload,8,4);
    const auto delta=static_cast<std::int32_t>(number(m.payload,12,4));
    if(type<1 || type>4 || down>1 || number(m.payload,16,4) || number(m.payload,20,4))return false;
    std::vector<INPUT> batch;
    if(type==1){
        if(code==0 || code>=keys_.size() || code==VK_PACKET || x || y || delta || (!down && !keys_.at(code)))return false;
        batch.push_back(key(code,down!=0));
        // Track before calling the OS: partial/failing injection still requires
        // conservative cleanup. Never log key values or retry a key down.
        if(down)keys_.at(code)=true;
    }else{
        const auto width=std::int64_t(output.right)-output.left,height=std::int64_t(output.bottom)-output.top;
        const auto sw=std::int64_t(screen.right)-screen.left,sh=std::int64_t(screen.bottom)-screen.top;
        if(!stream_width && width>0)stream_width=static_cast<unsigned>(width);
        if(!stream_height && height>0)stream_height=static_cast<unsigned>(height);
        if(width<=0 || height<=0 || sw<=1 || sh<=1 || stream_width<2 || stream_height<2 || x>=stream_width || y>=stream_height ||
            output.left<screen.left || output.top<screen.top || output.right>screen.right || output.bottom>screen.bottom)return false;
        INPUT move{};move.type=INPUT_MOUSE;move.mi.dwFlags=MOUSEEVENTF_MOVE|MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_VIRTUALDESK;
        const auto px=std::int64_t(x)*(width-1)/(stream_width-1),py=std::int64_t(y)*(height-1)/(stream_height-1);
        move.mi.dx=static_cast<LONG>(((std::int64_t(output.left)-screen.left+px)*65535)/(sw-1));
        move.mi.dy=static_cast<LONG>(((std::int64_t(output.top)-screen.top+py)*65535)/(sh-1));
        batch.push_back(move);
        if(type==2){
            if(code<1 || code>3 || delta || (!down && !buttons_.at(code-1)))return false;
            batch.push_back(button(code,down!=0));if(down)buttons_.at(code-1)=true;
        }else if(type==3){if(code || down || delta)return false;}
        else{
            if(code || down || !delta || delta<-1200 || delta>1200 || delta%120)return false;
            INPUT wheel{};wheel.type=INPUT_MOUSE;wheel.mi.dwFlags=MOUSEEVENTF_WHEEL;wheel.mi.mouseData=static_cast<DWORD>(delta);batch.push_back(wheel);
        }
    }
    if(send_(batch)!=batch.size()){failed_=true;return false;}
    if(type==1 && !down)keys_.at(code)=false;
    if(type==2 && !down)buttons_.at(code-1)=false;
    return true;
}
bool InputLedger::release_up(unsigned type,unsigned code,bool same){
    if(!same)return false;
    if(type==1){
        if(code==0 || code>254 || code==VK_PACKET)return false;
        if(!keys_.at(code))return true;
        if(send_({key(code,false)})!=1){failed_=true;return false;}
        keys_.at(code)=false;return true;
    }
    if(type!=2 || code<1 || code>buttons_.size())return false;
    if(!buttons_.at(code-1))return true;
    if(send_({button(code,false)})!=1){failed_=true;return false;}
    buttons_.at(code-1)=false;return true;
}
bool InputLedger::release_all(bool same){
    if(!held()){if(same)failed_=false;return true;}
    if(!same)return false; // Retain the ledger until the host allows cleanup.
    bool passed=true;
    for(unsigned code=1;code<keys_.size();++code)if(keys_.at(code)){
        if(send_({key(code,false)})==1)keys_.at(code)=false;else passed=false;
    }
    for(unsigned code=1;code<=buttons_.size();++code)if(buttons_.at(code-1)){
        if(send_({button(code,false)})==1)buttons_.at(code-1)=false;else passed=false;
    }
    failed_=!passed;
    return passed;
}
UINT send_windows_input(const std::vector<INPUT>& batch){
    if(batch.empty() || batch.size()>2)return 0;
    return SendInput(static_cast<UINT>(batch.size()),const_cast<INPUT*>(batch.data()),sizeof(INPUT));
}
}
