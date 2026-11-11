#include "relay_policy.hpp"
#include <algorithm>
#include <stdexcept>
namespace remote {
namespace {
void require(bool value){if(!value)throw std::invalid_argument("relay_policy_rejected");}
std::uint64_t get(const std::vector<std::uint8_t>& b,unsigned at,unsigned count){std::uint64_t value=0;for(unsigned i=0;i<count;++i)value|=std::uint64_t(b.at(at+i))<<(8*i);return value;}
void zero(const std::vector<std::uint8_t>& b,unsigned start,unsigned end){for(auto i=start;i<end;++i)require(!b.at(i));}
bool unicast(std::uint32_t ip,bool owned){const auto first=ip&255,second=(ip>>8)&255;
    return first && first<224 && ip!=0xffffffff && (first!=127 || owned) && !(first==169 && second==254);}
bool dns(const std::string& name){if(name.empty() || name.size()>253)return false;unsigned label=0;bool number=true;char prior=0;
    for(char c:name){if(c=='.'){if(!label || prior=='-')return false;label=0;}
        else {if(!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || (c=='-' && label)))return false;
            if(++label>63)return false;if(c<'0' || c>'9')number=false;}prior=c;}
    return label && prior!='-' && !number;
}
}
RelayPolicy parse_relay(const std::vector<std::uint8_t>& b){
    require(b.size()>=128 && b.size()<=1152 && b.at(0)=='G' && b.at(1)=='D' && b.at(2)=='R' && b.at(3)=='3' && get(b,4,2)==1 && get(b,8,4)==b.size());
    const auto mode=get(b,6,2);require(mode==1 || mode==2);zero(b,12,16);zero(b,92,128);
    RelayPolicy value;value.owned_udp=mode==2;std::copy_n(b.begin()+16,32,value.identity.begin());require(std::any_of(value.identity.begin(),value.identity.end(),[](auto v){return v!=0;}));
    value.expires=get(b,48,8);value.turn_ipv4=static_cast<std::uint32_t>(get(b,56,4));value.turn_port=static_cast<unsigned>(get(b,60,2));
    const auto host=get(b,62,2),user=get(b,64,2),password=get(b,66,2),count=get(b,68,4);
    require(value.expires && value.turn_port && host<=253 && user>=1 && user<=256 && password>=16 && password<=512 && count>=1 && count<=4 && 128+host+user+password==b.size());
    zero(b,72+static_cast<unsigned>(count)*4,88);
    value.allocation_min=static_cast<unsigned>(get(b,88,2));value.allocation_max=static_cast<unsigned>(get(b,90,2));require(value.allocation_min && value.allocation_max>=value.allocation_min);
    for(unsigned i=0;i<count;++i){auto ip=static_cast<std::uint32_t>(get(b,72+i*4,4));require(std::find(value.allocation_ipv4.begin(),value.allocation_ipv4.end(),ip)==value.allocation_ipv4.end());value.allocation_ipv4.push_back(ip);}
    for(std::size_t i=128;i<b.size();++i)require(b.at(i)>=33 && b.at(i)<=126);
    value.hostname.assign(b.begin()+128,b.begin()+128+host);value.username.assign(b.begin()+128+host,b.begin()+128+host+user);value.password.assign(b.begin()+128+host+user,b.end());
    require(value.owned_udp?value.hostname.empty():dns(value.hostname));return value;
}
void require_relay(const RelayPolicy& value,std::uint64_t now,std::uint64_t consent,bool owned){
    require(value.expires>now && value.expires<=consent && value.expires-now<=600000 && (!value.owned_udp || owned));
    require(unicast(value.turn_ipv4,owned));for(auto ip:value.allocation_ipv4)require(unicast(ip,owned));
}
}
