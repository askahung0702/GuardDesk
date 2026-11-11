#include "h264_frame_binding.hpp"
#include <span>
#include <algorithm>
#include <stdexcept>

namespace remote {
namespace {
constexpr std::size_t packet_limit=4*1024*1024;
constexpr std::array<std::uint8_t,16> uuid{'G','u','a','r','d','D','e','s','k','F','r','a','m','e','1',0};
void require(bool okay){if(!okay)throw std::invalid_argument("H264_frame_binding_rejected");}
struct Nal{std::size_t prefix=0,begin=0,end=0;unsigned type=0;};
struct Nals{std::array<Nal,256> values{};std::size_t count=0;};
Nals nals(const std::vector<std::uint8_t>& packet){
    require(!packet.empty() && packet.size()<=packet_limit);const auto bytes=std::span<const std::uint8_t>(packet);Nals result;
    for(std::size_t i=0;i+3<=bytes.size();){
        unsigned prefix=0;
        if(bytes[i]==0 && bytes[i+1]==0){
            if(i+4<=bytes.size() && bytes[i+2]==0 && bytes[i+3]==1)prefix=4;
            else if(bytes[i+2]==1)prefix=3;
        }
        if(!prefix){++i;continue;}
        require(result.count<result.values.size() && i+prefix<bytes.size());
        if(result.count)result.values.at(result.count-1).end=i;else require(i==0);
        const auto header=bytes[i+prefix];require((header&128)==0 && (header&31)>0 && (header&31)<24);
        result.values.at(result.count++)={i,i+prefix,bytes.size(),static_cast<unsigned>(header&31)};i+=prefix;
    }
    require(result.count>0);for(std::size_t i=0;i<result.count;++i)require(result.values.at(i).end>result.values.at(i).begin);
    return result;
}
std::optional<std::vector<std::uint8_t>> extract(const std::vector<std::uint8_t>& packet,const Nals& ranges){
    std::optional<std::vector<std::uint8_t>> metadata;const auto bytes=std::span<const std::uint8_t>(packet);
    for(std::size_t index=0;index<ranges.count;++index){
        const auto& nal=ranges.values.at(index);if(nal.type!=6)continue;
        auto encoded=bytes.subspan(nal.begin+1,nal.end-nal.begin-1);require(encoded.size()<=4096);
        std::vector<std::uint8_t> rbsp;rbsp.reserve(encoded.size());unsigned zeros=0;
        for(std::size_t i=0;i<encoded.size();++i){const auto value=encoded[i];
            if(zeros>=2 && value==3){require(i+1<encoded.size() && encoded[i+1]<=3);zeros=0;continue;}
            rbsp.push_back(value);zeros=value==0?zeros+1:0;
        }
        // Byte-stream trailing_zero_8bits are outside the SEI RBSP.
        while(!rbsp.empty() && rbsp.back()==0)rbsp.pop_back();
        require(!rbsp.empty() && rbsp.back()==0x80);std::size_t cursor=0;
        while(cursor+1<rbsp.size()){
            std::size_t type=0,size=0;unsigned byte=0;
            do{require(cursor+1<rbsp.size());byte=rbsp.at(cursor++);type+=byte;}while(byte==255);
            do{require(cursor+1<rbsp.size());byte=rbsp.at(cursor++);size+=byte;}while(byte==255);
            require(size<rbsp.size()-cursor);auto body=std::span<const std::uint8_t>(rbsp).subspan(cursor,size);
            if(type==5 && body.size()>=uuid.size() && std::equal(uuid.begin(),uuid.end(),body.begin())){
                require(!metadata && body.size()==uuid.size()+88);
                auto value=body.subspan(uuid.size());metadata=std::vector<std::uint8_t>(value.begin(),value.end());decode_video_binding(*metadata);
            }
            cursor+=size;
        }
        require(cursor+1==rbsp.size());
    }
    return metadata;
}
}
std::optional<std::vector<std::uint8_t>> h264_frame_metadata(const std::vector<std::uint8_t>& packet){const auto ranges=nals(packet);return extract(packet,ranges);}
std::vector<std::uint8_t> bind_h264_frame(const std::vector<std::uint8_t>& packet,const std::vector<std::uint8_t>& metadata){
    require(metadata.size()==88);decode_video_binding(metadata);const auto ranges=nals(packet);
    require(ranges.count<ranges.values.size() && !extract(packet,ranges));
    std::vector<std::uint8_t> rbsp{5,static_cast<std::uint8_t>(uuid.size()+metadata.size())};
    rbsp.insert(rbsp.end(),uuid.begin(),uuid.end());rbsp.insert(rbsp.end(),metadata.begin(),metadata.end());rbsp.push_back(0x80);
    std::vector<std::uint8_t> sei{0,0,0,1,6};unsigned zeros=0;
    for(auto value:rbsp){if(zeros>=2 && value<=3){sei.push_back(3);zeros=0;}sei.push_back(value);zeros=value==0?zeros+1:0;}
    require(packet.size()<=packet_limit-sei.size());std::size_t at=packet.size();
    for(std::size_t i=0;i<ranges.count;++i)if(ranges.values.at(i).type==1 || ranges.values.at(i).type==5){at=ranges.values.at(i).prefix;break;}
    require(at<packet.size());std::vector<std::uint8_t> result;result.reserve(packet.size()+sei.size());
    const auto bytes=std::span<const std::uint8_t>(packet);auto before=bytes.first(at),after=bytes.subspan(at);
    result.insert(result.end(),before.begin(),before.end());result.insert(result.end(),sei.begin(),sei.end());result.insert(result.end(),after.begin(),after.end());return result;
}
}
