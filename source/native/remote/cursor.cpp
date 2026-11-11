#include "cursor.hpp"
#include "capture.hpp"
#include <algorithm>
#include <stdexcept>
namespace remote {
CursorUpdate::~CursorUpdate(){if(!bgra.empty())SecureZeroMemory(bgra.data(),bgra.size());}
CursorUpdate& CursorUpdate::operator=(CursorUpdate value) noexcept{
    using std::swap;
    swap(session,value.session);swap(transport,value.transport);swap(generation,value.generation);swap(sequence,value.sequence);swap(shape,value.shape);
    swap(source_width,value.source_width);swap(source_height,value.source_height);swap(width,value.width);swap(height,value.height);swap(hot_x,value.hot_x);swap(hot_y,value.hot_y);
    swap(x,value.x);swap(y,value.y);swap(mode,value.mode);bgra.swap(value.bgra);xor_mask.swap(value.xor_mask);return *this;
}
namespace {
void require(bool value){if(!value)throw std::invalid_argument("cursor_rejected");}
void valid(const CursorUpdate& value){
    require(value.xor_mask.empty()); // unresolved capture-local data is never wire-valid
    require(std::any_of(value.session.begin(),value.session.end(),[](auto v){return v!=0;}) && value.transport && value.generation && value.sequence);
    require(value.source_width>0 && value.source_height>0 && value.source_width<=8192 && value.source_height<=8192 &&
        value.x>=-8192 && value.y>=-8192 && value.x<=8192 && value.y<=8192 && static_cast<unsigned>(value.mode)<=3);
    if(value.mode!=CursorMode::separate){require(value.bgra.empty() && !value.width && !value.height && !value.hot_x && !value.hot_y && !value.shape);return;}
    require(value.width>0 && value.height>0 && value.width<=cursor_max_side && value.height<=cursor_max_side && value.hot_x<value.width && value.hot_y<value.height && value.shape);
    require(value.bgra.empty() || value.bgra.size()==std::size_t(value.width)*value.height*4);
    for(std::size_t i=0;i<value.bgra.size();i+=4)for(unsigned channel=0;channel<3;++channel)require(value.bgra.at(i+channel)<=value.bgra.at(i+3));
}
std::uint64_t get(const std::vector<std::uint8_t>& b,unsigned at,unsigned count){std::uint64_t value=0;for(unsigned i=0;i<count;++i)value|=std::uint64_t(b.at(at+i))<<(8*i);return value;}
void put(std::vector<std::uint8_t>& b,unsigned at,std::uint64_t value,unsigned count){for(unsigned i=0;i<count;++i)b.at(at+i)=static_cast<std::uint8_t>(value>>(8*i));}
}
std::vector<std::uint8_t> encode_cursor(const CursorUpdate& value){valid(value);std::vector<std::uint8_t> b(cursor_wire_header+value.bgra.size());
    b.at(0)='G';b.at(1)='D';b.at(2)='C';b.at(3)='3';put(b,4,1,2);put(b,6,static_cast<unsigned>(value.mode),2);put(b,8,value.bgra.size(),4);
    std::copy(value.session.begin(),value.session.end(),b.begin()+16);put(b,32,value.transport,8);put(b,40,value.generation,8);put(b,48,value.sequence,8);
    put(b,56,value.source_width,4);put(b,60,value.source_height,4);put(b,64,static_cast<std::uint32_t>(value.x),4);put(b,68,static_cast<std::uint32_t>(value.y),4);
    put(b,72,value.width,2);put(b,74,value.height,2);put(b,76,value.hot_x,2);put(b,78,value.hot_y,2);put(b,80,value.shape,8);
    std::copy(value.bgra.begin(),value.bgra.end(),b.begin()+cursor_wire_header);return b;
}
CursorUpdate decode_cursor(const std::vector<std::uint8_t>& b){
    require(b.size()>=cursor_wire_header && b.size()<=cursor_wire_header+cursor_max_pixels && b.at(0)=='G' && b.at(1)=='D' && b.at(2)=='C' && b.at(3)=='3' && get(b,4,2)==1 && get(b,12,4)==0 && get(b,88,8)==0);
    require(get(b,8,4)==b.size()-cursor_wire_header);CursorUpdate v;v.mode=static_cast<CursorMode>(get(b,6,2));std::copy_n(b.begin()+16,16,v.session.begin());
    v.transport=get(b,32,8);v.generation=get(b,40,8);v.sequence=get(b,48,8);v.source_width=static_cast<unsigned>(get(b,56,4));v.source_height=static_cast<unsigned>(get(b,60,4));
    v.x=static_cast<std::int32_t>(get(b,64,4));v.y=static_cast<std::int32_t>(get(b,68,4));v.width=static_cast<unsigned>(get(b,72,2));v.height=static_cast<unsigned>(get(b,74,2));
    v.hot_x=static_cast<unsigned>(get(b,76,2));v.hot_y=static_cast<unsigned>(get(b,78,2));v.shape=get(b,80,8);v.bgra.assign(b.begin()+cursor_wire_header,b.end());valid(v);return v;
}
bool convert_cursor_shape(CursorUpdate& value,unsigned type,unsigned width,unsigned height,unsigned pitch,unsigned hot_x,unsigned hot_y,const std::vector<std::uint8_t>& bytes){
    auto unsupported=[&]{value.mode=CursorMode::unsupported;value.bgra.clear();value.xor_mask.clear();value.width=value.height=value.hot_x=value.hot_y=0;value.shape=0;return false;};
    const unsigned visible_height=type==1?height/2:height;
    if(!width || !visible_height || width>cursor_max_side || visible_height>cursor_max_side || hot_x>=width || hot_y>=visible_height ||
        pitch>cursor_max_side*4 || std::uint64_t(pitch)*height!=bytes.size() || (type!=1 && type!=2 && type!=4) || (type==1 && (height%2 || pitch<(width+7)/8)) ||
        (type!=1 && pitch<width*4))return unsupported();
    value.width=width;value.height=visible_height;value.hot_x=hot_x;value.hot_y=hot_y;value.bgra.assign(std::size_t(width)*visible_height*4,0);value.xor_mask.clear();
    if(type==1 || type==4)value.xor_mask.assign(std::size_t(width)*visible_height,0);
    for(unsigned y=0;y<visible_height;++y)for(unsigned x=0;x<width;++x){const auto dest=(std::size_t(y)*width+x)*4;
        if(type==1){const auto mask=128u>>(x%8);const bool a=(bytes.at(std::size_t(y)*pitch+x/8)&mask)!=0,b=(bytes.at(std::size_t(y+visible_height)*pitch+x/8)&mask)!=0;
            if(a && b){value.xor_mask.at(std::size_t(y)*width+x)=1;for(unsigned c=0;c<4;++c)value.bgra.at(dest+c)=255;}
            else if(!a){for(unsigned c=0;c<3;++c)value.bgra.at(dest+c)=b?255:0;value.bgra.at(dest+3)=255;}}
        else {const auto source=std::size_t(y)*pitch+x*4;const unsigned alpha=bytes.at(source+3);
            if(type==4 && alpha!=0 && alpha!=255)return unsupported();const unsigned out_alpha=type==4?255:alpha;
            if(type==4 && alpha==255)value.xor_mask.at(std::size_t(y)*width+x)=1;
            for(unsigned c=0;c<3;++c)value.bgra.at(dest+c)=static_cast<std::uint8_t>(unsigned(bytes.at(source+c))*out_alpha/255);
            value.bgra.at(dest+3)=static_cast<std::uint8_t>(out_alpha);}
    }
    if(std::none_of(value.xor_mask.begin(),value.xor_mask.end(),[](auto bit){return bit!=0;}))value.xor_mask.clear();
    value.mode=CursorMode::separate;return true;
}
CursorUpdate compose_cursor(CursorUpdate value,const Pixels& background,unsigned sw,unsigned sh){
    if(value.xor_mask.empty())return value;
    require(value.mode==CursorMode::separate && sw && sh && sw<=8192 && sh<=8192 &&
        value.width && value.height && value.width<=cursor_max_side && value.height<=cursor_max_side &&
        value.hot_x<value.width && value.hot_y<value.height && value.x>=-8192 && value.y>=-8192 && value.x<=8192 && value.y<=8192 &&
        value.bgra.size()==std::size_t(value.width)*value.height*4 && value.xor_mask.size()==std::size_t(value.width)*value.height &&
        background.width && background.height && background.width<=8192 && background.height<=8192 &&
        std::uint64_t(background.width)*background.height<=16777216 && background.bgra.size()==std::size_t(background.width)*background.height*4);
    for(unsigned y=0;y<value.height;++y)for(unsigned x=0;x<value.width;++x){
        const auto at=(std::size_t(y)*value.width+x)*4;
        if(!value.xor_mask.at(std::size_t(y)*value.width+x))continue;
        const auto sx=std::int64_t(value.x)-value.hot_x+x,sy=std::int64_t(value.y)-value.hot_y+y;
        if(sx<0 || sy<0 || sx>=sw || sy>=sh){for(unsigned c=0;c<4;++c)value.bgra.at(at+c)=0;continue;}
        const auto bx=static_cast<unsigned>(sx*background.width/sw),by=static_cast<unsigned>(sy*background.height/sh);
        for(unsigned c=0;c<3;++c)value.bgra.at(at+c)^=background.bgra.at((std::size_t(by)*background.width+bx)*4+c);
        value.bgra.at(at+3)=255;
    }
    value.xor_mask.clear();return value;
}
CursorUpdate scale_cursor(CursorUpdate value,unsigned sw,unsigned sh,unsigned tw,unsigned th){require(sw && sh && tw && th && sw<=8192 && sh<=8192 && tw<=8192 && th<=8192);
    require(value.xor_mask.empty());
    value.source_width=tw;value.source_height=th;value.x=static_cast<std::int32_t>(std::int64_t(value.x)*tw/sw);value.y=static_cast<std::int32_t>(std::int64_t(value.y)*th/sh);
    if(value.mode!=CursorMode::separate)return value;require(!value.bgra.empty());const auto old=value;
    value.width=std::max(1u,value.width*tw/sw);value.height=std::max(1u,value.height*th/sh);require(value.width<=cursor_max_side && value.height<=cursor_max_side);
    value.hot_x=std::min(value.width-1,value.hot_x*tw/sw);value.hot_y=std::min(value.height-1,value.hot_y*th/sh);value.bgra.resize(std::size_t(value.width)*value.height*4);
    for(unsigned y=0;y<value.height;++y)for(unsigned x=0;x<value.width;++x)for(unsigned c=0;c<4;++c)
        value.bgra.at((std::size_t(y)*value.width+x)*4+c)=old.bgra.at((std::size_t(y*old.height/value.height)*old.width+x*old.width/value.width)*4+c);
    return value;
}
}
