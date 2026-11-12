#pragma once
#include <array>
#include <cstdint>
#include <limits>
#include <span>

namespace remote {
// Diagnostic only: never stores key codes, coordinates, frame IDs or authority.
enum class InputFailure:std::uint32_t {none=0,view_only=1,authority=2,no_frame=3,not_ready=4,backpressure=5,closed=6,invalid=7,expired=8,ack_changed=9,cleanup=10};
inline unsigned input_category(std::span<const std::uint8_t> p){
    if(p.size()!=24 || p[1]>1)return 6;
    if(p[0]==1)return p[1]?0u:1u;
    if(p[0]==2)return p[1]?2u:3u;
    if(p[0]==3)return 4;
    if(p[0]==4)return 5;
    return 6;
}
struct InputDiagnostics {
    std::array<std::uint32_t,64> values{1};
    static void add(std::uint32_t& v){if(v!=(std::numeric_limits<std::uint32_t>::max)())++v;}
    void count(unsigned category,unsigned phase){if(category<6 && phase<4)add(values[4+category*4+phase]);}
    void rejected(unsigned category,InputFailure why,bool discarded=false){
        const auto reason=static_cast<unsigned>(why);
        if(reason==0 || reason>10)return;
        if(discarded)count(category,3);
        values[1]=reason;add(values[2]);values[3]=category<6?category:6;
        add(values[27+reason]);
        // Pointer traffic must not overwrite an unseen click/key-down hint.
        if(category==0 || category==2){values[38]=reason;add(values[39]);values[40]=category;}
    }
};
inline const wchar_t* input_failure_text(InputFailure reason){
    switch(reason){
    case InputFailure::view_only:return L"\u76ee\u524d\u53ea\u6709\u89c0\u770b\u6b0a\u9650\uff0c\u64cd\u4f5c\u672a\u9001\u51fa";
    case InputFailure::authority:return L"\u63a7\u5236\u6388\u6b0a\u5c1a\u672a\u5c31\u7dd2\u6216\u5df2\u5931\u6548\uff0c\u64cd\u4f5c\u672a\u9001\u51fa";
    case InputFailure::no_frame:return L"\u7b49\u5f85\u6709\u6548\u7684\u756b\u9762\u78ba\u8a8d\uff0c\u64cd\u4f5c\u672a\u9001\u51fa";
    case InputFailure::not_ready:return L"\u63a7\u5236\u901a\u9053\u5c1a\u672a\u5c31\u7dd2\uff0c\u64cd\u4f5c\u672a\u9001\u51fa";
    case InputFailure::backpressure:return L"\u63a7\u5236\u901a\u9053\u5fd9\u788c\uff0c\u64cd\u4f5c\u672a\u9001\u51fa";
    case InputFailure::closed:return L"\u63a7\u5236\u901a\u9053\u5df2\u7d50\u675f\uff0c\u64cd\u4f5c\u672a\u9001\u51fa";
    case InputFailure::invalid:return L"\u64cd\u4f5c\u8cc7\u6599\u7121\u6548\uff0c\u64cd\u4f5c\u672a\u9001\u51fa";
    case InputFailure::expired:return L"\u64cd\u4f5c\u50b3\u9001\u7b49\u5f85\u904e\u4e45\uff0c\u5df2\u53d6\u6d88\uff0c\u8acb\u91cd\u65b0\u64cd\u4f5c";
    case InputFailure::ack_changed:return L"\u756b\u9762\u78ba\u8a8d\u5df2\u8b8a\u66f4\uff0c\u64cd\u4f5c\u5df2\u53d6\u6d88";
    case InputFailure::cleanup:return L"\u64cd\u4f5c\u5df2\u96a8\u5b89\u5168\u6e05\u7406\u53d6\u6d88";
    default:return L"";
    }
}
}
