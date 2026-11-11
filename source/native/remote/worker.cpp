// Development entry: owned self-tests only. Desktop adapter is not dispatched.
#include "capture.hpp"
#include "codec.hpp"
#include "render.hpp"
#include "gpu_scale.hpp"
#include "benchmark.hpp"
#include <windows.h>
#include <mfapi.h>
#include <dxgi1_2.h>
#include <d3d11.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace remote {
constexpr std::size_t header_size=40, maximum_payload=65536;
enum class Kind : std::uint16_t { hello=1, capabilities, lease, desktop_state, input, release_all, stop, stats };
struct Message { Kind kind; std::uint64_t session, epoch, sequence; std::vector<std::uint8_t> payload; };
std::uint64_t le(const std::uint8_t* p, unsigned bytes) {
    std::uint64_t value=0;
    for(unsigned i=0;i<bytes;++i) value|=std::uint64_t(p[i])<<(8*i);
    return value;
}
Message parse(const std::vector<std::uint8_t>& wire) {
    if(wire.size()<header_size || std::memcmp(wire.data(),"GDR1",4)!=0 || le(wire.data()+4,2)!=1)
        throw std::invalid_argument("header");
    auto kind=le(wire.data()+6,2), size=le(wire.data()+8,4);
    if(kind<1 || kind>8 || size>maximum_payload || le(wire.data()+12,4)!=0 || wire.size()!=header_size+size)
        throw std::invalid_argument("size_or_kind");
    Message result{static_cast<Kind>(kind),le(wire.data()+16,8),le(wire.data()+24,8),le(wire.data()+32,8),{}};
    if(result.session==0 || result.epoch==0 || result.sequence==0) throw std::invalid_argument("identity");
    result.payload.assign(wire.begin()+header_size,wire.end());
    return result;
}
// A trusted broker provides expiry; this class never accepts client extensions.
class Gate {
    std::uint64_t session_,epoch_,sequence_=0,deadline_;
    bool stopped_=false, acknowledged_=false;
public:
    Gate(std::uint64_t session,std::uint64_t epoch,std::uint64_t now,std::uint64_t duration)
        :session_(session),epoch_(epoch),deadline_(now+(duration<=5000?duration:0)) {}
    void acknowledge(std::uint64_t epoch) { acknowledged_=epoch==epoch_; }
    void switch_epoch() { ++epoch_; acknowledged_=false; sequence_=0; }
    bool accept(const Message& m,std::uint64_t now) {
        if(stopped_ || now>=deadline_ || m.session!=session_ || m.epoch!=epoch_ || m.sequence<=sequence_) return false;
        if(m.kind==Kind::input && !acknowledged_) return false;
        sequence_=m.sequence;
        if(m.kind==Kind::stop) stopped_=true;
        return true;
    }
};
void require(bool value) { if(!value) throw std::runtime_error("self_test"); }
int test() {
    std::vector<std::uint8_t> wire(header_size,0);
    std::memcpy(wire.data(),"GDR1",4); wire[4]=1;wire[6]=5;wire[16]=1;wire[24]=1;wire[32]=1;
    auto input=parse(wire); Gate gate(1,1,100,5000);
    require(!gate.accept(input,101));gate.acknowledge(1);require(gate.accept(input,102));
    require(!gate.accept(input,103));gate.switch_epoch();input.sequence=2;require(!gate.accept(input,104));
    input.epoch=2;require(!gate.accept(input,105));gate.acknowledge(2);require(gate.accept(input,106));
    input.sequence=3;require(!gate.accept(input,5100));
    Gate stop(1,2,100,5000);input.kind=Kind::stop;require(stop.accept(input,101));
    input.sequence=4;require(!stop.accept(input,102));
    unsigned rejected=0;
    for(std::size_t i=0;i<header_size;++i) {
        try { parse(std::vector<std::uint8_t>(wire.begin(),wire.begin()+i)); } catch(const std::invalid_argument&) {++rejected;}
    }
    require(rejected==header_size);
    for(auto offset : {4,6,12,16,24,32}) {
        auto invalid=wire;invalid[static_cast<std::size_t>(offset)]=0;
        if(offset==12) invalid[12]=1;
        try {parse(invalid);throw std::runtime_error("invalid accepted");} catch(const std::invalid_argument&) {}
    }
    wire[8]=1;wire[10]=1;
    try {parse(wire);throw std::runtime_error("oversize accepted");} catch(const std::invalid_argument&) {}
    LARGE_INTEGER freq{},stamp{};require(QueryPerformanceFrequency(&freq)!=FALSE);require(QueryPerformanceCounter(&stamp)!=FALSE);
    // Instantiate only a factory and MF platform; no adapter/output enumeration or desktop pixels.
    IDXGIFactory1* factory=nullptr;
    require(SUCCEEDED(CreateDXGIFactory1(__uuidof(IDXGIFactory1),reinterpret_cast<void**>(&factory))));factory->Release();
    ID3D11Device* device=nullptr;ID3D11DeviceContext* context=nullptr;D3D_FEATURE_LEVEL level{};
    require(SUCCEEDED(D3D11CreateDevice(nullptr,D3D_DRIVER_TYPE_WARP,nullptr,0,nullptr,0,
        D3D11_SDK_VERSION,&device,&level,&context)));
    context->Release();device->Release();
    require(SUCCEEDED(CoInitializeEx(nullptr,COINIT_MULTITHREADED)));
    require(SUCCEEDED(MFStartup(MF_VERSION)));
    const auto encoded_bytes=codec_owned_frames_test();
    require(SUCCEEDED(MFShutdown()));CoUninitialize();
    capture_owned_texture_test();
    render_owned_texture_test();
    scale_owned_texture_test();
    std::cout<<"{\"passed\":true,\"truncated_headers_rejected\":"<<rejected<<",\"desktop_capture\":false,\"os_input\":false,\"dxgi_factory\":true,\"mf_platform\":true,\"owned_h264_bytes\":"<<encoded_bytes<<"}\n";
    return 0;
}
}
int main(int argc,char** argv) {
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    if(argc!=2) {std::cerr<<"Worker integration unavailable; owned tests only\n";return 2;}
    try {
        if(std::strcmp(argv[1],"--self-test")==0) return remote::test();
        if(std::strcmp(argv[1],"--synthetic-benchmark")==0) return remote::synthetic_benchmark();
        return 2;
    } catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}
}
