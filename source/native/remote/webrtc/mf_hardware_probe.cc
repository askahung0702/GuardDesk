// Real synthetic encode/decode, never infer hardware success from enumeration.
#include "codec.hpp"
#include <mfapi.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>
namespace {
remote::EncoderSelection run(remote::EncoderPreference preference){
    remote::H264Encoder encoder(320,180,30,1000000,preference);remote::H264Decoder decoder(320,180);
    std::vector<std::uint8_t> frame(320*180*3/2,128);unsigned decoded=0;
    for(unsigned i=0;i<8;++i){std::fill_n(frame.begin(),320*180,static_cast<std::uint8_t>(60+i*12));
        const auto packet=encoder.encode(frame,i==0);
        if(!packet.empty()){const auto image=decoder.decode(packet);if(image.size()!=frame.size())throw std::runtime_error("owned_hardware_decode_size");++decoded;}}
    if(decoded!=8)throw std::runtime_error("owned_hardware_decode_count");return encoder.selection();
}
}
int main(){if(FAILED(CoInitializeEx(nullptr,COINIT_MULTITHREADED)))return 2;if(FAILED(MFStartup(MF_VERSION))){CoUninitialize();return 3;}
    int result=0;try{auto software=run(remote::EncoderPreference::software_only);auto selected=run(remote::EncoderPreference::prefer_hardware);
        if(software.hardware_active || software.hardware_frames || selected.attempted>4 || (selected.hardware_active && selected.hardware_frames!=8))throw std::runtime_error("owned_hardware_policy");
        std::cout<<"{\"passed\":true,\"software_baseline_decoded\":8,\"preferred_path_decoded\":8,\"hardware_candidates\":"<<selected.candidates
            <<",\"hardware_attempted\":"<<selected.attempted<<",\"hardware_frames\":"<<selected.hardware_frames<<",\"hardware_active\":"<<(selected.hardware_active?"true":"false")
            <<",\"fallback_reason\":"<<selected.fallback<<",\"rejected_hresult\":"<<selected.rejected_hresult<<",\"rejected_source_line\":"<<selected.rejected_line
            <<",\"driver_hard_deadline_claimed\":false,\"desktop_capture\":false,\"os_input\":false}\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<"\n";result=1;}MFShutdown();CoUninitialize();return result;}
