#pragma once
#include <windows.h>
#include <mftransform.h>
#include <mfidl.h>
#include <d3d11.h>
#include <wrl/client.h>
#include <cstdint>
#include <vector>

namespace remote {
enum class EncoderPreference {software_only,prefer_hardware};
struct EncoderSelection {
    unsigned candidates=0,attempted=0,hardware_frames=0;
    bool hardware_active=false;
    // 0 software requested / hardware active, 1 no candidates, 2 configuration
    // rejected, 3 hardware runtime/output timeout. Scalar only, no device URL.
    unsigned fallback=0;
    std::uint32_t rejected_hresult=0;
    unsigned rejected_line=0;
};
// At most four registered MF hardware candidates, then one explicit Microsoft
// software fallback. Async event waits are bounded; driver COM calls themselves
// are cooperative and are not claimed to be forcibly interruptible.
class H264Encoder {
    Microsoft::WRL::ComPtr<IMFTransform> transform_;
    Microsoft::WRL::ComPtr<IMFActivate> activation_;
    void shutdown_hardware();
    unsigned width_,height_,fps_;
    unsigned bitrate_;
    std::uint64_t frame_=0;
    std::int64_t origin_us_=0,last_sample_time_=-1,capture_us_=0;
    EncoderSelection selection_;
    bool asynchronous_=false,need_input_=false,have_output_=false;
    Microsoft::WRL::ComPtr<IMFMediaEventGenerator> events_;
    Microsoft::WRL::ComPtr<IMFDXGIDeviceManager> manager_;
    Microsoft::WRL::ComPtr<ID3D11Device> device_;
    void configure();
    void software();
    bool hardware();
    bool event(bool input,std::uint64_t deadline);
    std::vector<std::uint8_t> encode_once(const std::vector<std::uint8_t>& nv12,bool keyframe);
    std::vector<std::uint8_t> output();
public:
    H264Encoder(unsigned width,unsigned height,unsigned fps,unsigned bitrate,EncoderPreference preference=EncoderPreference::software_only);
    ~H264Encoder();
    std::vector<std::uint8_t> encode(const std::vector<std::uint8_t>& nv12,bool keyframe=false,std::int64_t capture_us=0);
    bool set_bitrate(unsigned bitrate); // Owner MTA only; false requests bounded caller fallback.
    std::vector<std::uint8_t> drain();
    EncoderSelection selection() const{return selection_;}
};
class H264Decoder {
    Microsoft::WRL::ComPtr<IMFTransform> transform_;
    unsigned width_,height_;
    std::uint64_t frame_=0;
public:
    H264Decoder(unsigned width,unsigned height);
    std::vector<std::uint8_t> decode(const std::vector<std::uint8_t>& packet);
};
std::size_t codec_owned_frames_test();
}
