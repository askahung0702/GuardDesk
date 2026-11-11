#include "codec.hpp"
#include <mfapi.h>
#include <mferror.h>
#include <codecapi.h>
#include <wmcodecdsp.h>
#include <cstring>
#include <cstdio>
#include <stdexcept>

namespace remote {
using Microsoft::WRL::ComPtr;
namespace {
// MF Lock() supplies one pointer and an explicit byte length. Centralize and
// check every row offset before crossing that Win32 pointer boundary.
BYTE* checked_bytes(BYTE* base,std::size_t length,std::size_t offset,std::size_t count) {
    if(!base || offset>length || count>length-offset) throw std::runtime_error("codec_buffer_range");
#if defined(__clang__)
#pragma clang unsafe_buffer_usage begin
#endif
    return base+offset;
#if defined(__clang__)
#pragma clang unsafe_buffer_usage end
#endif
}
struct CodecFailure:std::runtime_error {
    HRESULT result;unsigned line;
    CodecFailure(HRESULT value,unsigned location,const char* message):std::runtime_error(message),result(value),line(location){}
};
void check_result(HRESULT result,unsigned line) {
    if(FAILED(result)) {
        char message[96]{};
        sprintf_s(message,"native_codec_hresult_%08lx_line_%u",static_cast<unsigned long>(result),line);
        throw CodecFailure(result,line,message);
    }
}
#define check(value) check_result((value),__LINE__)
void dimensions(IMFMediaType* type,unsigned width,unsigned height,unsigned fps) {
    check(type->SetGUID(MF_MT_MAJOR_TYPE,MFMediaType_Video));
    check(MFSetAttributeSize(type,MF_MT_FRAME_SIZE,width,height));
    check(MFSetAttributeRatio(type,MF_MT_FRAME_RATE,fps,1));
    check(MFSetAttributeRatio(type,MF_MT_PIXEL_ASPECT_RATIO,1,1));
    check(type->SetUINT32(MF_MT_INTERLACE_MODE,MFVideoInterlace_Progressive));
}
void check_display(IMFMediaType* type,unsigned width,unsigned height,unsigned expected_width,unsigned expected_height) {
    if(width==expected_width && height==expected_height) return;
    if(width!=(expected_width+15)/16*16 || height!=(expected_height+15)/16*16)
        throw std::runtime_error("decoder_resolution_change_requires_reset");
    MFVideoArea area{};UINT32 length=0;
    HRESULT result=type->GetBlob(MF_MT_MINIMUM_DISPLAY_APERTURE,reinterpret_cast<UINT8*>(&area),sizeof(area),&length);
    if(FAILED(result)) result=type->GetBlob(MF_MT_GEOMETRIC_APERTURE,reinterpret_cast<UINT8*>(&area),sizeof(area),&length);
    check(result);
    if(length!=sizeof(area) || area.OffsetX.value!=0 || area.OffsetX.fract!=0 ||
        area.OffsetY.value!=0 || area.OffsetY.fract!=0 || area.Area.cx!=static_cast<LONG>(expected_width) ||
        area.Area.cy!=static_cast<LONG>(expected_height)) throw std::runtime_error("decoder_crop_not_verified");
}
}

H264Encoder::H264Encoder(unsigned width,unsigned height,unsigned fps,unsigned bitrate,EncoderPreference preference)
    :width_(width),height_(height),fps_(fps),bitrate_(bitrate) {
    if(width==0 || height==0 || (width%2) || (height%2) || width>4096 || height>4096 ||
        std::uint64_t(width)*height>8847360 || fps<1 || fps>60 || bitrate<64000 || bitrate>50000000)
        throw std::invalid_argument("encoder_configuration");
    if(preference==EncoderPreference::prefer_hardware && hardware())return;
    software();
}
void H264Encoder::shutdown_hardware(){
    events_.Reset();transform_.Reset();
    if(activation_){activation_->ShutdownObject();activation_.Reset();}
    manager_.Reset();device_.Reset();
}
H264Encoder::~H264Encoder(){shutdown_hardware();}
void H264Encoder::software(){
    shutdown_hardware();
    events_.Reset();manager_.Reset();device_.Reset();transform_.Reset();asynchronous_=need_input_=have_output_=false;
    selection_.hardware_active=false;
    check(CoCreateInstance(CLSID_CMSH264EncoderMFT,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&transform_)));
    configure();
}
void H264Encoder::configure(){
    ComPtr<ICodecAPI> api;check(transform_.As(&api));
    VARIANT low{};low.vt=VT_BOOL;low.boolVal=VARIANT_TRUE;
    check(api->SetValue(&CODECAPI_AVLowLatencyMode,&low));
    VARIANT mode{};mode.vt=VT_UI4;mode.ulVal=eAVEncCommonRateControlMode_CBR;
    check(api->SetValue(&CODECAPI_AVEncCommonRateControlMode,&mode));
    ComPtr<IMFMediaType> out,in;check(MFCreateMediaType(&out));
    dimensions(out.Get(),width_,height_,fps_);
    check(out->SetGUID(MF_MT_SUBTYPE,MFVideoFormat_H264));
    check(out->SetUINT32(MF_MT_AVG_BITRATE,bitrate_));
    check(out->SetUINT32(MF_MT_MPEG2_PROFILE,eAVEncH264VProfile_Base));
    check(transform_->SetOutputType(0,out.Get(),0));
    check(MFCreateMediaType(&in));dimensions(in.Get(),width_,height_,fps_);
    check(in->SetGUID(MF_MT_SUBTYPE,MFVideoFormat_NV12));
    check(transform_->SetInputType(0,in.Get(),0));
    check(transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,0));
    check(transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM,0));
}

bool H264Encoder::hardware(){
    MFT_REGISTER_TYPE_INFO input{MFMediaType_Video,MFVideoFormat_NV12},output{MFMediaType_Video,MFVideoFormat_H264};
    IMFActivate** raw=nullptr;UINT32 count=0;
    const auto result=MFTEnumEx(MFT_CATEGORY_VIDEO_ENCODER,MFT_ENUM_FLAG_HARDWARE|MFT_ENUM_FLAG_SORTANDFILTER,&input,&output,&raw,&count);
    struct Activations {IMFActivate** values;UINT32 count;~Activations(){
        if(!values)return;
        for(UINT32 i=0;i<count;++i){
#if defined(__clang__)
#pragma clang unsafe_buffer_usage begin
#endif
            if(values[i])values[i]->Release();
#if defined(__clang__)
#pragma clang unsafe_buffer_usage end
#endif
        }CoTaskMemFree(values);}} cleanup{raw,count};
    selection_.candidates=count;
    if(FAILED(result) || !raw || !count){selection_.fallback=1;return false;}
    if(count>64){selection_.fallback=2;return false;}
    for(UINT32 i=0;i<std::min(count,4u);++i){
        ++selection_.attempted;shutdown_hardware();
        asynchronous_=need_input_=have_output_=false;
        try {
#if defined(__clang__)
#pragma clang unsafe_buffer_usage begin
#endif
            // MFTEnumEx returned count verified pointers; i < min(count,4).
            activation_=raw[i];
            check(activation_->ActivateObject(IID_PPV_ARGS(&transform_)));
#if defined(__clang__)
#pragma clang unsafe_buffer_usage end
#endif
            ComPtr<IMFAttributes> attributes;check(transform_->GetAttributes(&attributes));UINT32 async=0,aware=0;
            if(SUCCEEDED(attributes->GetUINT32(MF_TRANSFORM_ASYNC,&async)) && async){
                check(attributes->SetUINT32(MF_TRANSFORM_ASYNC_UNLOCK,TRUE));check(transform_.As(&events_));asynchronous_=true;
            }
            if(SUCCEEDED(attributes->GetUINT32(MF_SA_D3D11_AWARE,&aware)) && aware){
                check(D3D11CreateDevice(nullptr,D3D_DRIVER_TYPE_HARDWARE,nullptr,D3D11_CREATE_DEVICE_VIDEO_SUPPORT|D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                    nullptr,0,D3D11_SDK_VERSION,&device_,nullptr,nullptr));
                UINT reset=0;check(MFCreateDXGIDeviceManager(&reset,&manager_));check(manager_->ResetDevice(device_.Get(),reset));
                check(transform_->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER,reinterpret_cast<ULONG_PTR>(manager_.Get())));
            }
            configure();selection_.hardware_active=true;selection_.fallback=0;return true;
        }catch(const CodecFailure& error){selection_.fallback=2;selection_.rejected_hresult=static_cast<std::uint32_t>(error.result);selection_.rejected_line=error.line;}
        catch(const std::exception&){selection_.fallback=2;}
    }
    return false;
}
bool H264Encoder::event(bool input,std::uint64_t deadline){
    if(!events_)return false;
    unsigned events=0;
    while(GetTickCount64()<deadline && events<128){
        if(input?need_input_:have_output_)return true;
        ComPtr<IMFMediaEvent> value;const auto result=events_->GetEvent(MF_EVENT_FLAG_NO_WAIT,&value);
        if(result==MF_E_NO_EVENTS_AVAILABLE){Sleep(1);continue;}
        check(result);++events;MediaEventType type{};HRESULT status{};check(value->GetType(&type));check(value->GetStatus(&status));check(status);
        if(type==METransformNeedInput)need_input_=true;
        else if(type==METransformHaveOutput)have_output_=true;
        else if(type==MEError)throw std::runtime_error("hardware_transform_error");
    }
    return false;
}

std::vector<std::uint8_t> H264Encoder::output() {
    if(asynchronous_ && !event(false,GetTickCount64()+200))throw std::runtime_error("hardware_output_deadline");
    have_output_=false;
    MFT_OUTPUT_STREAM_INFO info{};check(transform_->GetOutputStreamInfo(0,&info));
    const DWORD capacity=info.cbSize>0?info.cbSize:width_*height_*3/2;
    if(capacity>16*1024*1024) throw std::runtime_error("encoder_output_bound");
    ComPtr<IMFSample> sample;ComPtr<IMFMediaBuffer> buffer;
    if(!(info.dwFlags&MFT_OUTPUT_STREAM_PROVIDES_SAMPLES)) {
        check(MFCreateSample(&sample));check(MFCreateMemoryBuffer(capacity,&buffer));
        check(sample->AddBuffer(buffer.Get()));
    }
    MFT_OUTPUT_DATA_BUFFER data{};data.pSample=sample.Get();DWORD status=0;
    const HRESULT result=transform_->ProcessOutput(0,1,&data,&status);
    ComPtr<IMFCollection> events;events.Attach(data.pEvents);
    if(!sample && data.pSample) sample.Attach(data.pSample);
    if(result==MF_E_TRANSFORM_NEED_MORE_INPUT) return {};
    check(result);
    if(!sample) throw std::runtime_error("encoder_output_missing");
    check(sample->ConvertToContiguousBuffer(&buffer));
    BYTE* bytes=nullptr;DWORD length=0;check(buffer->Lock(&bytes,nullptr,&length));
    struct Unlock {IMFMediaBuffer* buffer;~Unlock(){buffer->Unlock();}} unlock{buffer.Get()};
    if(length>16*1024*1024) throw std::runtime_error("encoded_packet_bound");
    if(length==0)return {};
    std::vector<std::uint8_t> packet(length);std::memcpy(packet.data(),bytes,length);return packet;
}

std::vector<std::uint8_t> H264Encoder::encode(const std::vector<std::uint8_t>& nv12,bool keyframe) {
    if(nv12.size()!=std::size_t(width_)*height_*3/2)throw std::invalid_argument("nv12_size");
    try {auto result=encode_once(nv12,keyframe);
        if(selection_.hardware_active){if(result.empty())throw std::runtime_error("hardware_empty_output");
            const auto prefix=result.size()>=4 && ((result.at(0)==0 && result.at(1)==0 && result.at(2)==1) ||
                (result.at(0)==0 && result.at(1)==0 && result.at(2)==0 && result.at(3)==1));
            if(!prefix)throw std::runtime_error("hardware_annexb_unavailable");++selection_.hardware_frames;}
        return result;
    }catch(const std::exception&){
        if(!selection_.hardware_active)throw;
        selection_.fallback=3;software();return encode_once(nv12,true);
    }
}
std::vector<std::uint8_t> H264Encoder::encode_once(const std::vector<std::uint8_t>& nv12,bool keyframe) {
    if(asynchronous_ && !event(true,GetTickCount64()+200))throw std::runtime_error("hardware_input_deadline");
    need_input_=false;
    const std::size_t expected=std::size_t(width_)*height_*3/2;
    if(nv12.size()!=expected) throw std::invalid_argument("nv12_size");
    if(keyframe) {
        ComPtr<ICodecAPI> api;check(transform_.As(&api));
        VARIANT force{};force.vt=VT_UI4;force.ulVal=1;
        check(api->SetValue(&CODECAPI_AVEncVideoForceKeyFrame,&force));
    }
    ComPtr<IMFSample> sample;ComPtr<IMFMediaBuffer> buffer;
    check(MFCreateSample(&sample));check(MFCreateMemoryBuffer(static_cast<DWORD>(expected),&buffer));
    BYTE* bytes=nullptr;check(buffer->Lock(&bytes,nullptr,nullptr));
    std::memcpy(bytes,nv12.data(),expected);check(buffer->Unlock());
    check(buffer->SetCurrentLength(static_cast<DWORD>(expected)));check(sample->AddBuffer(buffer.Get()));
    check(sample->SetSampleTime(static_cast<LONGLONG>(frame_*10000000/fps_)));
    check(sample->SetSampleDuration(10000000/fps_));
    check(transform_->ProcessInput(0,sample.Get(),0));++frame_;
    return output();
}

std::vector<std::uint8_t> H264Encoder::drain() {
    if(asynchronous_)return {}; // Every accepted low-latency frame already produced output.
    check(transform_->ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN,0));
    return output();
}

H264Decoder::H264Decoder(unsigned width,unsigned height):width_(width),height_(height) {
    if(width==0 || height==0 || width%2 || height%2 || width>4096 || height>4096 ||
        std::uint64_t(width)*height>8847360) throw std::invalid_argument("decoder_dimensions");
    check(CoCreateInstance(CLSID_CMSH264DecoderMFT,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&transform_)));
    // Decoder low latency is an IMFAttributes UINT32 (the ICodecAPI property
    // subset differs from the encoder and rejects this bool on this system).
    ComPtr<IMFAttributes> attributes;check(transform_->GetAttributes(&attributes));
    check(attributes->SetUINT32(CODECAPI_AVLowLatencyMode,1));
    check(attributes->SetUINT32(CODECAPI_AVDecVideoMaxCodedWidth,(width+15)/16*16));
    check(attributes->SetUINT32(CODECAPI_AVDecVideoMaxCodedHeight,(height+15)/16*16));
    ComPtr<IMFMediaType> in,out;check(MFCreateMediaType(&in));
    dimensions(in.Get(),width,height,30);check(in->SetGUID(MF_MT_SUBTYPE,MFVideoFormat_H264));
    check(transform_->SetInputType(0,in.Get(),0));
    check(MFCreateMediaType(&out));dimensions(out.Get(),width,height,30);
    check(out->SetGUID(MF_MT_SUBTYPE,MFVideoFormat_NV12));
    check(transform_->SetOutputType(0,out.Get(),0));
    check(transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,0));
    check(transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM,0));
}

std::vector<std::uint8_t> H264Decoder::decode(const std::vector<std::uint8_t>& packet) {
    if(packet.empty() || packet.size()>16*1024*1024) throw std::invalid_argument("h264_packet_bound");
    ComPtr<IMFSample> in;ComPtr<IMFMediaBuffer> input;
    check(MFCreateSample(&in));check(MFCreateMemoryBuffer(static_cast<DWORD>(packet.size()),&input));
    BYTE* bytes=nullptr;check(input->Lock(&bytes,nullptr,nullptr));
    std::memcpy(bytes,packet.data(),packet.size());check(input->Unlock());
    check(input->SetCurrentLength(static_cast<DWORD>(packet.size())));check(in->AddBuffer(input.Get()));
    check(in->SetSampleTime(static_cast<LONGLONG>(frame_++*10000000/30)));
    check(in->SetSampleDuration(10000000/30));check(transform_->ProcessInput(0,in.Get(),0));
    // A stream change is negotiated once per bounded packet. Dimensions from
    // encoded input never silently expand the caller's configured allocation.
    for(unsigned attempt=0;attempt<2;++attempt) {
        MFT_OUTPUT_STREAM_INFO info{};check(transform_->GetOutputStreamInfo(0,&info));
        if(info.cbSize>64*1024*1024) throw std::runtime_error("decoder_output_bound");
        ComPtr<IMFSample> sample;ComPtr<IMFMediaBuffer> buffer;
        if(!(info.dwFlags&MFT_OUTPUT_STREAM_PROVIDES_SAMPLES)) {
            check(MFCreateSample(&sample));
            check(MFCreateMemoryBuffer(info.cbSize>0?info.cbSize:width_*height_*3/2,&buffer));
            check(sample->AddBuffer(buffer.Get()));
        }
        MFT_OUTPUT_DATA_BUFFER out{};out.pSample=sample.Get();DWORD status=0;
        const HRESULT result=transform_->ProcessOutput(0,1,&out,&status);
        ComPtr<IMFCollection> events;events.Attach(out.pEvents);
        if(!sample && out.pSample) sample.Attach(out.pSample);
        if(result==MF_E_TRANSFORM_NEED_MORE_INPUT) return {};
        if(result==MF_E_TRANSFORM_STREAM_CHANGE) {
            ComPtr<IMFMediaType> type;
            bool selected=false;
            for(DWORD i=0;i<16;++i) {
                const HRESULT available=transform_->GetOutputAvailableType(0,i,&type);
                if(available==MF_E_NO_MORE_TYPES) break;
                check(available);GUID subtype{};check(type->GetGUID(MF_MT_SUBTYPE,&subtype));
                UINT32 width=0,height=0;check(MFGetAttributeSize(type.Get(),MF_MT_FRAME_SIZE,&width,&height));
                check_display(type.Get(),width,height,width_,height_);
                if(subtype==MFVideoFormat_NV12) {check(transform_->SetOutputType(0,type.Get(),0));selected=true;break;}
            }
            if(!selected) throw std::runtime_error("decoder_nv12_unavailable");
            continue;
        }
        check(result);
        if(!sample) throw std::runtime_error("decoder_output_missing");
        check(sample->ConvertToContiguousBuffer(&buffer));
        ComPtr<IMFMediaType> type;check(transform_->GetOutputCurrentType(0,&type));
        UINT32 width=0,height=0,stride=0;
        check(MFGetAttributeSize(type.Get(),MF_MT_FRAME_SIZE,&width,&height));
        check_display(type.Get(),width,height,width_,height_);
        if(FAILED(type->GetUINT32(MF_MT_DEFAULT_STRIDE,&stride))) stride=width;
        if(stride<width || stride>8192) throw std::runtime_error("decoder_stride");
        DWORD length=0;check(buffer->GetCurrentLength(&length));
        if(length>64*1024*1024 || length<std::uint64_t(stride)*height*3/2) throw std::runtime_error("decoder_nv12_bound");
        check(buffer->Lock(&bytes,nullptr,&length));
        struct Unlock {IMFMediaBuffer* buffer;~Unlock(){buffer->Unlock();}} unlock{buffer.Get()};
        std::vector<std::uint8_t> cropped(std::size_t(width_)*height_*3/2);
        for(unsigned row=0;row<height_;++row) std::memcpy(
            checked_bytes(cropped.data(),cropped.size(),std::size_t(row)*width_,width_),
            checked_bytes(bytes,length,std::size_t(row)*stride,width_),width_);
        for(unsigned row=0;row<height_/2;++row) std::memcpy(
            checked_bytes(cropped.data(),cropped.size(),std::size_t(width_)*height_+std::size_t(row)*width_,width_),
            checked_bytes(bytes,length,std::size_t(stride)*height+std::size_t(row)*stride,width_),width_);
        return cropped;
    }
    throw std::runtime_error("decoder_stream_change_loop");
}

std::size_t codec_owned_frames_test() {
    H264Encoder encoder(320,180,30,1000000);
    H264Decoder decoder(320,180);
    std::vector<std::uint8_t> nv12(320*180*3/2,128);
    std::size_t total=0,decoded=0;
    for(unsigned i=0;i<12;++i) {
        std::memset(nv12.data(),16+static_cast<int>(i)*8,320*180);
        const auto packet=encoder.encode(nv12,i==0);total+=packet.size();
        if(!packet.empty()) {
            const auto image=decoder.decode(packet);
            if(!image.empty()) {
                if(image.size()!=nv12.size())throw std::runtime_error("owned_decoder_size");
                // Coded height is 192 while display height is 180. Reading UV
                // from the display-height offset would instead read padding.
                for(const auto at:{std::size_t(320*180),std::size_t(320*180+1),image.size()-2,image.size()-1})
                    if(image[at]<120 || image[at]>136)throw std::runtime_error("owned_decoder_chroma_crop");
                ++decoded;
            }
        }
    }
    total+=encoder.drain().size();
    if(total==0 || total>2*1024*1024 || decoded==0) throw std::runtime_error("owned_encoder_decoder_output");
    return total;
}
}
