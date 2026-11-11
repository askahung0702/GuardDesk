#include "frame_pool.hpp"
#include "ipc_peer.hpp"
#include <sddl.h>
#include <cstring>
#include <stdexcept>
#include <span>

namespace remote {
namespace {
constexpr std::size_t header_bytes=128,maximum_pixels=16777216;
struct alignas(8) CursorMetadata {std::uint64_t revision=0,tick=0;std::uint32_t bytes=0,reserved=0;std::uint64_t reserved2=0;};
static_assert(sizeof(CursorMetadata)==32);
struct alignas(8) Metadata{
    std::uint32_t magic=0x32464447,format=2;
    ipc::Session session{};
    std::uint64_t sequence=0,generation=0,tick=0;
    std::uint32_t width=0,height=0,bytes=0,slot=0;
    std::array<std::uint8_t,64> reserved{};
};
static_assert(sizeof(Metadata)==header_bytes);
void require(bool okay,const char* reason){if(!okay)throw std::runtime_error(reason);}
std::size_t pixel_bytes(unsigned width,unsigned height){
    require(width>0 && height>0 && width<=8192 && height<=8192 && std::uint64_t(width)*height<=maximum_pixels,"frame_dimensions");
    return std::size_t(width)*height*4;
}
void invalidate(void* view,std::size_t capacity){
    auto* metadata=static_cast<Metadata*>(view);
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&metadata->sequence),0);
    auto bytes=std::span<std::uint8_t>(static_cast<std::uint8_t*>(view),header_bytes+capacity+cursor_storage_bytes);
    auto cursor=bytes.subspan(header_bytes+capacity,cursor_storage_bytes);
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&cursor.front()),0);
    MemoryBarrier();SecureZeroMemory(bytes.subspan(header_bytes,capacity).data(),capacity);
    SecureZeroMemory(cursor.subspan(sizeof(std::uint64_t)).data(),cursor_storage_bytes-sizeof(std::uint64_t));
    metadata->generation=metadata->tick=0;metadata->width=metadata->height=metadata->bytes=0;
}
}
std::size_t FramePool::shared_mapping_bytes(unsigned width,unsigned height){return header_bytes+pixel_bytes(width,height)+cursor_storage_bytes;}
FramePool::FramePool(ipc::Session session,unsigned width,unsigned height):session_(session),capacity_(pixel_bytes(width,height)){
    bool nonzero=false;for(auto value:session)nonzero|=value!=0;require(nonzero,"frame_session");
    ipc::Peer self(GetCurrentProcessId());
    const auto sddl=L"O:"+self.identity().sid+L"D:P(A;;GA;;;SY)(A;;GA;;;"+self.identity().sid+L")(A;;RC;;;OW)";
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr)!=FALSE,"frame_security");
    SECURITY_ATTRIBUTES security{sizeof(security),descriptor,FALSE};
    try{
        for(auto& slot:slots_){
            slot.mapping=CreateFileMappingW(INVALID_HANDLE_VALUE,&security,PAGE_READWRITE,0,static_cast<DWORD>(mapping_bytes()),nullptr);
            require(slot.mapping!=nullptr,"frame_mapping_create");
            slot.view=MapViewOfFile(slot.mapping,FILE_MAP_WRITE|FILE_MAP_READ,0,0,mapping_bytes());
            require(slot.view!=nullptr,"frame_mapping_write_view");
            Metadata metadata;metadata.session=session_;std::memcpy(slot.view,&metadata,sizeof(metadata));
        }
        LocalFree(descriptor);
    }catch(...){
        LocalFree(descriptor);for(auto& slot:slots_){if(slot.view)UnmapViewOfFile(slot.view);if(slot.mapping)CloseHandle(slot.mapping);}throw;
    }
}
FramePool::~FramePool(){clear();for(auto& slot:slots_){UnmapViewOfFile(slot.view);CloseHandle(slot.mapping);}}
FramePool::FramePool(ipc::Session session,unsigned width,unsigned height,std::array<HANDLE,2> handles)
    :session_(session),capacity_(pixel_bytes(width,height)){
    for(unsigned i=0;i<slots_.size();++i)slots_.at(i).mapping=handles.at(i);
    try{
        require(handles.at(0) && handles.at(1) && handles.at(0)!=handles.at(1),"frame_adopt_handles");
        for(auto& slot:slots_){
            slot.view=MapViewOfFile(slot.mapping,FILE_MAP_WRITE|FILE_MAP_READ,0,0,mapping_bytes());
            require(slot.view!=nullptr,"frame_adopt_view");
            Metadata existing{};std::memcpy(&existing,slot.view,sizeof(existing));
            require(existing.magic==0x32464447 && existing.format==2 && existing.session==session_ && existing.sequence==0,"frame_adopt_identity");
        }
    }catch(...){for(auto& slot:slots_){if(slot.view)UnmapViewOfFile(slot.view);if(slot.mapping)CloseHandle(slot.mapping);}throw;}
}
bool FramePool::publish(const Pixels& pixels,std::uint64_t generation,std::uint64_t sequence,std::uint64_t tick,FrameTicket& result){
    const auto bytes=pixel_bytes(pixels.width,pixels.height);
    if(!generation || !sequence || !tick || bytes>capacity_ || pixels.bgra.size()!=bytes)return false;
    std::lock_guard<std::mutex> lock(mutex_);
    if(sequence<=last_sequence_)return false;
    for(unsigned index=0;index<slots_.size();++index){auto& slot=slots_.at(index);
        if(slot.busy){
            // The producer owns this clock and both write mappings. A delayed
            // ICE/encoder consumer cannot keep expired pixels pinned forever.
            // Reuse only after the same 1s freshness limit as the reader/ACK
            // gate. Invalidate first; concurrent readers recheck the complete
            // metadata and discard reuse races. Late consumed messages still
            // require the exact old generation/sequence and cannot free this
            // new frame. Reclamation never supplies a displayed-frame ACK.
            if(tick<slot.ticket.tick || tick-slot.ticket.tick<=1000)continue;
            InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&static_cast<Metadata*>(slot.view)->sequence),0);
            MemoryBarrier();slot.busy=false;
        }
        Metadata metadata;metadata.session=session_;metadata.generation=generation;metadata.tick=tick;
        metadata.width=pixels.width;metadata.height=pixels.height;metadata.bytes=static_cast<unsigned>(bytes);metadata.slot=index;
        std::memcpy(slot.view,&metadata,sizeof(metadata));
        auto mapped=std::span<std::uint8_t>(static_cast<std::uint8_t*>(slot.view),mapping_bytes());
        std::memcpy(mapped.subspan(header_bytes,bytes).data(),pixels.bgra.data(),bytes);
        MemoryBarrier();InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&static_cast<Metadata*>(slot.view)->sequence),static_cast<LONG64>(sequence));
        slot.ticket={session_,generation,sequence,tick,index,pixels.width,pixels.height};slot.busy=true;last_sequence_=sequence;result=slot.ticket;return true;
    }
    return false; // Drop; never allocate a third slot or queue old images.
}
bool FramePool::release(const FrameTicket& ticket){
    std::lock_guard<std::mutex> lock(mutex_);if(ticket.slot>=slots_.size())return false;
    auto& slot=slots_.at(ticket.slot);
    if(!slot.busy || ticket.session!=session_ || ticket.sequence!=slot.ticket.sequence || ticket.generation!=slot.ticket.generation)return false;
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&static_cast<Metadata*>(slot.view)->sequence),0);
    slot.busy=false;return true;
}
void FramePool::clear(){
    std::lock_guard<std::mutex> lock(mutex_);for(auto& slot:slots_)if(slot.view){invalidate(slot.view,capacity_);slot.busy=false;slot.ticket={};}
}
bool FramePool::release_sequence(std::uint64_t generation,std::uint64_t sequence){
    std::lock_guard<std::mutex> lock(mutex_);
    for(auto& slot:slots_)if(slot.busy && slot.ticket.generation==generation && slot.ticket.sequence==sequence){
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&static_cast<Metadata*>(slot.view)->sequence),0);slot.busy=false;return true;
    }
    return false;
}
HANDLE FramePool::duplicate_read(unsigned index,HANDLE target) const{
    require(index<slots_.size() && target!=nullptr,"frame_target");HANDLE duplicate=nullptr;
    require(DuplicateHandle(GetCurrentProcess(),slots_.at(index).mapping,target,&duplicate,FILE_MAP_READ,FALSE,0)!=FALSE,"frame_read_duplicate");return duplicate;
}
HANDLE FramePool::duplicate_write(unsigned index,HANDLE target) const{
    require(index<slots_.size() && target!=nullptr,"frame_writer_target");HANDLE duplicate=nullptr;
    require(DuplicateHandle(GetCurrentProcess(),slots_.at(index).mapping,target,&duplicate,FILE_MAP_READ|FILE_MAP_WRITE,FALSE,0)!=FALSE,"frame_write_duplicate");return duplicate;
}
SharedFrame read_shared_frame(HANDLE mapping,std::size_t mapping_bytes,const ipc::Session& session,std::uint64_t generation,std::uint64_t now){
    require(mapping_bytes>header_bytes+cursor_storage_bytes && mapping_bytes<=header_bytes+maximum_pixels*4+cursor_storage_bytes+cursor_storage_bytes && generation>0,"frame_mapping_bound");
    const void* view=MapViewOfFile(mapping,FILE_MAP_READ,0,0,mapping_bytes);require(view!=nullptr,"frame_read_view");
    struct Unmap{const void* view;~Unmap(){UnmapViewOfFile(view);}} unmap{view};
    Metadata metadata{};std::memcpy(&metadata,view,sizeof(metadata));MemoryBarrier();
    Metadata sampled{};std::memcpy(&sampled,view,sizeof(sampled));
    if(std::memcmp(&sampled,&metadata,sizeof(metadata))!=0 || !metadata.sequence || metadata.generation<generation || metadata.tick>now || now-metadata.tick>1000)throw FrameRetry();
    require(metadata.magic==0x32464447 && metadata.format==2 && metadata.session==session && metadata.generation && metadata.slot<2,"frame_metadata");
    for(auto value:metadata.reserved)require(value==0,"frame_reserved");
    const auto count=pixel_bytes(metadata.width,metadata.height);
    require(metadata.bytes==count && count<=mapping_bytes-header_bytes-cursor_storage_bytes,"frame_length");
    SharedFrame result{{session,metadata.generation,metadata.sequence,metadata.tick,metadata.slot,metadata.width,metadata.height},
        {metadata.width,metadata.height,std::vector<std::uint8_t>(count)}};
    auto mapped=std::span<const std::uint8_t>(static_cast<const std::uint8_t*>(view),mapping_bytes);
    std::memcpy(result.pixels.bgra.data(),mapped.subspan(header_bytes,count).data(),count);MemoryBarrier();
    Metadata after{};std::memcpy(&after,view,sizeof(after));
    if(std::memcmp(&after,&metadata,sizeof(metadata))!=0){SecureZeroMemory(result.pixels.bgra.data(),result.pixels.bgra.size());throw FrameRetry();}
    return result;
}
FrameTicket peek_shared_frame(HANDLE mapping,std::size_t bytes,const ipc::Session& session){
    require(bytes>header_bytes+cursor_storage_bytes && bytes<=header_bytes+maximum_pixels*4+cursor_storage_bytes,"frame_peek_bound");
    const void* view=MapViewOfFile(mapping,FILE_MAP_READ,0,0,header_bytes);require(view!=nullptr,"frame_peek_view");
    Metadata first{},after{};std::memcpy(&first,view,sizeof(first));MemoryBarrier();std::memcpy(&after,view,sizeof(after));UnmapViewOfFile(view);
    if(std::memcmp(&first,&after,sizeof(first))!=0)throw FrameRetry();
    require(first.magic==0x32464447 && first.format==2 && first.session==session && first.slot<2,"frame_peek_identity");
    for(auto c:first.reserved)require(c==0,"frame_peek_reserved");
    if(first.sequence)require(first.generation && first.tick && first.bytes==pixel_bytes(first.width,first.height) && first.bytes<=bytes-header_bytes-cursor_storage_bytes,"frame_peek_length");
    return {session,first.generation,first.sequence,first.tick,first.slot,first.width,first.height};
}
bool FramePool::publish_cursor(const CursorUpdate& cursor,std::uint64_t tick){
    if(cursor.session!=session_ || !tick)return false;
    auto packet=encode_cursor(cursor);std::lock_guard<std::mutex> lock(mutex_);
    if(cursor_revision_>UINT64_MAX-2)return false;
    auto mapped=std::span<std::uint8_t>(static_cast<std::uint8_t*>(slots_.at(0).view),mapping_bytes());
    auto region=mapped.subspan(header_bytes+capacity_,cursor_storage_bytes);
    auto* metadata=reinterpret_cast<CursorMetadata*>(&region.front());
    const auto writing=cursor_revision_+1;cursor_revision_+=2;
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&metadata->revision),static_cast<LONG64>(writing));MemoryBarrier();
    metadata->tick=tick;metadata->bytes=static_cast<std::uint32_t>(packet.size());metadata->reserved=0;metadata->reserved2=0;
    std::memcpy(region.subspan(sizeof(CursorMetadata),packet.size()).data(),packet.data(),packet.size());
    MemoryBarrier();InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&metadata->revision),static_cast<LONG64>(cursor_revision_));return true;
}
std::optional<CursorUpdate> read_shared_cursor(HANDLE mapping,std::size_t bytes,const ipc::Session& session,std::uint64_t transport,std::uint64_t generation,std::uint64_t now){
    require(bytes>header_bytes+cursor_storage_bytes && bytes<=header_bytes+maximum_pixels*4+cursor_storage_bytes,"cursor_mapping_bound");
    const void* view=MapViewOfFile(mapping,FILE_MAP_READ,0,0,bytes);require(view!=nullptr,"cursor_read_view");
    struct Unmap{const void* view;~Unmap(){UnmapViewOfFile(view);}} unmap{view};
    auto region=std::span<const std::uint8_t>(static_cast<const std::uint8_t*>(view),bytes).last(cursor_storage_bytes);
    CursorMetadata before{},after{};std::memcpy(&before,region.data(),sizeof(before));MemoryBarrier();
    std::memcpy(&after,region.data(),sizeof(after));if(std::memcmp(&before,&after,sizeof(before))!=0)return std::nullopt;
    if(!before.revision || (before.revision&1) || !before.tick || before.tick>now || now-before.tick>1000)return std::nullopt;
    require(before.bytes>=cursor_wire_header && before.bytes<=cursor_wire_header+cursor_max_pixels && !before.reserved && !before.reserved2,"cursor_shared_schema");
    auto payload=region.subspan(sizeof(before),before.bytes);std::vector<std::uint8_t> packet(payload.begin(),payload.end());MemoryBarrier();std::memcpy(&after,region.data(),sizeof(after));
    if(std::memcmp(&before,&after,sizeof(before))!=0)return std::nullopt;
    auto cursor=decode_cursor(packet);require(cursor.session==session && cursor.transport==transport,"cursor_shared_identity");
    if(cursor.generation!=generation)return std::nullopt;return cursor;
}

}
