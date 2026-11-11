#pragma once
#include <windows.h>
#include <cstdint>
#ifdef GUARDDESK_REMOTE_BRIDGE_BUILD
#define GD_REMOTE_API extern "C" __declspec(dllexport)
#else
#define GD_REMOTE_API extern "C" __declspec(dllimport)
#endif
// In-process SYSTEM broker ABI, never a public/network API. Values are copied
// from the broker's authenticated consent/logon snapshot. No path, shell text,
// endpoint credential or viewer-selected lease is accepted. The separate media
// channel accepts bounded opaque SDP and trusted local network configuration.
struct GD_REMOTE_START {
    std::uint32_t bytes,format,wts_session,administrator;
    std::uint32_t can_control,reserved;
    std::uint64_t authentication,logon_time,consent_filetime,consent_tick_deadline,transport;
    std::uint8_t session[16];
    wchar_t user_sid[184];
};
GD_REMOTE_API DWORD __stdcall GDRemoteReserve(const GD_REMOTE_START* spec,void** context);
// Read-only readiness check; no consent, capture, worker launch or token change.
GD_REMOTE_API DWORD __stdcall GDRemoteCheckTrust();
GD_REMOTE_API DWORD __stdcall GDRemoteLaunch(void* context);
// Private media channel: authenticated local configuration/SDP only. The caller
// must never forward a network-supplied grant/configuration or a worker lease.
GD_REMOTE_API DWORD __stdcall GDRemoteMediaWrite(void* context,const std::uint8_t* packet,std::uint32_t bytes);
GD_REMOTE_API DWORD __stdcall GDRemoteMediaPoll(void* context,std::uint8_t* packet,std::uint32_t capacity,std::uint32_t* bytes);
GD_REMOTE_API DWORD __stdcall GDRemoteWorkerPoll(void* context,std::uint8_t* packet,std::uint32_t capacity,std::uint32_t* bytes);
GD_REMOTE_API DWORD __stdcall GDRemoteCommand(void* context,const std::uint8_t* packet,std::uint32_t bytes);
GD_REMOTE_API DWORD __stdcall GDRemoteLastError(char* text,std::uint32_t capacity);
GD_REMOTE_API DWORD __stdcall GDRemoteStop(void* context);
GD_REMOTE_API DWORD __stdcall GDRemoteClose(void* context);
