#pragma once
#include <windows.h>
#include <cstdint>
#include <array>
#ifdef GD_MIS_NATIVE_BUILD
#define GD_MIS_API extern "C" __declspec(dllexport)
#else
#define GD_MIS_API extern "C" __declspec(dllimport)
#endif
// Local trusted controller ABI. No arbitrary URL, long-term token or file path.
struct GD_MIS_CONFIG {
    std::uint32_t bytes,version,can_control,owned_loopback;
    std::array<std::uint8_t,16> session;
    std::uint64_t transport,consent_deadline;
    std::uint32_t local_count,peer_count;
    std::array<std::uint32_t,8> local_ipv4,peer_ipv4;
    std::uint32_t hidden,software;
};
GD_MIS_API DWORD __stdcall GDMisCreate(const GD_MIS_CONFIG*,void**);
GD_MIS_API DWORD __stdcall GDMisGrant(void*,std::uint64_t);
GD_MIS_API DWORD __stdcall GDMisRelay(void*,const std::uint8_t*,std::uint32_t);
GD_MIS_API DWORD __stdcall GDMisOffer(void*);
GD_MIS_API DWORD __stdcall GDMisSignal(void*,std::uint32_t,const std::uint8_t*,std::uint32_t);
// Returns ERROR_NO_MORE_ITEMS, ERROR_INSUFFICIENT_BUFFER, or 0. SDP never logged.
GD_MIS_API DWORD __stdcall GDMisTakeSignal(void*,std::uint32_t*,std::uint8_t*,std::uint32_t*);
GD_MIS_API DWORD __stdcall GDMisPump(void*);
// Blocking owner loop; no callbacks into Python. Bounded cross-thread mailboxes.
GD_MIS_API DWORD __stdcall GDMisRun(void*);
GD_MIS_API DWORD __stdcall GDMisPostReply(void*,std::uint64_t,const std::uint8_t*,std::uint32_t);
GD_MIS_API DWORD __stdcall GDMisActivate(void*,std::uint32_t);
GD_MIS_API DWORD __stdcall GDMisWait(void*); // owner UI thread; message/frame/mailbox event
GD_MIS_API DWORD __stdcall GDMisWake(void*); // cross-thread mailbox notification only
GD_MIS_API DWORD __stdcall GDMisDiagnostics(void*,std::uint32_t*,std::uint32_t); // fixed scalar snapshot
GD_MIS_API DWORD __stdcall GDMisEndReason(void*,std::uint32_t*); // first cause, scalar enum; query before Close
GD_MIS_API DWORD __stdcall GDMisTransportDiagnostics(void*,std::uint32_t*,std::uint32_t); // 20 bounded scalars
GD_MIS_API DWORD __stdcall GDMisStop(void*); // cross-thread immediate lease fence
GD_MIS_API DWORD __stdcall GDMisClose(void*); // creator thread, after stop
