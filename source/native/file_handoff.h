#pragma once
#include <windows.h>
#include <oleidl.h>

// Versioned, process-local interface for a cooperating receiver adapter.
// No global hook, remote process attachment, URL discovery or file-content IO.
constexpr DWORD GD_HANDOFF_ABI = 1;
constexpr DWORD GD_HANDOFF_CAPACITY = 64;
constexpr DWORD GD_HANDOFF_FILES = 32;
constexpr DWORD GD_HANDOFF_PATH = 4096;
constexpr DWORD GD_HANDOFF_ORIGIN = 512;

struct GDHandoffRecord {
    DWORD abi;
    DWORD size;
    GUID operation;
    ULONGLONG occurred;
    DWORD process_id;
    DWORD thread_id;
    DWORD file_index;
    DWORD file_count;
    DWORD effect;
    WCHAR path[GD_HANDOFF_PATH];
    WCHAR origin[GD_HANDOFF_ORIGIN];
};

// The receiver supplies the origin bound to THIS drop callback. A foreground
// window, title or recent URL is not an adequate implementation of this API.
using GDHandoffOrigin = BOOL (WINAPI*)(void*, WCHAR*, DWORD);

#ifdef GD_HANDOFF_BUILD
#define GD_HANDOFF_API extern "C" __declspec(dllexport)
#else
#define GD_HANDOFF_API extern "C" __declspec(dllimport)
#endif

GD_HANDOFF_API DWORD WINAPI gd_handoff_abi();
GD_HANDOFF_API DWORD WINAPI gd_handoff_record_size();
GD_HANDOFF_API HRESULT WINAPI gd_handoff_wrap(IDropTarget*, GDHandoffOrigin, void*, IDropTarget**);
GD_HANDOFF_API DWORD WINAPI gd_handoff_poll(GDHandoffRecord*, DWORD, ULONGLONG*);
