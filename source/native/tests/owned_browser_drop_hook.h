#pragma once
#define GD_HANDOFF_BUILD
#include "../file_handoff.h"

// Research ABI only. Never installed or selected by the normal Agent.
constexpr DWORD GD_OWNED_DROP_MAGIC = 0x47444f44;
constexpr DWORD GD_OWNED_DROP_SLOTS = 8;
struct GDOwnedDropShared {
    DWORD magic, size, browser_pid, controller_pid;
    ULONGLONG browser_created;
    WCHAR profile[1024];
    WCHAR fixture[GD_HANDOFF_PATH];
    WCHAR allowed_origins[2][GD_HANDOFF_ORIGIN];
    volatile LONG state, error, attached, detached, count, rejected, origin_failed, origin_stage;
    ULONGLONG callback_max_us, enter_max_us, origin_max_us, lost;
    GDHandoffRecord records[GD_OWNED_DROP_SLOTS];
};

// State 1=attached, 2=detached, -1=failed. A valid attachment pins the test DLL
// until this owned browser exits because Chromium can retain IDataObject refs.
// This deliberately does not claim a production unload/installer contract.
