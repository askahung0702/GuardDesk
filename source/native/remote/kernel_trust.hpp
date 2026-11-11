#pragma once
#include <windows.h>

namespace remote {
// Only kernel objects belonging to the fixed SYSTEM broker. File/desktop
// ownership and permissions use their separate, unchanged trust policies.
void require_kernel_descriptor(PSECURITY_DESCRIPTOR descriptor,DWORD harmless);
void require_query_only_kernel_trust(HANDLE object,DWORD harmless);
}
