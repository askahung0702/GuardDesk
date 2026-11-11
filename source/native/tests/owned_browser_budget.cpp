// Actual OS timer comparison, no browser, input, file contents or system changes.
#include "owned_browser_budget.h"
#include <cstdio>

int wmain() {
    LARGE_INTEGER frequency{}; QueryPerformanceFrequency(&frequency);
    DWORD coarse_false_expired = 0, precise_false_expired = 0, short_valid = 0, long_expired = 0;
    for (DWORD i = 0; i < 1505; ++i) {
        OwnedBrowserBudget budget;
        ULONGLONG coarse = GetTickCount64();
        LARGE_INTEGER start{}, now{}; QueryPerformanceCounter(&start);
        const LONGLONG target = i < 1500 ? frequency.QuadPart*450/1000000 : frequency.QuadPart*12/1000;
        do { QueryPerformanceCounter(&now); } while (now.QuadPart-start.QuadPart < target);
        bool precise = budget.within();
        bool coarse_expired = GetTickCount64() > coarse+10;
        QueryPerformanceCounter(&now);
        LONGLONG actual_us = (now.QuadPart-start.QuadPart)*1000000/frequency.QuadPart;
        if (i < 1500 && actual_us < 9000) {
            ++short_valid;
            if (!precise) ++precise_false_expired;
            if (coarse_expired) ++coarse_false_expired;
        } else if (i >= 1500 && !precise) ++long_expired;
    }
    printf("{\"short_valid\":%lu,\"coarse_false_expired\":%lu,\"precise_false_expired\":%lu,\"long_expired\":%lu}\n",
        static_cast<unsigned long>(short_valid),static_cast<unsigned long>(coarse_false_expired),
        static_cast<unsigned long>(precise_false_expired),static_cast<unsigned long>(long_expired));
    return short_valid > 1400 && precise_false_expired == 0 && long_expired == 5 ? 0 : 1;
}
