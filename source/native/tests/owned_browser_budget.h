#pragma once
#include <windows.h>

// A cooperative 10ms query budget, never a promise to interrupt a Windows API.
// GetTickCount64's 10-16ms granularity can falsely expire sub-millisecond work.
class OwnedBrowserBudget {
    LARGE_INTEGER start_{}, frequency_{};
    bool ready_ = false;
public:
    OwnedBrowserBudget() {
        ready_ = QueryPerformanceFrequency(&frequency_) && frequency_.QuadPart >= 100 &&
            QueryPerformanceCounter(&start_);
    }
    bool within() const {
        LARGE_INTEGER now{};
        return ready_ && QueryPerformanceCounter(&now) && now.QuadPart >= start_.QuadPart &&
            now.QuadPart-start_.QuadPart <= frequency_.QuadPart/100;
    }
};
