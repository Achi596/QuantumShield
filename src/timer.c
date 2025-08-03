#include "timer.h"

#if defined(_WIN32) || defined(_WIN64)
#define USE_QPC
#include <windows.h>

// High-resolution timer using QueryPerformanceCounter
double hires_time_seconds(void) {
    static LARGE_INTEGER freq;
    static int init = 0;
    LARGE_INTEGER counter;
    if (!init) {
        QueryPerformanceFrequency(&freq);
        init = 1;
    }
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)freq.QuadPart;
}

// Fallback to using the standard time function if the Windows API is not available
#else
#include <time.h>

// High-resolution timer using clock_gettime
double hires_time_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

#endif
