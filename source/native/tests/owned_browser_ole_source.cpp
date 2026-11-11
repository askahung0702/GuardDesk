// Research test driver only. Reuse the owned OLE source without changing its
// sealed executable. Restrict browser target to the large test window and click
// our OWN unobscured source window when Windows declines foreground activation.
// No foreground-lock policy changes, AttachThreadInput or global input hooks.
#include <windows.h>
#include <cstdio>

namespace {
HWND expected_receiver = nullptr;
HWND owned_source_window(DWORD extended, LPCWSTR kind, LPCWSTR title, DWORD style,
    int x, int y, int width, int height, HWND parent, HMENU menu, HINSTANCE instance, LPVOID parameter) {
    if (!kind || wcscmp(kind,L"STATIC") != 0 || parent) return nullptr;
    WNDCLASSW klass{};
    klass.lpfnWndProc = DefWindowProcW;
    klass.hInstance = instance;
    klass.lpszClassName = L"GuardDeskOwnedOleSource.v1";
    if (!RegisterClassW(&klass) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return nullptr;
    // WindowFromPoint intentionally skips STATIC text controls. Use a normal
    // test window so the unobscured-own-window input guard is meaningful.
    return CreateWindowExW(extended,klass.lpszClassName,title,style,x,y,width,height,
        parent,menu,instance,parameter);
}

BOOL owned_source_foreground(HWND window) {
    SetForegroundWindow(window);
    Sleep(80);
    if (GetForegroundWindow() == window) return TRUE;
    DWORD pid = 0; GetWindowThreadProcessId(window, &pid);
    if (pid != GetCurrentProcessId()) return FALSE;
    if (GetAsyncKeyState(VK_LBUTTON) & 0x8000) { fprintf(stderr,"owned_activation_existing_press\n"); return FALSE; }
    SetWindowPos(window, HWND_TOP, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    Sleep(40);
    RECT bounds{};
    if (!GetWindowRect(window, &bounds)) return FALSE;
    POINT point{bounds.left+70, bounds.top+60};
    // Refuse to click through another program, menu or overlay.
    HWND hit = WindowFromPoint(point);
    if (!hit || GetAncestor(hit, GA_ROOT) != window) { fprintf(stderr,"owned_activation_point_obscured\n"); return FALSE; }
    if (!SetCursorPos(point.x, point.y)) return FALSE;
    INPUT press[2]{};
    for (auto& item : press) item.type = INPUT_MOUSE;
    press[0].mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
    press[1].mi.dwFlags = MOUSEEVENTF_LEFTUP;
    UINT sent = SendInput(2, press, sizeof(INPUT));
    if (sent == 1) SendInput(1, &press[1], sizeof(INPUT));
    Sleep(50);
    bool active = GetForegroundWindow() == window;
    fprintf(stderr,"owned_activation_click_sent=%u,active=%u\n",sent,active ? 1u : 0u);
    return sent == 2 && active;
}

struct OwnedEnumeration { WNDENUMPROC callback; LPARAM argument; };
BOOL CALLBACK owned_large_window(HWND window, LPARAM context) {
    if (expected_receiver && window != expected_receiver) return TRUE;
    RECT bounds{};
    if (!GetWindowRect(window, &bounds) || bounds.right-bounds.left < 800 ||
        bounds.bottom-bounds.top < 600) return TRUE;
    auto value = reinterpret_cast<OwnedEnumeration*>(context);
    return value->callback(window, value->argument);
}
BOOL owned_enum_windows(WNDENUMPROC callback, LPARAM argument) {
    OwnedEnumeration value{callback, argument};
    return EnumWindows(owned_large_window, reinterpret_cast<LPARAM>(&value));
}
}

#define SetForegroundWindow owned_source_foreground
#define EnumWindows owned_enum_windows
#define CreateWindowExW owned_source_window
#define wmain owned_source_main
#include "owned_ole_drop.cpp"
#undef wmain
#undef CreateWindowExW
#undef EnumWindows
#undef SetForegroundWindow

int wmain(int argc, wchar_t** argv) {
    // All test cursor, WindowFromPoint and receiver coordinates are physical.
    using SetDpi = BOOL (WINAPI*)(HANDLE);
    auto set_dpi = reinterpret_cast<SetDpi>(GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetProcessDpiAwarenessContext"));
    if (!set_dpi || !set_dpi(reinterpret_cast<HANDLE>(-4))) return 13;
    if (argc < 4 || wcsncmp(argv[argc-1],L"--target-window=",16) != 0) return 14;
    expected_receiver = reinterpret_cast<HWND>(_wcstoui64(argv[argc-1]+16,nullptr,10));
    DWORD pid = 0; GetWindowThreadProcessId(expected_receiver,&pid);
    if (!expected_receiver || GetAncestor(expected_receiver,GA_ROOT) != expected_receiver ||
        pid != wcstoul(argv[1],nullptr,10)) return 15;
    --argc;
    return owned_source_main(argc,argv);
}
