// Bounded UI test of the native file dialog of an explicitly owned Chrome PID.
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdlib>

namespace {
DWORD browser_pid = 0;
HWND dialog = nullptr;
HWND filename = nullptr;
HANDLE browser = nullptr;
HANDLE dialog_process = nullptr;
DWORD dialog_pid = 0;
WCHAR browser_image[32768]{};
ULONGLONG browser_created = 0;

ULONGLONG created(HANDLE process) {
    FILETIME start{}, end{}, kernel{}, user{};
    if (!GetProcessTimes(process, &start, &end, &kernel, &user)) return 0;
    return (static_cast<ULONGLONG>(start.dwHighDateTime)<<32)|start.dwLowDateTime;
}
bool browser_child(DWORD pid) {
    // Chrome's native chooser is hosted by a separate UtilWin process. Admit
    // only its exact direct child, same image, live retained handles and age.
    if (WaitForSingleObject(browser, 0) != WAIT_TIMEOUT) return false;
    DWORD parent = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do { if (entry.th32ProcessID == pid) { parent = entry.th32ParentProcessID; break; } }
        while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    if (pid != browser_pid && parent != browser_pid) return false;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!process) return false;
    WCHAR image[32768]{}; DWORD size = 32768;
    bool valid = WaitForSingleObject(process, 0) == WAIT_TIMEOUT &&
        QueryFullProcessImageNameW(process, 0, image, &size) &&
        _wcsicmp(image, browser_image) == 0 && created(process) >= browser_created;
    if (valid) { dialog_process = process; dialog_pid = pid; }
    else CloseHandle(process);
    return valid;
}
BOOL CALLBACK find_dialog(HWND window, LPARAM) {
    DWORD pid = 0; GetWindowThreadProcessId(window, &pid);
    WCHAR name[128]{}; GetClassNameW(window, name, 128);
    if (!IsWindowVisible(window) || wcscmp(name, L"#32770") != 0) return TRUE;
    HWND owner = GetWindow(window, GW_OWNER);
    bool same_owner = pid == browser_pid;
    for (int i = 0; owner && i < 8; ++i) {
        DWORD owner_pid = 0; GetWindowThreadProcessId(owner, &owner_pid);
        if (owner_pid == browser_pid) { same_owner = true; break; }
        owner = GetWindow(owner, GW_OWNER);
    }
    if (same_owner && browser_child(pid)) {
        dialog = window; return FALSE;
    }
    return TRUE;
}
BOOL CALLBACK find_filename(HWND window, LPARAM) {
    WCHAR name[128]{}; GetClassNameW(window, name, 128);
    const int id = GetDlgCtrlID(window);
    if (wcscmp(name, L"Edit") == 0 && IsWindowVisible(window)) {
        fprintf(stderr, "owned_dialog_edit_id=%d\n", id);
        if (id == 1001 || id == 0x480 || id == 0x47c) filename = window;
    }
    return TRUE;
}
bool owned(HWND window) {
    DWORD pid = 0; GetWindowThreadProcessId(window, &pid);
    return IsWindow(window) && pid == dialog_pid &&
        GetAncestor(window, GA_ROOT) == dialog &&
        WaitForSingleObject(browser, 0) == WAIT_TIMEOUT &&
        WaitForSingleObject(dialog_process, 0) == WAIT_TIMEOUT;
}
}
int wmain(int argc, WCHAR** argv) {
    struct Handles {
        ~Handles() { if (dialog_process) CloseHandle(dialog_process); if (browser) CloseHandle(browser); }
    } handles;
    if (argc != 3) return 2;
    browser_pid = wcstoul(argv[1], nullptr, 10);
    DWORD attributes = GetFileAttributesW(argv[2]);
    if (browser_pid <= 4 || attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) return 3;
    browser = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, browser_pid);
    DWORD size = 32768;
    if (!browser || !QueryFullProcessImageNameW(browser, 0, browser_image, &size)) return 10;
    browser_created = created(browser);
    if (!browser_created) return 10;
    ULONGLONG deadline = GetTickCount64()+8000;
    while (!dialog && GetTickCount64() < deadline) { EnumWindows(find_dialog, 0); if (!dialog) Sleep(50); }
    if (!dialog) { fprintf(stderr, "owned_file_dialog_not_observed\n"); return 4; }
    EnumChildWindows(dialog, find_filename, 0);
    if (!filename || !owned(filename)) { fprintf(stderr, "owned_filename_control_unresolved\n"); return 5; }
    HWND open = GetDlgItem(dialog, IDOK);
    if (!open || !owned(open)) return 6;
    DWORD_PTR response = 0;
    if (!SendMessageTimeoutW(filename, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(argv[2]),
                             SMTO_ABORTIFHUNG | SMTO_BLOCK, 1500, &response)) return 7;
    if (!owned(dialog) || !owned(open)) return 8;
    if (!SendMessageTimeoutW(open, BM_CLICK, 0, 0, SMTO_ABORTIFHUNG | SMTO_BLOCK, 1500, &response)) return 9;
    printf("{\"scope\":\"owned_native_file_picker\",\"target_pid\":%lu,\"selected\":true}\n",
           static_cast<unsigned long>(browser_pid));
    return 0;
}
