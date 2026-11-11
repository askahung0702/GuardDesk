// Real Windows OLE drag into an explicitly identified, self-owned test browser.
// No hooks, code injection, memory inspection, browser-policy or security changes.
#include <windows.h>
#include <ole2.h>
#include <shlobj.h>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <atomic>
#include <vector>
#include <cstring>

namespace {
DWORD browser_pid = 0;
HWND target = nullptr;
POINT destination{};
ULONGLONG started = 0;
HANDLE source_thread = nullptr;
bool cancel_drag = false;

void own_wait_stack() {
    // Bounded, metadata-only watchdog of this helper's own blocked thread.
    // Never attaches to Chrome or records stack bytes, registers or contents.
    if (SuspendThread(source_thread) == static_cast<DWORD>(-1)) return;
    CONTEXT context{}; context.ContextFlags = CONTEXT_FULL;
    DWORD64 pcs[16]{}; size_t count = 0;
    if (GetThreadContext(source_thread, &context)) {
        while (context.Rip && count < 16) {
            pcs[count++] = context.Rip;
            DWORD64 base = 0;
            auto entry = RtlLookupFunctionEntry(context.Rip, &base, nullptr);
            if (entry) {
                PVOID handler = nullptr; DWORD64 frame = 0;
                RtlVirtualUnwind(0, base, context.Rip, entry, &context, &handler, &frame, nullptr);
            } else {
                MEMORY_BASIC_INFORMATION memory{};
                if (!VirtualQuery(reinterpret_cast<void*>(context.Rsp), &memory, sizeof(memory)) ||
                    memory.State != MEM_COMMIT || (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS))) break;
                context.Rip = *reinterpret_cast<DWORD64*>(context.Rsp);
                context.Rsp += sizeof(DWORD64);
            }
        }
    }
    ResumeThread(source_thread);
    for (size_t i = 0; i < count; ++i) {
        HMODULE module = nullptr; WCHAR image[MAX_PATH]{};
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(pcs[i]), &module) && GetModuleFileNameW(module, image, MAX_PATH)) {
            const WCHAR* name = wcsrchr(image, L'\\');
            fwprintf(stderr, L"owned_wait_frame=%s+%llx\n", name ? name+1 : image,
                static_cast<unsigned long long>(pcs[i]-reinterpret_cast<DWORD64>(module)));
        }
    }
    fflush(stderr);
}

// A self-owned CF_HDROP object avoids invoking shell extensions while preparing
// the fixture. It exposes paths only and never opens the fixture's contents.
class Data final : public IDataObject {
    LONG references_ = 1;
    std::vector<BYTE> bytes_;
public:
    explicit Data(const WCHAR* path) {
        bytes_.resize(sizeof(DROPFILES)+(wcslen(path)+2)*sizeof(WCHAR), 0);
        auto header = reinterpret_cast<DROPFILES*>(bytes_.data());
        header->pFiles = sizeof(DROPFILES); header->fWide = TRUE;
        memcpy(bytes_.data()+sizeof(DROPFILES), path, (wcslen(path)+1)*sizeof(WCHAR));
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (id != IID_IUnknown && id != IID_IDataObject) return E_NOINTERFACE;
        *out = static_cast<IDataObject*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&references_); }
    ULONG STDMETHODCALLTYPE Release() override { auto n = InterlockedDecrement(&references_); if (!n) delete this; return n; }
    HRESULT STDMETHODCALLTYPE QueryGetData(FORMATETC* f) override {
        return f && f->cfFormat == CF_HDROP && f->dwAspect == DVASPECT_CONTENT &&
            f->lindex == -1 && (f->tymed & TYMED_HGLOBAL) ? S_OK : DV_E_FORMATETC;
    }
    HRESULT STDMETHODCALLTYPE GetData(FORMATETC* f, STGMEDIUM* out) override {
        if (!out || QueryGetData(f) != S_OK) return DV_E_FORMATETC;
        HGLOBAL block = GlobalAlloc(GMEM_MOVEABLE, bytes_.size());
        if (!block) return E_OUTOFMEMORY;
        void* dest = GlobalLock(block);
        if (!dest) { GlobalFree(block); return E_OUTOFMEMORY; }
        memcpy(dest, bytes_.data(), bytes_.size()); GlobalUnlock(block);
        *out = {}; out->tymed = TYMED_HGLOBAL; out->hGlobal = block; return S_OK;
    }
    HRESULT STDMETHODCALLTYPE EnumFormatEtc(DWORD direction, IEnumFORMATETC** out) override {
        if (direction != DATADIR_GET) return E_NOTIMPL;
        FORMATETC format{CF_HDROP, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
        return SHCreateStdEnumFmtEtc(1, &format, out);
    }
    HRESULT STDMETHODCALLTYPE GetDataHere(FORMATETC*, STGMEDIUM*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetCanonicalFormatEtc(FORMATETC*, FORMATETC*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetData(FORMATETC*, STGMEDIUM*, BOOL) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE DAdvise(FORMATETC*, DWORD, IAdviseSink*, DWORD*) override { return OLE_E_ADVISENOTSUPPORTED; }
    HRESULT STDMETHODCALLTYPE DUnadvise(DWORD) override { return OLE_E_ADVISENOTSUPPORTED; }
    HRESULT STDMETHODCALLTYPE EnumDAdvise(IEnumSTATDATA**) override { return OLE_E_ADVISENOTSUPPORTED; }
};

BOOL CALLBACK find_window(HWND window, LPARAM) {
    DWORD pid = 0; GetWindowThreadProcessId(window, &pid);
    WCHAR name[128]{}; GetClassNameW(window, name, 128);
    if (pid == browser_pid && IsWindowVisible(window) && wcscmp(name, L"Chrome_WidgetWin_1") == 0) {
        target = window; return FALSE;
    }
    return TRUE;
}
BOOL CALLBACK find_content(HWND window, LPARAM) {
    WCHAR name[128]{}; GetClassNameW(window, name, 128);
    if (IsWindowVisible(window) && wcscmp(name, L"Chrome_RenderWidgetHostHWND") == 0) {
        RECT bounds{}; GetWindowRect(window, &bounds);
        if (bounds.right-bounds.left > 300 && bounds.bottom-bounds.top > 200) {
            destination = {(bounds.left+bounds.right)/2, (bounds.top+bounds.bottom)/2};
            return FALSE;
        }
    }
    return TRUE;
}
class Source final : public IDropSource {
    LONG references_ = 1;
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (id != IID_IUnknown && id != IID_IDropSource) return E_NOINTERFACE;
        *out = static_cast<IDropSource*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&references_); }
    ULONG STDMETHODCALLTYPE Release() override { auto n = InterlockedDecrement(&references_); if (!n) delete this; return n; }
    HRESULT STDMETHODCALLTYPE QueryContinueDrag(BOOL escape, DWORD) override {
        static bool first = true;
        if (first) { fprintf(stderr, "owned_query_continue\n"); fflush(stderr); first = false; }
        if (escape || !IsWindow(target)) {
            fprintf(stderr,"owned_cancel_reason=%s\n",escape ? "escape" : "target_gone");
            return DRAGDROP_S_CANCEL;
        }
        if (GetTickCount64()-started < 800) return S_OK;
        if (cancel_drag) { fprintf(stderr,"owned_cancel_reason=explicit_case\n"); return DRAGDROP_S_CANCEL; }
        POINT point{}; GetCursorPos(&point);
        HWND under = WindowFromPoint(point);
        DWORD under_pid = 0; GetWindowThreadProcessId(under,&under_pid);
        RECT receiver_bounds{}; GetWindowRect(target,&receiver_bounds);
        // Edge can expose its owned drag visual as a separate root window.
        // Accept only the same verified test browser, same root owner and a
        // physical point inside our exact receiver; never another app/root.
        bool owned_visual = under && under_pid == browser_pid &&
            GetAncestor(under,GA_ROOTOWNER) == target && PtInRect(&receiver_bounds,point);
        if (!under || (GetAncestor(under, GA_ROOT) != target && !owned_visual)) {
            DWORD pid = under_pid;
            RECT bounds = receiver_bounds;
            // Metadata about our expected receiver and cursor only. No window
            // title, text, foreign process memory or document contents.
            fprintf(stderr,"owned_cancel_reason=cursor_receiver_mismatch,x=%ld,y=%ld,expected_rect=%ld,%ld,%ld,%ld,hit_same_browser=%u,root_owner_matches=%u\n",
                point.x,point.y,bounds.left,bounds.top,bounds.right,bounds.bottom,
                pid == browser_pid ? 1u : 0u,
                under && GetAncestor(under,GA_ROOTOWNER) == target ? 1u : 0u);
            return DRAGDROP_S_CANCEL;
        }
        return DRAGDROP_S_DROP;
    }
    HRESULT STDMETHODCALLTYPE GiveFeedback(DWORD) override { return DRAGDROP_S_USEDEFAULTCURSORS; }
};
}

int wmain(int argc, WCHAR** argv) {
    if (argc != 3 && !(argc == 4 && wcscmp(argv[3], L"--cancel") == 0)) {
        fwprintf(stderr, L"Usage: owned_ole_drop.exe <owned-browser-pid> <synthetic-file> [--cancel]\n"); return 2;
    }
    cancel_drag = argc == 4;
    browser_pid = wcstoul(argv[1], nullptr, 10);
    DWORD attributes = GetFileAttributesW(argv[2]);
    if (browser_pid <= 4 || attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) return 3;
    EnumWindows(find_window, 0);
    if (!target) return 4;
    if (GetAsyncKeyState(VK_LBUTTON) & 0x8000) {
        fprintf(stderr, "owned_test_refused_existing_mouse_press\n"); return 9;
    }
    RECT bounds{}; GetWindowRect(target, &bounds);
    destination = {(bounds.left+bounds.right)/2, bounds.top+(bounds.bottom-bounds.top)*2/3};
    EnumChildWindows(target, find_content, 0);
    POINT prior_cursor{};
    if (!GetCursorPos(&prior_cursor)) {
        fprintf(stderr, "owned_input_desktop_unavailable=%lu\n", static_cast<unsigned long>(GetLastError()));
        return 7;
    }
    HRESULT hr = OleInitialize(nullptr);
    if (FAILED(hr)) return 5;
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &source_thread,
                         THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, 0)) {
        OleUninitialize(); return 10;
    }
    IDataObject* data = new Data(argv[2]);
    HWND prior = GetForegroundWindow();
    // DoDragDrop must originate from our own foreground UI thread. Starting it
    // while Chrome owns foreground/capture is not a real source-side drag.
    HWND source_window = CreateWindowExW(0, L"STATIC", L"GuardDesk owned drag source",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE, 980, 40, 300, 140, nullptr, nullptr,
        GetModuleHandleW(nullptr), nullptr);
    if (!source_window) { data->Release(); CloseHandle(source_thread); OleUninitialize(); return 11; }
    ShowWindow(source_window, SW_SHOWNORMAL); UpdateWindow(source_window);
    DWORD effect = DROPEFFECT_NONE;
    if (SUCCEEDED(hr)) {
        SetForegroundWindow(source_window);
        RECT source_bounds{}; GetWindowRect(source_window, &source_bounds);
        if (GetForegroundWindow() != source_window || !SetCursorPos(source_bounds.left+100, source_bounds.top+70)) {
            fprintf(stderr, "owned_source_foreground_unavailable\n");
            DestroyWindow(source_window); data->Release(); CloseHandle(source_thread); OleUninitialize(); return 12;
        }
        std::atomic<bool> running{true};
        INPUT button{}; button.type = INPUT_MOUSE; button.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
        if (SendInput(1, &button, sizeof(button)) != 1) {
            fprintf(stderr, "owned_input_rejected=%lu\n", static_cast<unsigned long>(GetLastError()));
            DestroyWindow(source_window); data->Release(); CloseHandle(source_thread); OleUninitialize(); return 8;
        }
        std::thread movement([&running]() {
            bool toggle = false, sampled = false;
            while (running.load()) {
                Sleep(40); toggle = !toggle;
                if (!sampled && GetTickCount64()-started > 2000) {
                    sampled = true; own_wait_stack();
                }
                if (IsWindow(target)) {
                    if (GetTickCount64()-started > 150) SetCursorPos(destination.x, destination.y);
                    INPUT input{}; input.type = INPUT_MOUSE;
                    input.mi.dx = toggle ? 1 : -1;
                    input.mi.dwFlags = MOUSEEVENTF_MOVE;
                    SendInput(1, &input, sizeof(input));
                    if (GetTickCount64()-started > 900) {
                        input.mi.dx = 0; input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
                        SendInput(1, &input, sizeof(input));
                    }
                }
            }
        });
        started = GetTickCount64();
        auto source = new Source();
        fprintf(stderr, "owned_ole_begin\n"); fflush(stderr);
        hr = DoDragDrop(data, source, DROPEFFECT_COPY, &effect);
        fprintf(stderr, "owned_ole_end=%ld\n", static_cast<long>(hr)); fflush(stderr);
        source->Release(); running.store(false); movement.join();
        button.mi.dwFlags = MOUSEEVENTF_LEFTUP; SendInput(1, &button, sizeof(button));
    }
    if (GetForegroundWindow() == target || GetForegroundWindow() == source_window) {
        SetCursorPos(prior_cursor.x, prior_cursor.y);
        if (IsWindow(prior)) SetForegroundWindow(prior);
    }
    DestroyWindow(source_window);
    if (data) data->Release();
    CloseHandle(source_thread);
    OleUninitialize();
    printf("{\"hresult\":%ld,\"effect\":%lu,\"target_pid\":%lu,\"scope\":\"owned_real_ole_drag\"}\n",
           static_cast<long>(hr), static_cast<unsigned long>(effect), static_cast<unsigned long>(browser_pid));
    return (cancel_drag ? hr == DRAGDROP_S_CANCEL : hr == DRAGDROP_S_DROP && effect != DROPEFFECT_NONE) ? 0 : 6;
}
