// Explicitly owned-browser research. Thread-specific functional Windows hook,
// no global hook, code patching, security changes, contents or employee target.
// The OleDropTargetInterface property is undocumented: research only.
#include "owned_browser_drop_hook.h"
#include "owned_browser_budget.h"
#include <oleacc.h>
#include <servprov.h>
#include <tlhelp32.h>
#include <wrl/client.h>
#include <string>
#include <cwchar>
#include <new>

using Microsoft::WRL::ComPtr;

// Minimal ABI declaration for the published IAccessible2 metadata interface.
// Interface order/GUID from Linux Foundation Accessible2.idl (BSD-3-Clause).
// Full notice is retained in owned_browser_drop_hook_IA2_LICENSE.txt.
struct __declspec(uuid("E89F726E-C4F4-4c19-BB19-B647D7FA8478")) IA2Metadata : IAccessible {
    virtual HRESULT STDMETHODCALLTYPE get_nRelations(LONG*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_relation(LONG, void**) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_relations(LONG, void**, LONG*) = 0;
    virtual HRESULT STDMETHODCALLTYPE role(LONG*) = 0;
    virtual HRESULT STDMETHODCALLTYPE scrollTo(int) = 0;
    virtual HRESULT STDMETHODCALLTYPE scrollToPoint(int, LONG, LONG) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_groupPosition(LONG*, LONG*, LONG*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_states(LONG*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_extendedRole(BSTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_localizedExtendedRole(BSTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_nExtendedStates(LONG*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_extendedStates(LONG, BSTR**, LONG*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_localizedExtendedStates(LONG, BSTR**, LONG*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_uniqueID(LONG*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_windowHandle(HWND*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_indexInParent(LONG*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_locale(void*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_attributes(BSTR*) = 0;
};

namespace {
HMODULE module = nullptr;
HANDLE mapping = nullptr;
GDOwnedDropShared* shared = nullptr;
HWND receiver = nullptr;
HWND drop_window = nullptr;
DWORD owner_thread = 0;
IDropTarget* installed_target = nullptr;
// No global COM destructor under loader lock. Release explicitly on the UI
// thread on attach failure or successful restoration.
IDropTarget* original_target = nullptr;
ULONGLONG last_native_loss = 0;
const wchar_t* message_name = L"GuardDesk.OwnedBrowserDropProbe.v1";

void close_mapping() {
    if (shared) { UnmapViewOfFile(shared); shared = nullptr; }
    if (mapping) { CloseHandle(mapping); mapping = nullptr; }
}

void attach_failure(LONG error) {
    if (shared) { shared->error = error; MemoryBarrier(); shared->state = -1; }
    if (original_target) { original_target->Release(); original_target = nullptr; }
    close_mapping();
}

DWORD parent_pid() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
    DWORD parent = 0;
    if (Process32FirstW(snapshot, &entry)) do {
        if (entry.th32ProcessID == GetCurrentProcessId()) { parent = entry.th32ParentProcessID; break; }
    } while (Process32NextW(snapshot, &entry));
    CloseHandle(snapshot); return parent;
}

bool own_scope(GDOwnedDropShared* value, DWORD controller) {
    FILETIME c{}, e{}, k{}, u{};
    if (!value || value->magic != GD_OWNED_DROP_MAGIC || value->size != sizeof(*value) ||
        value->browser_pid != GetCurrentProcessId() || value->controller_pid != controller ||
        parent_pid() != controller || !GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u)) return false;
    ULARGE_INTEGER created{}; created.LowPart = c.dwLowDateTime; created.HighPart = c.dwHighDateTime;
    if (created.QuadPart != value->browser_created) return false;
    if (!wmemchr(value->profile, 0, 1024) || !wmemchr(value->fixture, 0, GD_HANDOFF_PATH) ||
        !wmemchr(value->allowed_origins[0], 0, GD_HANDOFF_ORIGIN) ||
        !wmemchr(value->allowed_origins[1], 0, GD_HANDOFF_ORIGIN)) return false;
    // Only the controller-launched disposable profile, never an employee one.
    if (!wcsstr(value->profile, L"\\runtime\\owned-native-drop-") ||
        !wcsstr(GetCommandLineW(), value->profile) ||
        !wcsstr(value->fixture, L"\\runtime\\owned-native-drop-") ||
        !wcsstr(value->fixture, L"\\owned-fixture.txt")) return false;
    const std::wstring profile(value->profile);
    if (profile.size() < 8 || profile.compare(profile.size()-8,8,L"\\profile") != 0 ||
        profile.substr(0,profile.size()-8)+L"\\owned-fixture.txt" != value->fixture) return false;
    return wcsncmp(value->allowed_origins[0], L"http://127.0.0.1:", 17) == 0;
}

struct Document {
    LONG id = 0;
    HWND window = nullptr;
    WCHAR origin[GD_HANDOFF_ORIGIN]{};
};

bool resolve_document(POINTL point, Document& result) {
    if (!shared || GetCurrentThreadId() != owner_thread) return false;
    OwnedBrowserBudget budget;
    shared->origin_stage = 10;
    ComPtr<IAccessible> current;
    if (FAILED(AccessibleObjectFromWindow(receiver, static_cast<DWORD>(OBJID_CLIENT), IID_PPV_ARGS(&current)))) return false;
    VARIANT hit{};
    shared->origin_stage = 11;
    if (FAILED(current->accHitTest(point.x, point.y, &hit))) return false;
    if (hit.vt == VT_DISPATCH && hit.pdispVal) {
        ComPtr<IAccessible> child;
        HRESULT status = hit.pdispVal->QueryInterface(IID_PPV_ARGS(&child));
        VariantClear(&hit);
        if (FAILED(status)) return false;
        current = child;
    } else if (hit.vt != VT_I4 || hit.lVal != CHILDID_SELF) {
        VariantClear(&hit); return false;
    } else { VariantClear(&hit); }
    VARIANT self{}; self.vt = VT_I4; self.lVal = CHILDID_SELF;
    for (int depth = 0; current && depth < 32 && budget.within(); ++depth) {
        VARIANT role{}, state{};
        HRESULT hr = current->get_accRole(self, &role);
        if (FAILED(hr)) return false;
        const bool is_document = role.vt == VT_I4 && role.lVal == ROLE_SYSTEM_DOCUMENT;
        VariantClear(&role);
        if (is_document) {
            shared->origin_stage = 20;
            if (FAILED(current->get_accState(self, &state))) return false;
            bool hidden = state.vt != VT_I4 || (state.lVal & (STATE_SYSTEM_INVISIBLE | STATE_SYSTEM_OFFSCREEN));
            VariantClear(&state);
            if (hidden) return false;
            ComPtr<IServiceProvider> provider;
            ComPtr<IA2Metadata> metadata;
            shared->origin_stage = 22;
            if (FAILED(current.As(&provider)) || FAILED(provider->QueryService(IID_IAccessible,
                    __uuidof(IA2Metadata), reinterpret_cast<void**>(metadata.GetAddressOf())))) return false;
            BSTR attributes = nullptr;
            shared->origin_stage = 23;
            hr = metadata->get_attributes(&attributes);
            // An author-provided ARIA document/input must not spoof the URL.
            const bool document_tag = SUCCEEDED(hr) && attributes && SysStringLen(attributes) <= 8192 &&
                (wcsncmp(attributes, L"tag:#document;", 14) == 0 || wcsstr(attributes, L";tag:#document;"));
            SysFreeString(attributes);
            if (!document_tag) {
                // An author ARIA document is not a browser document. Skip it
                // without ever reading its editable value, then find its real
                // containing document (including a cross-origin iframe).
                ComPtr<IDispatch> parent;
                ComPtr<IAccessible> next;
                if (FAILED(current->get_accParent(&parent)) || !parent || FAILED(parent.As(&next))) return false;
                current = next;
                continue;
            }
            shared->origin_stage = 24;
            if (FAILED(metadata->get_uniqueID(&result.id)) || !result.id ||
                FAILED(metadata->get_windowHandle(&result.window)) || !result.window) return false;
            DWORD pid = 0; GetWindowThreadProcessId(result.window, &pid);
            shared->origin_stage = 25;
            if (pid != GetCurrentProcessId() || GetAncestor(result.window, GA_ROOT) != receiver) return false;
            BSTR value = nullptr;
            shared->origin_stage = 26;
            hr = current->get_accValue(self, &value);
            if (FAILED(hr) || !value || SysStringLen(value) > 8192) { SysFreeString(value); return false; }
            // Discard path/query/fragment; this research accepts only our local origins.
            const wchar_t* end = wcspbrk(value + (wcsncmp(value, L"http://", 7) == 0 ? 7 : 0), L"/?#");
            size_t length = end ? static_cast<size_t>(end-value) : wcslen(value);
            bool valid = length > 7 && length < GD_HANDOFF_ORIGIN;
            if (valid) { wmemcpy(result.origin, value, length); result.origin[length] = 0; }
            SysFreeString(value);
            if (!valid) return false;
            shared->origin_stage = 27;
            const bool allowed = (wcscmp(result.origin, shared->allowed_origins[0]) == 0 ||
                    (shared->allowed_origins[1][0] && wcscmp(result.origin, shared->allowed_origins[1]) == 0)) &&
                    budget.within();
            if (allowed) shared->origin_stage = 28;
            return allowed;
        }
        ComPtr<IDispatch> parent;
        if (FAILED(current->get_accParent(&parent)) || !parent) return false;
        ComPtr<IAccessible> next;
        if (FAILED(parent.As(&next))) return false;
        current = next;
    }
    return false;
}

bool document_at(POINTL point, Document& result) {
    LARGE_INTEGER start{}, finish{}, frequency{};
    QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&start);
    bool found = resolve_document(point,result);
    QueryPerformanceCounter(&finish);
    ULONGLONG duration = static_cast<ULONGLONG>((finish.QuadPart-start.QuadPart)*1000000/frequency.QuadPart);
    if (shared && duration > shared->origin_max_us) shared->origin_max_us = duration;
    return found;
}

class Target final : public IDropTarget {
    LONG references_ = 1;
    ComPtr<IDropTarget> wrapped_;
    Document before_{};
    bool bound_ = false;
    static BOOL WINAPI origin(void* context, WCHAR* output, DWORD capacity) {
        auto target = static_cast<Target*>(context);
        if (!target->bound_ || capacity < GD_HANDOFF_ORIGIN) return FALSE;
        wcscpy_s(output, capacity, target->before_.origin); return TRUE;
    }
public:
    HRESULT init(IDropTarget* target) { return gd_handoff_wrap(target, origin, this, &wrapped_); }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (id != IID_IUnknown && id != IID_IDropTarget) return E_NOINTERFACE;
        *out = static_cast<IDropTarget*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(InterlockedIncrement(&references_)); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG value = InterlockedDecrement(&references_); if (!value) delete this;
        return static_cast<ULONG>(value);
    }
    HRESULT STDMETHODCALLTYPE DragEnter(IDataObject* data, DWORD keys, POINTL point, DWORD* effect) override {
        LARGE_INTEGER start{}, finish{}, frequency{};
        QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&start);
        // Warm a newly exposed document's browser-owned accessibility cache.
        // No GetData, file content, path or origin retained at this stage.
        // The actual Drop must independently resolve the same document twice.
        Document warm{}; document_at(point,warm);
        HRESULT status = wrapped_->DragEnter(data, keys, point, effect);
        QueryPerformanceCounter(&finish);
        ULONGLONG duration = static_cast<ULONGLONG>((finish.QuadPart-start.QuadPart)*1000000/frequency.QuadPart);
        if (duration > shared->enter_max_us) shared->enter_max_us = duration;
        return status;
    }
    HRESULT STDMETHODCALLTYPE DragOver(DWORD keys, POINTL point, DWORD* effect) override { return wrapped_->DragOver(keys, point, effect); }
    HRESULT STDMETHODCALLTYPE DragLeave() override { return wrapped_->DragLeave(); }
    HRESULT STDMETHODCALLTYPE Drop(IDataObject* data, DWORD keys, POINTL point, DWORD* effect) override {
        LARGE_INTEGER start{}, finish{}, frequency{}; QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&start);
        before_ = {}; bound_ = document_at(point, before_);
        HRESULT status = wrapped_->Drop(data, keys, point, effect);
        Document after{};
        const bool consistent = bound_ && document_at(point, after) && before_.id == after.id &&
            before_.window == after.window && wcscmp(before_.origin, after.origin) == 0;
        // This pinned research DLL has one receiving UI thread and no competing
        // ring consumer; poll only after its original Drop has returned.
        GDHandoffRecord records[GD_OWNED_DROP_SLOTS]{}; ULONGLONG lost = 0;
        DWORD count = gd_handoff_poll(records, GD_OWNED_DROP_SLOTS, &lost);
        shared->lost += lost >= last_native_loss ? lost-last_native_loss : lost;
        last_native_loss = lost;
        if (!consistent) InterlockedIncrement(&shared->origin_failed);
        for (DWORD i = 0; i < count; ++i) {
            if (!consistent || _wcsicmp(records[i].path, shared->fixture) != 0) {
                InterlockedIncrement(&shared->rejected); continue;
            }
            LONG index = shared->count;
            if (index >= static_cast<LONG>(GD_OWNED_DROP_SLOTS)) { ++shared->lost; continue; }
            shared->records[index] = records[i];
            MemoryBarrier(); InterlockedIncrement(&shared->count);
        }
        QueryPerformanceCounter(&finish);
        ULONGLONG duration = static_cast<ULONGLONG>((finish.QuadPart-start.QuadPart)*1000000/frequency.QuadPart);
        if (duration > shared->callback_max_us) shared->callback_max_us = duration;
        return status;
    }
};

void attach(HWND window, DWORD controller, ATOM atom) {
    if (shared || GetWindowThreadProcessId(window, nullptr) != GetCurrentThreadId()) return;
    WCHAR name[256]{};
    if (!GlobalGetAtomNameW(atom, name, 256) || wcsncmp(name, L"Local\\GuardDesk-OwnedDrop-", 25) != 0) return;
    mapping = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name);
    if (!mapping) return;
    auto value = static_cast<GDOwnedDropShared*>(MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(GDOwnedDropShared)));
    if (!value || !own_scope(value, controller)) {
        if (value) UnmapViewOfFile(value); CloseHandle(mapping); mapping = nullptr; return;
    }
    shared = value; receiver = GetAncestor(window, GA_ROOT); drop_window = window; owner_thread = GetCurrentThreadId();
    auto original = reinterpret_cast<IDropTarget*>(GetPropW(drop_window, L"OleDropTargetInterface"));
    if (!original) { attach_failure(1); return; }
    // Undocumented property is used ONLY in this controller-owned test process.
    original_target = original; original_target->AddRef();
    auto target = new (std::nothrow) Target();
    if (!target) { attach_failure(2); return; }
    HRESULT status = target->init(original);
    HMODULE pinned = nullptr;
    if (SUCCEEDED(status) && !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(module), &pinned)) status = HRESULT_FROM_WIN32(GetLastError());
    if (SUCCEEDED(status)) status = RevokeDragDrop(drop_window);
    if (SUCCEEDED(status)) status = RegisterDragDrop(drop_window, target);
    if (FAILED(status)) {
        RegisterDragDrop(drop_window, original);
        target->Release(); attach_failure(static_cast<LONG>(status)); return;
    }
    installed_target = target; target->Release();
    shared->attached = 1; MemoryBarrier(); shared->state = 1;
}

void detach() {
    if (!shared || !installed_target || GetCurrentThreadId() != owner_thread) return;
    if (GetPropW(drop_window, L"OleDropTargetInterface") != installed_target) {
        shared->error = 3; return;  // Preserve another owner's replacement.
    }
    HRESULT status = RevokeDragDrop(drop_window);
    if (SUCCEEDED(status)) status = RegisterDragDrop(drop_window, original_target);
    if (SUCCEEDED(status)) {
        installed_target = nullptr; original_target->Release(); original_target = nullptr;
        shared->detached = 1; MemoryBarrier(); shared->state = 2;
        close_mapping();
    } else { shared->error = static_cast<LONG>(status); }
}
}

extern "C" __declspec(dllexport) LRESULT CALLBACK gd_owned_browser_callwndproc(int code, WPARAM wparam, LPARAM lparam) {
    if (code >= 0 && lparam) {
        const auto message = reinterpret_cast<CWPSTRUCT*>(lparam);
        if (message->message == RegisterWindowMessageW(message_name)) {
            if (message->wParam) attach(message->hwnd, static_cast<DWORD>(message->wParam), static_cast<ATOM>(message->lParam));
            else detach();
        }
    }
    return CallNextHookEx(nullptr, code, wparam, lparam);
}

extern "C" __declspec(dllexport) DWORD WINAPI gd_owned_browser_shared_size() { return sizeof(GDOwnedDropShared); }

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) module = instance;
    return TRUE;
}
