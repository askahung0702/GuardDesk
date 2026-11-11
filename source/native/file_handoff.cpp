#define GD_HANDOFF_BUILD
#include "file_handoff.h"
#include <shellapi.h>
#include <shlobj.h>
#include <memory>
#include <new>
#include <cstring>

namespace {
SRWLOCK lock = SRWLOCK_INIT;
GDHandoffRecord ring[GD_HANDOFF_CAPACITY]{};
DWORD head = 0, used = 0;
volatile LONG64 lost = 0;

void gap(ULONGLONG count = 1) {
    InterlockedAdd64(&lost, static_cast<LONG64>(count));
}

struct Files {
    DWORD count = 0;
    WCHAR paths[GD_HANDOFF_FILES][GD_HANDOFF_PATH]{};
};

bool snapshot(const STGMEDIUM& medium, Files& files) {
    files.count = 0;
    if (medium.tymed != TYMED_HGLOBAL || !medium.hGlobal) return false;
    const SIZE_T size = GlobalSize(medium.hGlobal);
    if (size < sizeof(DROPFILES) + 2 * sizeof(WCHAR) ||
        size > sizeof(DROPFILES) + sizeof(WCHAR) * GD_HANDOFF_FILES * GD_HANDOFF_PATH + 2 * sizeof(WCHAR)) {
        return false;
    }
    // IDataObject is untrusted input. Validate the entire bounded string list
    // before asking shell32 to enumerate it. ANSI/virtual payloads are gaps.
    auto bytes = static_cast<const BYTE*>(GlobalLock(medium.hGlobal));
    if (!bytes) return false;
    const auto header = reinterpret_cast<const DROPFILES*>(bytes);
    bool valid = header->fWide && header->pFiles >= sizeof(DROPFILES) &&
        header->pFiles % sizeof(WCHAR) == 0 && header->pFiles <= size - 2 * sizeof(WCHAR);
    DWORD validated_count = 0;
    if (valid) {
        const auto start = reinterpret_cast<const WCHAR*>(bytes + header->pFiles);
        const SIZE_T available = (size - header->pFiles) / sizeof(WCHAR);
        SIZE_T cursor = 0;
        bool ended = false;
        while (cursor < available) {
            if (!start[cursor]) { ended = true; break; }
            const SIZE_T begin = cursor;
            while (cursor < available && start[cursor]) ++cursor;
            if (cursor == available || cursor - begin >= GD_HANDOFF_PATH || ++validated_count > GD_HANDOFF_FILES) {
                valid = false; break;
            }
            const SIZE_T length = cursor - begin;
            memcpy(files.paths[validated_count - 1], start + begin, length * sizeof(WCHAR));
            files.paths[validated_count - 1][length] = 0;
            ++cursor;
        }
        valid = valid && ended && validated_count > 0;
    }
    GlobalUnlock(medium.hGlobal);
    if (!valid) return false;
    // Parse/copy under the size bound instead of passing a mutable untrusted
    // HGLOBAL to an unbounded shell enumeration after validation.
    files.count = validated_count;
    return true;
}

// Observe only metadata that the receiver itself requests. An extra GetData
// call can synchronously block on the drag source and is deliberately avoided.
// The original STGMEDIUM and its ownership always pass back unchanged.
class DataProxy final : public IDataObject {
    volatile LONG references_ = 1;
    IDataObject* inner_;
    std::shared_ptr<Files> files_;
    DWORD owner_ = GetCurrentThreadId();
    void observe(FORMATETC* format, STGMEDIUM* medium, HRESULT result) {
        if (result == S_OK && format && medium && format->cfFormat == CF_HDROP &&
            format->dwAspect == DVASPECT_CONTENT && format->lindex == -1) {
            if (GetCurrentThreadId() == owner_) snapshot(*medium, *files_);
            // Off-thread observations do not become evidence. Drop reports a
            // gap if its receiving STA never obtained usable path metadata.
        }
    }
public:
    DataProxy(IDataObject* inner, std::shared_ptr<Files> files) : inner_(inner), files_(std::move(files)) { inner_->AddRef(); }
    ~DataProxy() { inner_->Release(); }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (id != IID_IUnknown && id != IID_IDataObject) return inner_->QueryInterface(id, out);
        *out = static_cast<IDataObject*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(InterlockedIncrement(&references_)); }
    ULONG STDMETHODCALLTYPE Release() override {
        auto value = static_cast<ULONG>(InterlockedDecrement(&references_));
        if (!value) delete this;
        return value;
    }
    HRESULT STDMETHODCALLTYPE GetData(FORMATETC* f, STGMEDIUM* m) override {
        HRESULT hr = inner_->GetData(f, m); observe(f, m, hr); return hr;
    }
    HRESULT STDMETHODCALLTYPE GetDataHere(FORMATETC* f, STGMEDIUM* m) override {
        HRESULT hr = inner_->GetDataHere(f, m); observe(f, m, hr); return hr;
    }
    HRESULT STDMETHODCALLTYPE QueryGetData(FORMATETC* f) override { return inner_->QueryGetData(f); }
    HRESULT STDMETHODCALLTYPE GetCanonicalFormatEtc(FORMATETC* a, FORMATETC* b) override { return inner_->GetCanonicalFormatEtc(a, b); }
    HRESULT STDMETHODCALLTYPE SetData(FORMATETC* f, STGMEDIUM* m, BOOL release) override { return inner_->SetData(f, m, release); }
    HRESULT STDMETHODCALLTYPE EnumFormatEtc(DWORD d, IEnumFORMATETC** out) override { return inner_->EnumFormatEtc(d, out); }
    HRESULT STDMETHODCALLTYPE DAdvise(FORMATETC* f, DWORD d, IAdviseSink* s, DWORD* c) override { return inner_->DAdvise(f, d, s, c); }
    HRESULT STDMETHODCALLTYPE DUnadvise(DWORD c) override { return inner_->DUnadvise(c); }
    HRESULT STDMETHODCALLTYPE EnumDAdvise(IEnumSTATDATA** out) override { return inner_->EnumDAdvise(out); }
};

void publish(const Files& files, const WCHAR* origin, DWORD effect, const GUID& operation,
             ULONGLONG occurred) {
    // The receiver's UI thread never waits for the consumer's lock, disk, IPC
    // or network. Contention/capacity loss stays visible in a monotonic counter.
    if (!TryAcquireSRWLockExclusive(&lock)) { gap(files.count); return; }
    if (files.count > GD_HANDOFF_CAPACITY - used) {
        ReleaseSRWLockExclusive(&lock); gap(files.count); return;
    }
    for (DWORD i = 0; i < files.count; ++i) {
        auto& record = ring[(head + used) % GD_HANDOFF_CAPACITY];
        record = {};
        record.abi = GD_HANDOFF_ABI; record.size = sizeof(record);
        record.operation = operation; record.occurred = occurred;
        record.process_id = GetCurrentProcessId(); record.thread_id = GetCurrentThreadId();
        record.file_index = i; record.file_count = files.count; record.effect = effect;
        wcscpy_s(record.path, files.paths[i]); wcscpy_s(record.origin, GD_HANDOFF_ORIGIN, origin);
        ++used;
    }
    ReleaseSRWLockExclusive(&lock);
}

class Target final : public IDropTarget {
    volatile LONG references_ = 1;
    IDropTarget* inner_;
    GDHandoffOrigin origin_;
    void* context_;
    std::shared_ptr<Files> files_;
    DataProxy* active_ = nullptr;
    IDataObject* original_ = nullptr;
    void clear() {
        if (active_) active_->Release();
        active_ = nullptr; original_ = nullptr; files_.reset();
    }
    void prepare(IDataObject* data) {
        clear();
        if (!data) return;
        try {
            files_ = std::make_shared<Files>();
            active_ = new DataProxy(data, files_); original_ = data;
        } catch (const std::bad_alloc&) { clear(); }
    }
public:
    Target(IDropTarget* inner, GDHandoffOrigin origin, void* context)
        : inner_(inner), origin_(origin), context_(context) { inner_->AddRef(); }
    ~Target() { clear(); inner_->Release(); }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void** result) override {
        if (!result) return E_POINTER;
        *result = nullptr;
        if (id != IID_IUnknown && id != IID_IDropTarget) return E_NOINTERFACE;
        *result = static_cast<IDropTarget*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(InterlockedIncrement(&references_)); }
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG value = static_cast<ULONG>(InterlockedDecrement(&references_));
        if (!value) delete this;
        return value;
    }
    HRESULT STDMETHODCALLTYPE DragEnter(IDataObject* data, DWORD keys, POINTL point, DWORD* effect) override {
        prepare(data);
        HRESULT result = inner_->DragEnter(active_ ? active_ : data, keys, point, effect);
        if (FAILED(result)) clear();
        return result;
    }
    HRESULT STDMETHODCALLTYPE DragOver(DWORD keys, POINTL point, DWORD* effect) override {
        return inner_->DragOver(keys, point, effect);
    }
    HRESULT STDMETHODCALLTYPE DragLeave() override {
        HRESULT result = inner_->DragLeave(); clear(); return result;
    }
    HRESULT STDMETHODCALLTYPE Drop(IDataObject* data, DWORD keys, POINTL point, DWORD* effect) override {
        // A cooperating receiver callback supplies context at the point of the
        // operation, before it can navigate as a consequence of accepting it.
        // Failure to collect evidence must not change the actual drop result.
        WCHAR origin[GD_HANDOFF_ORIGIN]{};
        const bool bound = origin_(context_, origin, GD_HANDOFF_ORIGIN) &&
            wmemchr(origin, 0, GD_HANDOFF_ORIGIN) && origin[0];
        if (original_ != data || !active_) prepare(data);
        auto files = files_;
        GUID operation{};
        const bool identity = SUCCEEDED(CoCreateGuid(&operation));
        HRESULT result = inner_->Drop(active_ ? active_ : data, keys, point, effect);
        if (result == S_OK && effect && (*effect & (DROPEFFECT_COPY | DROPEFFECT_MOVE | DROPEFFECT_LINK))) {
            if (bound && files && files->count && identity) {
                FILETIME stamp{}; GetSystemTimeAsFileTime(&stamp);
                ULARGE_INTEGER value{}; value.LowPart = stamp.dwLowDateTime; value.HighPart = stamp.dwHighDateTime;
                publish(*files, origin, *effect, operation, value.QuadPart);
            } else { gap(); }
        }
        clear();
        return result;
    }
};
}

DWORD WINAPI gd_handoff_abi() { return GD_HANDOFF_ABI; }
DWORD WINAPI gd_handoff_record_size() { return sizeof(GDHandoffRecord); }
HRESULT WINAPI gd_handoff_wrap(IDropTarget* inner, GDHandoffOrigin origin, void* context, IDropTarget** output) {
    if (!output) return E_POINTER;
    *output = nullptr;
    if (!inner || !origin) return E_INVALIDARG;
    auto target = new (std::nothrow) Target(inner, origin, context);
    if (!target) return E_OUTOFMEMORY;
    *output = target; return S_OK;
}
DWORD WINAPI gd_handoff_poll(GDHandoffRecord* records, DWORD capacity, ULONGLONG* losses) {
    if (!records || !capacity || capacity > GD_HANDOFF_CAPACITY || !losses) return 0;
    AcquireSRWLockExclusive(&lock);
    DWORD count = used < capacity ? used : capacity;
    for (DWORD i = 0; i < count; ++i) {
        records[i] = ring[head]; ring[head] = {};
        head = (head + 1) % GD_HANDOFF_CAPACITY; --used;
    }
    ReleaseSRWLockExclusive(&lock);
    *losses = static_cast<ULONGLONG>(InterlockedCompareExchange64(&lost, 0, 0));
    return count;
}
