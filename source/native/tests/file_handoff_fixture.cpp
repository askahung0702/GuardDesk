// Self-owned COM fixture, not a Chrome/Edge adapter or a physical-input test.
#include "../file_handoff.h"
#include <shellapi.h>
#include <shlobj.h>
#include <cstring>
#include <vector>

namespace {
volatile LONG get_data_calls = 0;
class Data final : public IDataObject {
    LONG refs_ = 1;
    std::vector<BYTE> bytes_;
public:
    Data(const WCHAR* const* paths, DWORD count, DWORD malformed) {
        size_t chars = count ? 1 : 2;
        for (DWORD i = 0; i < count; ++i) chars += wcslen(paths[i]) + 1;
        bytes_.resize(sizeof(DROPFILES) + chars * sizeof(WCHAR), 0);
        auto header = reinterpret_cast<DROPFILES*>(bytes_.data());
        header->pFiles = sizeof(DROPFILES); header->fWide = TRUE;
        auto cursor = reinterpret_cast<WCHAR*>(bytes_.data() + sizeof(DROPFILES));
        for (DWORD i = 0; i < count; ++i) { size_t len = wcslen(paths[i]); memcpy(cursor, paths[i], (len + 1) * sizeof(WCHAR)); cursor += len + 1; }
        if (malformed == 1) header->pFiles = 0xffffffff;
        if (malformed == 2) header->fWide = FALSE;
        if (malformed == 3) bytes_.resize(sizeof(DROPFILES) + sizeof(WCHAR));
        if (malformed == 4) memset(bytes_.data() + sizeof(DROPFILES), 'A', bytes_.size() - sizeof(DROPFILES));
        if (malformed == 5) header->pFiles = sizeof(DROPFILES) + 1;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (id != IID_IUnknown && id != IID_IDataObject) return E_NOINTERFACE;
        *output = static_cast<IDataObject*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }
    ULONG STDMETHODCALLTYPE Release() override { auto value = InterlockedDecrement(&refs_); if (!value) delete this; return value; }
    HRESULT STDMETHODCALLTYPE GetData(FORMATETC* format, STGMEDIUM* output) override {
        InterlockedIncrement(&get_data_calls);
        if (!output || QueryGetData(format) != S_OK) return DV_E_FORMATETC;
        auto handle = GlobalAlloc(GMEM_MOVEABLE, bytes_.size()); if (!handle) return E_OUTOFMEMORY;
        auto dest = GlobalLock(handle); if (!dest) { GlobalFree(handle); return E_OUTOFMEMORY; }
        memcpy(dest, bytes_.data(), bytes_.size()); GlobalUnlock(handle);
        *output = {}; output->tymed = TYMED_HGLOBAL; output->hGlobal = handle; return S_OK;
    }
    HRESULT STDMETHODCALLTYPE QueryGetData(FORMATETC* f) override {
        return f && f->cfFormat == CF_HDROP && f->dwAspect == DVASPECT_CONTENT && f->lindex == -1 && (f->tymed & TYMED_HGLOBAL) ? S_OK : DV_E_FORMATETC;
    }
    HRESULT STDMETHODCALLTYPE GetDataHere(FORMATETC*, STGMEDIUM*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetCanonicalFormatEtc(FORMATETC*, FORMATETC*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetData(FORMATETC*, STGMEDIUM*, BOOL) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE EnumFormatEtc(DWORD, IEnumFORMATETC**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE DAdvise(FORMATETC*, DWORD, IAdviseSink*, DWORD*) override { return OLE_E_ADVISENOTSUPPORTED; }
    HRESULT STDMETHODCALLTYPE DUnadvise(DWORD) override { return OLE_E_ADVISENOTSUPPORTED; }
    HRESULT STDMETHODCALLTYPE EnumDAdvise(IEnumSTATDATA**) override { return OLE_E_ADVISENOTSUPPORTED; }
};
class Receiver final : public IDropTarget {
    LONG refs_ = 1; DWORD effect_; HRESULT result_;
    IDataObject* entered_ = nullptr;
    bool read_on_enter_;
    void read(IDataObject* data) {
        FORMATETC format{CF_HDROP, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL}; STGMEDIUM medium{};
        if (SUCCEEDED(data->GetData(&format, &medium))) ReleaseStgMedium(&medium);
    }
public:
    Receiver(DWORD effect, HRESULT result, bool read_on_enter) : effect_(effect), result_(result), read_on_enter_(read_on_enter) {}
    ~Receiver() { if (entered_) entered_->Release(); }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void** output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (id != IID_IUnknown && id != IID_IDropTarget) return E_NOINTERFACE;
        *output = static_cast<IDropTarget*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }
    ULONG STDMETHODCALLTYPE Release() override { auto value = InterlockedDecrement(&refs_); if (!value) delete this; return value; }
    HRESULT STDMETHODCALLTYPE DragEnter(IDataObject* data, DWORD, POINTL, DWORD* effect) override {
        if (entered_) entered_->Release();
        entered_ = data; entered_->AddRef();
        if (read_on_enter_) read(data);
        *effect = effect_; return S_OK;
    }
    HRESULT STDMETHODCALLTYPE DragOver(DWORD, POINTL, DWORD* effect) override { *effect = effect_; return S_OK; }
    HRESULT STDMETHODCALLTYPE DragLeave() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Drop(IDataObject* data, DWORD, POINTL, DWORD* effect) override {
        // A real cooperating receiver requests its normal path metadata.
        if (entered_ != data) return E_UNEXPECTED;
        if (result_ == S_OK && effect_) {
            if (!read_on_enter_) read(data);
        }
        *effect = effect_; return result_;
    }
};
BOOL WINAPI origin(void* context, WCHAR* out, DWORD capacity) {
    auto value = static_cast<const WCHAR*>(context);
    if (!value || wcslen(value) >= capacity) return FALSE;
    wcscpy_s(out, capacity, value); return TRUE;
}
extern "C" __declspec(dllexport) LONG WINAPI gd_fixture_get_data_calls() { return InterlockedCompareExchange(&get_data_calls, 0, 0); }
}
static HRESULT run(const WCHAR* const* paths, DWORD count,
    const WCHAR* site, DWORD effect, HRESULT result, BOOL cancel_before_drop, BOOL read_on_enter, DWORD malformed, bool wrapped) {
    if (count > 33 || (count && !paths)) return E_INVALIDARG;
    for (DWORD i = 0; i < count; ++i) if (!paths[i] || wcslen(paths[i]) > 5000) return E_INVALIDARG;
    auto receiver = new Receiver(effect, result, read_on_enter != FALSE);
    IDropTarget* wrapper = nullptr;
    HRESULT hr = S_OK;
    if (wrapped) hr = gd_handoff_wrap(receiver, origin, const_cast<WCHAR*>(site), &wrapper);
    else { wrapper = receiver; wrapper->AddRef(); }
    receiver->Release(); if (FAILED(hr)) return hr;
    auto data = new Data(paths, count, malformed); DWORD actual = effect; POINTL point{};
    wrapper->DragEnter(data, 0, point, &actual);
    if (cancel_before_drop) hr = wrapper->DragLeave();
    else hr = wrapper->Drop(data, 0, point, &actual);
    data->Release(); wrapper->Release(); return hr;
}
extern "C" __declspec(dllexport) HRESULT WINAPI gd_fixture_drop(const WCHAR* const* paths, DWORD count,
    const WCHAR* site, DWORD effect, HRESULT result, BOOL cancel_before_drop, BOOL read_on_enter, DWORD malformed) {
    return run(paths, count, site, effect, result, cancel_before_drop, read_on_enter, malformed, true);
}
extern "C" __declspec(dllexport) HRESULT WINAPI gd_fixture_drop_direct(const WCHAR* const* paths, DWORD count,
    const WCHAR* site, DWORD effect, HRESULT result, BOOL cancel_before_drop, BOOL read_on_enter, DWORD malformed) {
    return run(paths, count, site, effect, result, cancel_before_drop, read_on_enter, malformed, false);
}
