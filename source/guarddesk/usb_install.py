"""One UAC entry with bounded, redacted diagnostics returned to the caller."""
import collections
import ctypes
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

SCRIPT = Path(__file__).with_name('windows') / 'install-usb.ps1'

MESSAGES = {
    'script_policy': '選用控制所需的 PowerShell 腳本遭執行政策阻擋。請 MIS 核對有效政策與公司核准方式；Restricted 禁止所有腳本，單純簽章仍不足。請保留原端點資料。',
    'access_denied': 'Windows 拒絕存取或既有安裝權限不符。請 MIS 查看下方診斷；保留既有目錄與身分，不要刪除重裝。',
    'connection': '受保護元件無法連線或驗證 Server。確認公司網路、Server 與憑證後，雙擊同一個 Setup-Endpoint.cmd 重試。',
    'native_failed': '受保護元件安裝未完成。已保留端點身分；請 MIS 查看下方診斷，處理後雙擊同一個 Setup-Endpoint.cmd 重試。',
    'completed': '受保護元件安裝完成。',
}

class InstallError(OSError):
    def __init__(self, report):
        self.report = report
        super().__init__(MESSAGES.get(report.get('code'), MESSAGES['native_failed']) + '\n' + report.get('detail', '')[:5000])


def diagnostic(code, text='', settings=None):
    # Redact before truncating: a partial credential must not survive.
    text = str(text)
    if not isinstance(settings, dict): settings = {}
    for key in ('token', 'update_key', 'deployment_code', 'password', 'client_secret'):
        value = (settings or {}).get(key)
        if isinstance(value, str) and value: text = text.replace(value, '[REDACTED]')
    text = re.sub(r'(?i)(Bearer\s+)[^\s"\x27]+', r'\1[REDACTED]', text)
    text = ''.join(c for c in text if c in '\n\t' or ord(c) >= 32)
    lower = text.casefold()
    category = 'completed' if code == 0 else 'native_failed'
    if code:
        if any(s in lower for s in ('pssecurityexception', 'not digitally signed', 'execution policies', 'about_execution_policies', 'running scripts is disabled', '未經數位簽署', '數位簽章', '禁止執行指令碼')): category = 'script_policy'
        elif any(s in lower for s in ('access is denied', 'access denied', 'permissionerror', '拒絕存取', '擁有者', '可由一般使用者改寫')): category = 'access_denied'
        elif any(s in lower for s in ('certificate_verify_failed', 'connectionerror', 'urlopen error', 'timed out', '連線', '憑證')): category = 'connection'
    stages = re.findall(r'GUARDDESK_STAGE=([a-z_]+)', text)
    return {'format': 1, 'code': category, 'exit_code': int(code), 'stage': stages[-1] if stages else 'powershell_start', 'detail': text[-5000:]}


def validate_report(report, exit_code):
    if (not isinstance(report, dict) or set(report) != {'format', 'code', 'exit_code', 'stage', 'detail'} or
        type(report['format']) is not int or report['format'] != 1 or not isinstance(report['code'], str) or report['code'] not in MESSAGES or type(report['exit_code']) is not int or
        report['exit_code'] != exit_code or not isinstance(report['stage'], str) or len(report['stage']) > 50 or
        not isinstance(report['detail'], str) or len(report['detail']) > 5000 or
        (exit_code == 0) != (report['code'] == 'completed')):
        raise OSError('安裝診斷與程序結果不符；未宣告完成。請保留目前身分並交 MIS 檢查。')
    return report


def powershell_path():
    from ctypes import wintypes as w
    system = ctypes.WinDLL('kernel32', use_last_error=True)
    system.GetSystemDirectoryW.argtypes = [w.LPWSTR, w.UINT]
    buffer = ctypes.create_unicode_buffer(32768); length = system.GetSystemDirectoryW(buffer, len(buffer))
    if not length or length >= len(buffer): raise OSError('無法取得 Windows 系統路徑')
    return Path(buffer.value) / 'WindowsPowerShell/v1.0/powershell.exe'


def run_script(config, action, source):
    """Honor script policy, including failures before the script starts."""
    script = SCRIPT
    if not script.is_file(): raise OSError('安裝包缺少內部安裝元件，請從新版管理中心重新下載完整端點安裝包。')
    settings = json.loads(Path(config).read_text(encoding='utf-8-sig'))
    arguments = [str(powershell_path()), '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(script),
                 '-Action', action, '-SourceDirectory', str(source), '-SourceConfig', str(config)]
    chunks = collections.deque(maxlen=16)  # At most 64 KiB, not an unlimited transcript.
    total = [0]
    child = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    def drain():
        while block := child.stdout.read1(4096):
            total[0] += len(block); chunks.append(block)
    reader = threading.Thread(target=drain, daemon=True); reader.start()
    try: code = child.wait()
    finally: reader.join(5); child.stdout.close()
    raw = b''.join(chunks)
    if total[0] > sum(map(len, chunks)):
        # Drop the leading partial line before redacting so a split token at
        # the bounded ring's edge cannot leak its suffix.
        raw = raw.partition(b'\n')[2]
    try: text = raw.decode('utf-8-sig')
    except UnicodeDecodeError: text = raw.decode('mbcs' if os.name == 'nt' else 'utf-8', errors='replace')
    return diagnostic(code, text, settings)


def run_native(config, action, source,*,remote_test=False):
    from .native_installer import install as native_install
    settings = json.loads(Path(config).read_text(encoding='utf-8-sig'))
    try:
        if remote_test:native_install(config,action,source,remote_test=True)
        else:native_install(config, action, source)
        message=('GUARDDESK_STAGE=check_complete\nLAB01 測試前檢查完成，未修改端點' if remote_test and action=='Status'
                 else 'GUARDDESK_STAGE=complete\nWindows 原生安裝完成')
        return diagnostic(0,message,settings)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        report = diagnostic(1, str(exc), settings)
        if report['stage'] == 'powershell_start': report['stage'] = 'native_installer'
        return report


def helper(config, action, pipe,*,remote_test=False):
    from .windows_privilege import is_admin
    from .installer_channel import connect, send
    from .single_instance import machine_instance
    if not is_admin(): raise PermissionError('此步驟需要安裝入口提出的 Windows UAC。請直接雙擊 Setup-Endpoint.cmd。')
    if action not in ('Install', 'Uninstall', 'Status'): raise ValueError('安裝動作不正確')
    channel = connect(pipe)  # Connect before any machine changes; diagnostics only.
    settings = {}
    try:
        try:
            config = Path(config).resolve(strict=True)
            if config.stat().st_size > 65536: raise ValueError('端點設定過大')
            settings = json.loads(config.read_text(encoding='utf-8-sig'))
            if not isinstance(settings, dict): raise ValueError('端點設定格式不正確')
            did = settings.get('device_id', '')
            if not isinstance(did, str) or not re.fullmatch('[0-9a-f]{24}', did): raise ValueError('端點識別碼不正確')
            source = Path(sys.executable).resolve().parent
            if not getattr(sys, 'frozen', False): raise ValueError('請使用完整 Windows 安裝包')
            print('GuardDesk：正在安裝受保護元件，請稍候。原本的安裝視窗會顯示結果。', flush=True)
            with machine_instance('endpoint-install', did):
                report=run_native(config,action,source,remote_test=True) if remote_test else run_native(config,action,source)
        except (OSError, ValueError) as exc: report = diagnostic(1, str(exc), settings)
        send(channel, report)
        return report['exit_code']
    finally: channel[0].CloseHandle(channel[1])


def elevate(config, action, source, timeout=600,*,remote_test=False):
    from ctypes import wintypes as w
    from .installer_channel import Receiver
    receiver = Receiver()
    class Info(ctypes.Structure):
        _fields_ = [('cbSize', w.DWORD), ('fMask', w.ULONG), ('hwnd', w.HWND), ('lpVerb', w.LPCWSTR), ('lpFile', w.LPCWSTR), ('lpParameters', w.LPCWSTR), ('lpDirectory', w.LPCWSTR), ('nShow', ctypes.c_int), ('hInstApp', w.HINSTANCE), ('lpIDList', w.LPVOID), ('lpClass', w.LPCWSTR), ('hkeyClass', w.HKEY), ('dwHotKey', w.DWORD), ('hIcon', w.HANDLE), ('hProcess', w.HANDLE)]
    shell = ctypes.WinDLL('shell32', use_last_error=True); system = ctypes.WinDLL('kernel32', use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(Info)]; shell.ShellExecuteExW.restype = w.BOOL
    system.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]; system.WaitForSingleObject.restype = w.DWORD
    system.GetExitCodeProcess.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]; system.CloseHandle.argtypes = [w.HANDLE]
    arguments = ['endpoint-native-install', '--config', str(config), '--action', action, '--diagnostic-pipe', receiver.name]
    if remote_test:arguments.append('--lab01-remote-test')
    info = Info(); info.cbSize = ctypes.sizeof(info); info.fMask = 0x40; info.lpVerb = 'runas'; info.lpFile = str(source / installer_name())
    info.lpParameters = subprocess.list2cmdline(arguments); info.lpDirectory = str(source); info.nShow = 1
    try:
        if not shell.ShellExecuteExW(ctypes.byref(info)):
            error = ctypes.get_last_error()
            if error == 1223: raise PermissionError('Windows UAC 已取消。註冊身分已保存；雙擊同一個 Setup-Endpoint.cmd 即可重試。')
            raise ctypes.WinError(error)
        deadline = time.monotonic() + timeout; report = None; notice = time.monotonic() + 15
        while True:
            if report is None: report = receiver.poll()
            wait = system.WaitForSingleObject(info.hProcess, 100)
            if wait == 0: break
            if wait != 258: raise OSError('無法取得安裝程序狀態；未宣告完成。')
            if time.monotonic() >= deadline:
                raise OSError('安裝超過 10 分鐘，可能仍在處理；未強制停止或宣告完成。請 MIS 檢查 GuardDesk 安裝視窗，結束前不要重複安裝。')
            if time.monotonic() >= notice:
                print('仍在安裝受保護元件，請稍候；不要關閉安裝視窗。', flush=True); notice = time.monotonic() + 15
        if report is None: report = receiver.poll()
        code = w.DWORD()
        if not system.GetExitCodeProcess(info.hProcess, ctypes.byref(code)): raise ctypes.WinError(ctypes.get_last_error())
        if report is None: raise OSError(f'安裝程序未提供診斷（Windows 結束代碼 {code.value}）。請 MIS 檢查 App Control／Defender 事件；不要刪除原註冊。')
        return validate_report(report, code.value)
    finally:
        if info.hProcess: system.CloseHandle(info.hProcess)
        receiver.close()


def install(config, action='Install', source=None):
    if os.name != 'nt': raise OSError('USB 安裝只適用於 Windows')
    if action not in ('Install', 'Uninstall', 'Status'): raise ValueError('安裝動作不正確')
    config = Path(config).resolve()
    if not config.is_file(): raise ValueError('請先註冊端點或啟動本機 demo')
    source = Path(source).resolve() if source else (Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[1] / 'dist/GuardDesk')
    if not (source / 'GuardDesk.exe').is_file(): raise ValueError('請先建立或解壓縮完整 Windows 執行包')
    from .windows_privilege import is_admin
    report = run_native(config, action, source) if is_admin() else elevate(config, action, source)
    if report['exit_code']: raise InstallError(report)
    return {'status': 'installer_completed', 'action': action}


def installer_name():
    from .remote_trial import enabled
    return 'GuardDeskInstaller.exe' if enabled() else 'GuardDesk.exe'
