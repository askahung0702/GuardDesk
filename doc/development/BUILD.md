# 建置與打包

## Python環境

需要Windows x64 CPython 3.13（含pip、venv、Tcl/Tk）。`python dev/bootstrap.py --download`明確從官方PyPI下載鎖定wheels；離線使用`--wheelhouse <資料夾>`。12個依賴逐檔核對SHA256，安裝後核對distribution RECORD。不改全域Python或防護政策。

## 原生工具鏈

版本與官方來源在dependencies/toolchains.lock.json。Windows核心使用VS2019 Build Tools、MSVC14.29.30133與SDK10.0.19041.0；WebRTC路徑另需VS2026 Build Tools、MFC/ATL及文件鎖定的SDK／debugging tools。

```powershell
python dev/develop.py document
python dev/develop.py native
python dev/develop.py service
python dev/fetch_webrtc.py
# 明確允許官方來源下載與hooks時才執行下一行
python dev/fetch_webrtc.py --download
python dev/develop.py webrtc
python dev/develop.py assemble
python dev/develop.py notices
```

工具安裝需自行核准，腳本不自動安裝VS、不重啟。WebRTC會下載數GB；不當作日常單元回歸相依。native/service的自有測試不安裝服務；完整WebRTC建置會執行自有測試視窗，不等於擷取真人桌面或SYSTEM/UAC實機驗收。

## 完整管理中心

唯一入口是根目錄Build-Management.cmd，明確傳入新版本與修訂：

```cmd
Build-Management.cmd --version 0.4.106 --artifact-root C:\ApprovedArtifacts --check
Build-Management.cmd --version 0.4.106 --artifact-root C:\ApprovedArtifacts
```

版本須大於參照基線，輸出存在即停止。--check只核對前置。完整流程核對依賴、來源、notices、原生及service收據，組裝匹配cohort，執行來源回歸、完整EXE/MIS角色與PYZ門檻、容量／移除／MSI／升級／生命週期測試，最後驗證真正ZIP、NTFS、中文／空白路徑、CMD碼頁及正常Defender掃描。

輸出在dist，逐階段收據在runtime/management-build-*。不提權、不安裝Agent、不部署、不改基線或防護。掃描退出0也需有明確乾淨結果；不保證組織EDR／首次執行策略通過。

### 公開來源的歷史輸入限制

公開repository刻意不提供私有歷史二進位、原始基線來源封存與現場驗收收據。dependencies/release-inputs.lock.json等仍是完整性限制，不是缺件就可以重寫的成功宣告。缺少對應授權artifact時，完整打包會停止。此公開整理沒有完成新的全套發布包建置。

`--reuse-native-from <受控來源>`是明確的選擇，僅當來源／receipt／log／artifact hash完全相符時可重用；去識別化修改過的原生來源可能已與舊cache不符，應重建，不能修改lock硬放行。報告需標記重用，不稱本次重測。

不以修改歷史recipe、略過gate、加入Defender排除或混用DLL取得包。正式發布另需可信簽章及外部Server／端點生命週期、UAC、效能與組織防護驗收。
