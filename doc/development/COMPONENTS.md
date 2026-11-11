# 模組分類與修改邊界

| 工作 | 來源入口 | 相鄰邊界 |
| --- | --- | --- |
| 中心／Web | source/guarddesk/server.py、fleet.py、store.py、static/ | TLS、角色、CSRF、查詢容量及狀態 |
| 政策／稽核／分類 | source/guarddesk/policy*、category*、audit*、event_storage.py | 端點相容投影、排除、索引與留存 |
| 端點／全機服務 | source/guarddesk/machine_agent*、native_usb.py；source/native/service | SYSTEM owner／管道DACL、登入／使用者helper |
| 安裝／更新／移除 | source/guarddesk/native_installer.py、endpoint_setup.py、update*、removal*、endpoint_retire.py | 原身分、交易、容量、ACL、程序停止與結果 |
| MIS及遠端協調 | source/guarddesk/mis*、remote* | 同意、撤權、會話生命週期，與原生版本成套 |
| 原生遠端 | source/native/remote、webrtc/ | DXGI、H.264／WebRTC、輸入、桌面／UAC、窗口及協定 |
| 文件／瀏覽器 | source/native/document_trace.cpp、source/guarddesk/document*、source/browser-extension | ETW／SACL及已核准的收集／排除契約 |
| 建置／維護 | source/tools、dev | Python角色封裝、cohort、版本、來源與成品hash |

config/component-catalog.json逐檔列出分類。公開整理保留模組分工；歷史裝置相關檔名及其import已一致改為虛構範例。source/tests 是可維護的測試來源，不是應排除的測試資料。

歷史field／LAB01／競品研究工具保留作回歸線索，沒有列入每日入口；不能直接套用到新同事或正式端點。MeshCentral維持獨立備用工作線，沒有把尚未實作的整合當目前產品。
