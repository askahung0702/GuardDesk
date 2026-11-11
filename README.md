# GuardDesk

GuardDesk 是以 Windows 端點管理為主的開發專案，包含管理中心、全機 Agent、MIS 遠端協助工具、原生 Windows 元件與瀏覽器擴充。

**本 repository 提供經去識別化整理的原始碼與開發工具，不提供可直接部署的正式安裝包。** 參照功能基線為 `0.4.105 / 001`；公開來源經過範例資料與文件整理，與內部歷史成品的位元組不相同，也不繼承其現場驗收結論。

## 主要功能與架構

| 元件 | 技術與用途 |
| --- | --- |
| 管理中心 | Python、SQLite、Web 管理介面；端點註冊、群組、政策、稽核查詢與更新管理 |
| 端點 Agent | Python 協調程式及原生 Windows 服務；全機元件與使用者工作階段分離 |
| MIS 遠端協助 | Windows 桌面工具；原生視窗、DXGI 擷取、H.264／WebRTC 與鍵鼠控制 |
| 原生元件 | C++／Win32；服務、管道、桌面／UAC 邊界與文件稽核元件 |
| 瀏覽器擴充 | JavaScript；搭配政策與原生接點的瀏覽器相關功能 |
| MSI 派送 | 經驗證的 MSI 安裝流程；不提供任意 EXE 或 Shell 派送 |

遠端協助保留端點使用者同意、管理角色、授權時效、撤銷、會話與桌面世代驗證。具備原始碼不代表已在所有顯示卡、Windows 版本、UAC 或防護政策下完成驗收。

## 目錄

```text
source/          管理中心、Agent、MIS、C++、擴充及測試原始碼
dev/             環境建立、受控 stage、測試與完整打包入口
dependencies/    Python wheel hash、原生工具鏈與相依鎖定
doc/             公開開發指南、架構與安全／工程準則
config/          範例設定及元件分類
licenses/        第三方授權文字與來源材料
provenance/      本公開來源快照的完整性與整理說明
Build-Management.cmd   完整管理中心打包入口
```

`runtime/`、`dist/`、venv、WebRTC checkout、資料庫、帳密、私鑰、現場診斷與安裝成品不納入 Git。

## 開始開發

環境：**Windows x64、CPython 3.13**，包含 pip、venv 與 Tcl/Tk。日常編輯與單元測試使用一般帳戶，不需要先安裝 Agent 或啟動管理中心。

```powershell
git clone https://github.com/askahung0702/GuardDesk.git
cd GuardDesk

# 明確選擇從官方 PyPI 取得鎖定的開發套件
python dev/bootstrap.py --download

python dev/develop.py check
python dev/develop.py test
python -m unittest discover -s dev/tests -v
```

離線環境可將 bootstrap 改成：

```powershell
python dev/bootstrap.py --wheelhouse C:\ApprovedWheels
```

請修改 **`source/`**，不要修改自動產生的 `runtime/remote-next-src`。完整原生建置還需要鎖定版本的 Visual Studio Build Tools、Windows SDK、WebRTC 及其工具鏈，見[建置指南](doc/development/BUILD.md)。

## 打包與驗收

`Build-Management.cmd` 是固定的完整管理中心打包入口，使用新版本號、匹配的原生 cohort、相依鎖定、來源／成品測試及正常 Defender 掃描；失敗即停止，禁止拿舊成功成品頂替或覆寫已封存版本。

**公開 repository 不包含歷史私有基線成品與驗收收據。** 因此新 checkout 可以進行來源開發與文件所列的離線測試，但不保證僅執行一個指令就能產生完整發布包。完整打包的歷史完整性 gate 若缺少授權 artifact，會停止；不能建立假收據或關掉檢查繞過。原生編譯成功與單元測試通過，也不等於正式簽章、端點安裝／更新、實際 UAC 或跨機效能驗收。

參照基線與公開快照分別記錄在 `CURRENT-BASELINE.json`、`DEVELOPMENT-BASELINE.json` 及 `provenance/source-provenance.json`；建置不會自動升訂版或部署。

## 安全與公開資料範圍

- 不停用 Defender、EDR、AMSI、SmartScreen、UAC 或執行政策，不自動建立防毒排除。
- 特權元件只接受經驗證的固定操作，不執行一般使用者可修改的特權程式／設定。
- 範例使用虛構裝置、帳號與網路資料；請自行建立實際環境設定，不提交真實憑證或現場資料。
- 歷史維護／實驗工具保留作工程參考，不是日常執行清單；請勿直接對實際端點批次執行。
- 不要對本 repository 執行全部 `source/tests` 的無差別 discover；部分測試會建立完整中心、操作 Windows 或需要外部測試機。使用文件指定的分層入口。

更多資料：[開發入口](doc/development/README.md) · [架構](doc/development/COMPONENTS.md) · [建置](doc/development/BUILD.md) · [測試](doc/development/TESTING.md) · [安全準則](doc/11-security-and-defender-guidelines.md) · [公開整理範圍](doc/PUBLIC-SOURCE.md)

## 授權狀態

本次沒有新增第一方開源授權條款。第三方元件的既有授權與聲明保留於 `licenses/`、`source/THIRD_PARTY_NOTICES.md` 及相依套件中；公開來源不代表所有相依或第一方程式自動採同一授權。

---

**English:** Windows endpoint-management development sources, including a Python management center, endpoint orchestration, native Windows services, native remote assistance and browser extensions. This is a sanitized source snapshot, not a certified or production-ready binary release. Start with the development guide; private historical release artifacts and field evidence are intentionally not distributed.
