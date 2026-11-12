# 開發入口

先讀根目錄README、AGENTS、DEVELOPMENT-BASELINE與CURRENT-BASELINE，以及安全準則與工程回歸文件。

source/是唯一產品編輯入口；dev工具核對既有stage未被人工修改，才同步至runtime/remote-next-src。venv、wheel cache及測試結果都留在runtime，不提交。

先建立Windows x64 CPython 3.13環境，再依README執行bootstrap、靜態檢查、指定單元回歸及dev工具回歸。不要直接discover所有source/tests，亦不要執行歷史維護工具或啟動完整中心作為入門步驟。

參照基線0.4.108/001不是本公開來源的二進位驗收。本公開快照有去識別化差異；不要把其hash當作私有封存成品hash。

[模組](COMPONENTS.md) · [建置](BUILD.md) · [測試](TESTING.md) · [版本控管](SVN.md) · [公開範圍](../PUBLIC-SOURCE.md)
