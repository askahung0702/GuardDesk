# 版本控管

本公開副本使用 Git，remote 為 repository 自身。以小型 commit 記錄需求、影響範圍及實際測試。

若另使用 SVN，可將 `config/svn-global-ignores.txt` 套用至其工作副本；`dev/configure_svn.py --apply` 只設定目前 checkout 的忽略屬性，不會提交。本公開來源不帶其他版本庫的地址、帳號、歷史或憑證。

不提交 runtime、dist、venv、第三方 checkout、金鑰、資料庫、診斷或安裝成品。不要自動改寫換行或關鍵字，讓 hash 失去對應；發布成品放適當 artifact store，並分開記錄簽章及驗收。
