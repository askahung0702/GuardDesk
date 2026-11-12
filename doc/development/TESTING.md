# 測試分層

1. `python dev/develop.py check`：離線來源、語法、檔案類型與祕密模式檢查，不啟動產品。
2. `python dev/develop.py test`：16組指定來源測試目標，共195項；未提供原生cohort fixture時允許明列的一項skip，其餘意外skip失敗。不能把194通過加1跳過說成195完整通過。
3. `python -m unittest discover -s dev/tests -v`：stage、版本／訂版保護、hash／ZIP拒絕、失敗停止、建置鎖、Defender判讀及CMD入口等工具回歸。
4. C++自有probe：依BUILD文件另行建置；不用其通過推定真SYSTEM、UAC、實際顯示卡或跨機效能已驗收。
5. 完整成品及外部整合：使用明確授權的外部Server／端點；不要在開發機自動啟動完整中心或對已安裝Agent測試。

source/tests還保留大量歷史、Windows、瀏覽器與整合測試，部分會起完整中心、操作OS或需要歷史成品。禁止直接對整個source/tests無差別discover。

公開快照的實際檢查與未驗收範圍記錄在provenance/publication.json。內部歷史測試結果不是此公開快照的測試結果；新增整理沒有取得正式簽章或防護相容資格。
