# 五分鐘展示指南

## 展示目標

說明如何把一份 Python requirements 轉成漏洞報告，並找到符合指定
Python／平台條件的升級候選。這個版本是後端 MVP；AI 說明尚未實作。

## 展示前準備

1. 在 repo 根目錄依 README 安裝後端依賴。
2. 啟動後端，保留終端機：

   ```powershell
   .\.venv-mvp\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --reload
   ```

3. 打開 http://127.0.0.1:8000/docs，確認 POST `/api/v1/scan` 存在。
4. 打開 GitHub Actions 頁面，準備展示已通過的執行紀錄。
5. 備妥 `examples/scan-report.snapshot.json`，網路失敗時可展示保存結果，
   但要清楚說明這是快照，而非當場成功的查詢。

範例的舊套件只作為掃描文字，不需要安裝。

## 0:00–1:00：說明問題與輸入

可以這樣介紹：

> 開發者除了需要知道依賴有哪些已知漏洞，也需要知道修補版本是否適合
> 自己的 Python 與執行平台。這個 API 把漏洞與升級候選查驗串成一個流程。

展開 POST `/api/v1/scan`，點 Try it out，貼上
`examples/scan-request.json`。說明 target_python 是使用者的目標環境，
不是伺服器的 Python；win_amd64 代表 Windows x64。

## 1:00–2:00：執行與解讀統計

按 Execute，看 Server response 的實際狀態碼與 Response body，
不要把頁面底部的 Example Value 當成實際結果。

保存的範例有 3 個套件、8 筆漏洞。即時數量可能隨資料更新而變動。
這些數字描述輸入的原版本；系統回傳建議後，原版本漏洞數不會消失。

## 2:00–3:00：漏洞與 CVSS

挑一筆 requests 漏洞，展示 CVE、aliases、cvss_score、cvss_vector。
說明 CVE／GHSA／PYSEC 可能是同一漏洞的不同資料庫編號，已合併處理。
CVSS 是漏洞嚴重程度依據，並非整個專案的風險分數。

## 3:00–4:00：NumPy 候選搜尋

展示 NumPy 的 checked_versions 和 release_checks。保存結果中：

- 1.22：沒有符合目標的 wheel，狀態 no_compatible_wheel。
- 1.26.0：Python 條件與 wheel 標記符合，OSV 沒有查到已知漏洞。
- candidate_source=pypi_release、expanded_search=true：代表修補邊界未通過後，
  系統繼續從 PyPI 尋找其他穩定版本。

說明 `remaining_vulnerability_ids=null` 是未成功完成該候選 OSV 查驗；
空清單 `[]` 才是已查詢且沒有回傳漏洞。

Flask 的 major_upgrade=true 提醒這是跨主要版本的升級候選。

## 4:00–5:00：可信度與限制

展示 GitHub Actions 的 Python 3.11、3.12 通過紀錄，並說明本機有 102 個
離線測試，涵蓋外部服務失敗與相容性判斷。CI 成功不代表每次即時查詢
都成功，也不代表升級後的應用程式已通過測試。

最後說明目前尚未驗證跨套件依賴衝突、實際安裝或程式運作。
這些將是下一階段；目前不宣稱有前端、資料庫或 AI Agent。

## 常見問題

| 現象 | 處理方式 |
|---|---|
| `/` 顯示 Not Found | 使用 `/docs`；根網址沒有頁面 |
| `/scan/parse` 回傳缺少 content | 批次掃描選 `/scan`，輸入欄位用 requirements |
| 422 | 查看 detail：確認固定版本、完整 Python 版本與支援的平台 |
| 502 | 原版本 OSV 查詢失敗；查看網路與服務狀態後重試 |
| verification_failed | 候選查驗失敗；原版本漏洞報告仍有效 |
| manual_review | 查看拒絕紀錄；可能沒有修補資訊或已用完候選額度 |
| 結果與快照不同 | 即時資料會更新，快照只記錄一次查詢 |

## 保存與 CI

```powershell
git add README.md docs backend
git commit -m "feat: check direct dependency constraints"
git push -u origin feature/direct-dependency-check
```

到 GitHub Actions 確認這次執行結果。展示時以實際綠色通過紀錄為準。

第一版 MVP 已合併到 main，main 的 CI 已通過。後續功能在 feature
分支提交，推送後建立到 main 的 PR；查看差異與 CI，再合併。

## 新增：直接依賴條件檢查

在請求加入 `"check_dependencies": true`。展示頂層 dependency_check，
說明 selected_versions 是所有套件採用候選後的計畫。三套件範例未提供
Flask、Requests 的所有依賴，通常會是 incomplete；這是未完整解析，
不是已證明有衝突。conflict 才表示某個選定版本違反直接依賴條件。
unknown 表示資料或環境條件不足。這版不會安裝套件或做完整 resolver。
