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

展示 GitHub Actions 的 Python 3.11、3.12 通過紀錄，並說明本機有 136 個
離線測試，涵蓋外部服務失敗與相容性判斷。CI 成功不代表每次即時查詢
都成功，也不代表升級後的應用程式已通過測試。

最後說明目前尚未驗證跨套件依賴衝突、實際安裝或程式運作。
這些將是下一階段；目前有本機前端，尚未有資料庫或 AI Agent。

## 常見問題

| 現象 | 處理方式 |
|---|---|
| 首頁沒有出現 | 確認已切換到新增前端的版本，並重新啟動後端 |
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


## 網站展示

啟動方式不變，直接開 http://127.0.0.1:8000/。點「載入範例」，確認
Python 與平台後按「開始安全掃描」。依序展示統計、候選來源、漏洞表格、
依賴條件明細與 JSON 下載。可選文字檔以示範檔案輸入；不用安裝其中套件。
掃描錯誤會顯示在輸入區，上一份結果會隱藏。網站僅供本機操作，尚未部署。


## 升級草案與新手操作

1. 開啟首頁，第一次使用可按「載入範例」。首頁預設英文，可在右上角切換五種語言。
2. 點「開始安全掃描」。不確定 Python 與平台時可保留空白，這表示沒有做對應的相容性查驗。
3. 要示範 Python 3.12 / Windows x64 的 NumPy 候選搜尋，先展開選用設定並指定環境。
4. 檢視升級草案的「原版本 → 草案版本」、提醒及下一步。資訊不完整不等於安裝失敗。
5. 下載 `requirements.proposed.txt`，打開確認版本與檔頭提醒。這不是 lockfile，請先在獨立環境測試。
6. 展開技術明細，可查看原始漏洞、依賴條件與候選查驗證據。

## 啟用與展示本機 AI

預設使用 Ollama 的本機 `qwen3:4b`，不需要 OpenAI 金鑰。
保持 Ollama 執行中，重啟 FastAPI 並重新整理網頁。
掃描完成後，AI 區塊會標示本機模型；按「用 AI 解釋這份報告」。
第一次載入模型可能較慢。建議用三套件範例開始。
回應會列出摘要、套件測試重點與引用的漏洞編號。
本機服務離線或模型未安裝時會顯示原因，啟動後可按「重新確認」。
Ollama 失敗不會自動轉到 OpenAI；掃描與下載仍可使用。

如要更改模型，可在專案根目錄 `.env` 設定：

```dotenv
AI_PROVIDER=ollama
OLLAMA_MODEL=qwen3:4b
```

`AI_PROVIDER=openai` 才使用 OpenAI 金鑰與 API 計費，`AI_PROVIDER=none` 停用 AI。
雲端 Ollama 模型不接受；本機模型會使用電腦記憶體與運算資源。
AI 不改下載版本、不安裝套件、不保證建議文字正確。請對照掃描證據。
