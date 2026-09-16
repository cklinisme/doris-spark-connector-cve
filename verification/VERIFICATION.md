# 修補版驗證結果

- 查核時間（UTC）：2026-09-16T17:17:17.909638+00:00
- 原始基準：Apache Doris Connector tag 26.1.0 / a25f7a1845760e45111e7eccac2f4087601cd563
- 目標：Java / Spark 3.5.1 / Scala 2.12；本機使用 JDK 11 驗證。
- 單元測試：91 個，失敗 0，錯誤 0，略過 0。
- 原本漏跑的 RowConvertorsTest 與 V2ExpressionBuilderTest 已確實執行。
- 最終 JAR：`spark-doris-connector-spark-3.5-26.1.0-cve.1.jar`。
- SHA-256：`a9879a2454e6ee6fe1538486268bfc8b90ef0cc6d626f36193f8adfd1aedb977`。
- 已識別套件：123 個；OSV 回報 0 筆。
- JAR 結構與 Jackson 版本檢查：通過。
- Java Spark 3.5.1 local job、Doris JSON 解析、JavaTime、Spark JSON 與 provider 登錄：通過。

## 公司阻擋的 CVE-2026-54512

- 公司回報評級：Critical；FasterXML 公告評級：High／CVSS 3.1 8.1。
- [官方公告 GHSA-j3rv-43j4-c7qm](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-j3rv-43j4-c7qm)。
- Jackson 2.x 受影響範圍：2.10.0–2.18.7、2.19.0–2.21.3；2.18 分支自 2.18.8 修補。
- 本成品內嵌 databind **2.18.10**，已涵蓋修補；無需為此 CVE 再換版本。
- 針對成品的獨立回歸測試：3 種未允許的泛型參數被拒，未建立測試 bean；正常輸入通過。
- 舊版 2.13.5 對照：此次未執行；可使用 --baseline 重跑。
- 回歸測試時間（UTC）：2026-09-16T17:18:28.739514+00:00；結果與上列 JAR SHA-256 綁定。
- 詳細紀錄：`cve-2026-54512.json`；此結果不等同於公司的掃描器已放行。

## 範圍與限制

OSV 查核結合內嵌套件資訊與 Maven Shade 打包清單；無法保證辨識所有已被第三方再次打包的二進位內容。
未連線到真實 Doris，尚未執行正式環境讀寫；Spark 自带 runtime 依賴不在此次 Connector 修補範圍。
本機解析出的原始 Spark 3.5.1 runtime 另含 databind 2.15.2，也在 CVE-2026-54512 受影響範圍；它未打包進修補版 Connector。若公司掃描整個應用／容器，仍需處理這份執行環境依賴。
主要阻擋編號已確認為 CVE-2026-54512；公司的掃描器政策與實際結果仍待確認。

## 檔案

- `audit.json`：完整套件清單與 OSV 結果。
- `sbom.cdx.json`：CycloneDX 1.6 格式套件清單，可供後續掃描工具匯入。
- `test-summary.json`：測試數與各測試類別。
- `cve-2026-54512.json`：公司阻擋項目的版本依據、成品回歸測試與可選舊版對照。
- `build.log`、`smoke.log`：本機驗證紀錄，含本機路徑，供本機審閱；不必公開發布。

## Maven 發布包解析驗證

已由獨立 Maven 專案，透過本機 file repository 解析發布包，下載的 JAR SHA-256 與已掃描成品相同。
依賴樹只有新座標，不會再拉回舊版 Connector 或未發布的 fork 模組。
這是本機發布包驗證；公開 Maven Central 的下載驗證仍待正式發布後執行。
