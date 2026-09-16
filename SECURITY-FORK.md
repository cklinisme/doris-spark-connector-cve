# Doris Spark Connector 26.1.0：Jackson 修補版

這是以 Apache Doris 官方 tag `26.1.0`（commit `a25f7a1845760e45111e7eccac2f4087601cd563`）為基礎的非官方維護版本。
本版針對 **Java / Spark 3.5.1 / Scala 2.12**；其他 Spark 版本尚未驗證。

## 修補範圍

| 項目 | 原版 | 修補版 |
|---|---|---|
| Jackson databind / core / annotations / Scala / jsr310 | 2.13.5 | Jackson BOM 2.18.10 |
| Apache HttpClient | 4.5.13 | 4.5.14 |
| Apache HttpCore | 4.4.15 | 4.4.16 |
| Netty | 4.1.110.Final | 4.1.138.Final（BOM 對齊） |
| Commons Lang | 3.12.0 | 3.18.0 |
| Protobuf Java | 3.22.3 | 3.25.8 |
| Apache Thrift | 0.16.0 | 0.24.0 |
| Thrift 間接依賴 HttpClient 5 / HttpCore 5 | 新版 Thrift 預設 5.2.1 / 5.2 | 5.6.3 / 5.4.3 |
| AWS SDK | 2.29.52 | 2.54.18 |
| AWS SDK 內嵌的另一份 Jackson Core | 2.15.2 | 2.21.4 |
| Spark 編譯／測試基準 | 3.5.0 | 3.5.1 |
| Maven groupId | org.apache.doris | io.github.cklinisme（非官方修補版） |
| Connector version | 26.1.0 | 26.1.0-cve.1 |

Jackson 仍使用 `org.apache.doris.shaded.com.fasterxml.jackson` 的隔離套件名稱。
JAR 內的 Jackson **實際更新**；保留套件版本資訊供掃描器識別。
使用 BOM 同步所有 Jackson 模組，避免單獨升級 databind 後造成方法或版本不相容。
依賴只在最終 Spark 3.5 JAR 打包一次，避免中間模組的 shaded/reduced POM 影響 reactor。
建置外掛更新為 Scala Maven Plugin 4.9.10、License Maven Plugin 2.7.1、Flatten Maven Plugin 1.8.0，修復舊建置工具在多模組解析時的問題。
Surefire 更新為 3.5.4，補上 JUnit Jupiter/Vintage 5.10.2 測試引擎，讓原本被漏跑的 JUnit 5 JSON 轉換與 Spark expression 測試確實執行。
同步修正舊測試的 LARGEINT 預期值：官方原始碼已使用 StringType；測試原本仍期待 DecimalType(38,0)。實際型別轉換行為沒有變更。

上游安全依據（查核日：2026-09-16）：

- [GHSA-gx83-3vf8-gh7j / CVE-2026-83557](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-gx83-3vf8-gh7j)：2.18.10 為修補版本。
- [GHSA-q4xh-88c3-wmh7](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-q4xh-88c3-wmh7)：2.18.10 為修補版本。
- [GHSA-vvgp-rfg2-7rr6](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-vvgp-rfg2-7rr6)：InetAddress 問題的後續修補。

公司已確認主要阻擋 **CVE-2026-54512**，公司評級為 Critical。
[FasterXML 官方公告 GHSA-j3rv-43j4-c7qm](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-j3rv-43j4-c7qm) 評為 High／CVSS 3.1 8.1，列出 Jackson 2.x 受影響範圍為 2.10.0–2.18.7、2.19.0–2.21.3；修補版本為 2.18.8、2.21.4（3.x 為 3.1.4）。
本版內嵌 databind 2.18.10 已涵蓋此修補。`tools/run_cve54512.py` 直接測試最終 shaded JAR，驗證 List、Map value、巢狀 List 的未允許型別參數在建立 bean 前遭拒，並保留正常輸入對照。
本機另以無害 bean 在原版 2.13.5 重現問題，確認測試確實能辨識漏洞；測試不執行命令或連線。
結果存於 `release-output/cve-2026-54512.json`，附成品 SHA-256。公司的實際掃描結果仍待確認。
Spark 3.5.1 自帶的 Jackson 及其他執行環境套件是另一份依賴；此修補不會替 Spark runtime 升級它們。
獨立測試解析出的原始 Spark 3.5.1 classpath 含另一份 databind **2.15.2**，也落在此 CVE 的受影響版本範圍；該 runtime JAR 沒有打包進修補版 Connector。
若掃描對象是整個 Spark 應用或容器，仍需檢查 runtime。

## 建置與驗證

需求：JDK 11、Maven 3.8.7 以上、Python 3。
在 repo 根目錄執行（PowerShell 或 Bash 均可；範例為單行）：

```sh
mvn -B -ntp -f spark-doris-connector/pom.xml -P spark-3.5 -pl spark-doris-connector-spark-3.5 -am -Dspark.version=3.5.1 clean verify
python tools/audit_artifact.py spark-doris-connector/spark-doris-connector-spark-3.5/target/spark-doris-connector-spark-3.5-26.1.0-cve.1.jar --osv
```

`audit_artifact.py` 檢查最終 JAR 的內嵌依賴版本、Jackson relocation、Spark provider 登錄，以及 OSV 公開公告。
另外直接读取 AWS SDK 內嵌 Jackson Core 的 `PackageVersion.class` 版本常數，避免只掃 AWS artifactId 而漏掉 Jackson Core 漏洞。
建議直接執行 `python tools/build.py --osv`，會保留建置日誌並以 `--build-log .build/build.log` 補查沒有內嵌 Maven metadata 的 Protobuf、Thrift、gRPC 等套件，再執行獨立 Java Spark 測試。
此建置流程也會執行 CVE-2026-54512 回歸測試；可用 `python tools/run_cve54512.py --java-home /path/to/jdk11` 單獨重跑。`--baseline` 額外使用本機 Maven 快取中的三個 Jackson 2.13.5 JAR 作為舊版對照，不影響發布依賴。
預設遇到 Jackson 漏洞或封裝錯誤會失敗；其他漏洞保留在 `release-output/audit.json`。
需要任一 OSV 漏洞都使工作失敗時，加入 `--fail-on-any`。
OSV 查詢失敗會使指令失敗，不能把失敗當成零漏洞。
此檢查以 JAR 內的套件中繼資料為主，不能完整辨識沒有中繼資料的二次打包依賴，也不能代替公司的掃描器。

獨立消費端測試（`mdep.outputFile` 建議給絕對路徑）：

```sh
mvn -B -ntp -f tools/smoke/pom.xml dependency:build-classpath -Dmdep.outputFile=/absolute/path/to/spark-classpath.txt
python tools/run_smoke.py --classpath-file /absolute/path/to/spark-classpath.txt
```

這個測試會把最終 JAR 與原始 Spark 3.5.1 依賴放在同一個 JVM，驗證 Doris JSON、JavaTime、provider 登錄、Spark local job 及 JSON 輸出。
未連線到真實 Doris，因此正式上線前仍需對你的 Doris 環境做一次讀取／Stream Load 驗證。

## 本機建置

請先看根目錄 `BUILD.md`。本 ZIP 只需要 JDK 11 與 Maven 即可產生 JAR，不需要登入 GitHub 或 Maven Central。
Python 3 僅供額外的成品掃描與回歸測試使用。
預定公開座標為 `io.github.cklinisme:spark-doris-connector-spark-3.5:26.1.0-cve.1`；發布狀態與操作見 `PUBLISHING.md`。
第一次建置仍需從 Maven 倉庫下載編譯依賴；來源 ZIP 不包含依賴快取。

## 授權與來源

保留 Apache License、NOTICE 與上游作者資訊；這是非官方修補版。
此來源包不包含 Git 歷史、私人帳號名稱、登入憑證或本機建置日誌。
