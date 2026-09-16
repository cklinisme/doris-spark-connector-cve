# 自行建置 Doris Spark Connector 修補版

目標：Java / Spark **3.5.1** / Scala **2.12**。
以 Apache Doris Connector 26.1.0 為基準，內嵌 Jackson databind **2.18.10**，涵蓋 **CVE-2026-54512** 修補。
本修補版的 Maven groupId 為 `io.github.cklinisme`；此版本尚未公開發布。

## 1. 準備環境

- **JDK 11**（需要 `javac`，只有 JRE 不夠）。
- **Maven 3.8.7 或以上**。
- 將 `JAVA_HOME` 指向 JDK 11，並讓 `java`、`javac`、`mvn` 位於 PATH。
- 建置時需能透過 Maven 下載依賴。沿用你自己的 Maven `settings.xml`／公司鏡像設定。
- 不需要 Git、GitHub 帳號、Maven Central 發布帳號或預先安裝 Spark。

先確認：

```sh
java -version
javac -version
mvn -version
```

`mvn -version` 顯示的 Java version 也應為 11。

## 2. 解壓並建置 JAR

解壓 ZIP，進入包含本文件的 `doris-spark-connector-cve` 資料夾。
在 PowerShell、cmd 或 Bash 執行以下單行指令：

```sh
mvn -B -ntp -f spark-doris-connector/pom.xml -P spark-3.5 -pl spark-doris-connector-spark-3.5 -am -Dspark.version=3.5.1 clean verify
```

看到 `BUILD SUCCESS` 即完成。此指令會執行單元測試，並將所需 Connector 依賴打包到最終 JAR。
請保留 `-P spark-3.5`、`-pl ...` 與 `-am`，它們會選定正確的 Spark 版本並一起建置所需內部模組。

## 3. 取得成品

```text
spark-doris-connector/spark-doris-connector-spark-3.5/target/spark-doris-connector-spark-3.5-26.1.0-cve.1.jar
```

使用上述完整檔名的 JAR。`original-...jar` 與其他 base 模組 JAR 不是完整成品。
可將此成品交給公司掃描器檢查，或透過 Spark 的 `--jars` 載入：

```sh
spark-submit --jars /path/to/spark-doris-connector-spark-3.5-26.1.0-cve.1.jar --class your.package.Main your-application.jar
```

請換成你實際的檔案與主程式名稱，並移除執行環境中另一份官方 Connector，避免重複 provider。

## 4. 額外驗證（選用，需 Python 3）

完整建置、掃描成品、Spark 本機測試、CVE 回歸測試及 OSV 公告查詢：

```sh
python tools/build.py --osv
```

只重跑已建置 JAR 的 CVE-2026-54512 回歸測試：

```sh
python tools/run_cve54512.py
```

這些 Python 指令使用 `JAVA_HOME`；需要時可加 `--java-home /path/to/jdk11`。
Windows 的 Python 命令若為 `py`，可將 `python` 換成 `py -3`。
`build.py` 支援 `--maven /path/to/mvn`，Windows 可指定 `mvn.cmd`。
`--osv` 需要連線至 OSV；產生 JAR 本身不需要 OSV。若查詢失敗，不能將結果解讀成零漏洞。
完整驗證紀錄與 SBOM 會放在 `release-output/`。

## 範圍

此修補針對 Connector 內嵌依賴。Spark 3.5.1 runtime 的另一份 Jackson 不會隨這個 JAR 一起升級；若掃描整個應用或容器，仍需檢查 runtime。
尚未連線到你的 Doris 做正式讀寫。其他修補項目與依據見 `SECURITY-FORK.md`。
