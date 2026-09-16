# Maven Central 發布設定

此專案是 Apache Doris Connector 26.1.0 的非官方修補版，公開維護身分為 **cklinisme**。

## 公開資訊

| 項目 | 設定 |
|---|---|
| Maven groupId | `io.github.cklinisme`（Central 已驗證） |
| artifactId | `spark-doris-connector-spark-3.5` |
| version | `26.1.0-cve.1` |
| 原始碼 | https://github.com/cklinisme/doris-spark-connector-cve |
| Git 作者 | `cklinisme <330095769+cklinisme@users.noreply.github.com>` |
| 簽章指紋 | `BD2E377C0A8960326661167F4CA34BB64B8F436E` |
| 公鑰 | [public-keys/cklinisme-release.asc](public-keys/cklinisme-release.asc) |

本座標與 Apache 官方的 `org.apache.doris` 分開；程式內原有的 Apache 套件名稱、LICENSE 與 NOTICE 保留。
公開設定記錄於 `publish-config.json`，不含密碼或 token。

## 目前狀態

- Central 的 `io.github.cklinisme` namespace 已顯示 **Verified**。
- 已建立公開 GitHub repo。
- 已用公開 groupId 重新建置 JAR，通過 91 個測試及 Spark 3.5.1 本機測試。
- CVE-2026-54512 成品回歸測試通過；123 個已識別成分的 OSV 查核為 0 筆。
- 已建立簽章金鑰，公鑰已送到 `keyserver.ubuntu.com`。
- 四個發布檔案的簽章已驗證；獨立 Maven 消費端解析成功。
- **尚待 Central 正式發布及匿名下載確認；目前不能宣稱此座標已可下載。**

## 重建發布包

需求：JDK 11、Maven 3.8.7 以上、Python 3、GnuPG。

```sh
python tools/build.py --osv
python tools/prepare_release.py --repository-url https://github.com/cklinisme/doris-spark-connector-cve
python tools/verify_release.py
```

`build.py` 與 `verify_release.py` 可用 `--maven`、`--java-home`、`--maven-repository` 指定工具與快取。
`prepare_release.py` 預設產生未簽署預覽；正式發布必須簽署，且拒絕 JAR 座標不符、掃描不完整或有漏洞、回歸測試失敗的成品。

### Windows 上此發布身分的簽章

```powershell
.\tools\sign_release.ps1 -Gpg 'C:\Program Files\Git\usr\bin\gpg.exe'
```

私鑰位於 `%LOCALAPPDATA%\doris-connector-publisher\cklinisme\gnupg`；私鑰有隨機密碼，密碼另外由 Windows DPAPI 綁定目前 Windows 使用者加密保存。此目錄不在 repo 或來源 ZIP 中。
請妥善備份簽章資料及可還原的 Windows 使用者環境；DPAPI 檔案不能直接搬到其他 Windows 帳號解密。
`setup_signing.ps1` 用於首次設定；已存在金鑰時不會另造相同身分的金鑰。

使用其他環境的既有金鑰時：

```sh
python tools/prepare_release.py --repository-url https://github.com/cklinisme/doris-spark-connector-cve --sign --gpg-key BD2E377C0A8960326661167F4CA34BB64B8F436E
```

## Central 上傳與確認

1. 在 https://central.sonatype.com/ 選 **Continue with GitHub**，使用 `cklinisme` 登入。
2. Publish → Publish Component，選取 `release-output/central-bundle.zip`。
3. 通過 Portal 驗證後完成發布，保留 deployment ID。
4. 執行 `python tools/verify_public_release.py`，從公開 Central 匿名下載四個檔案並核對 SHA-256；通過後才標記發布成功。

發布包內含主 JAR、standalone POM、sources JAR、使用說明 javadoc JAR，以及各自簽章／校驗碼。POM 不引用尚未發布的 fork parent/base 模組。
Central 同一版本發布後不能覆蓋，後續修補必須增加版本。

## 驗證與限制

可公開查核資料放在 `verification/`，原始本機建置日誌不包含於公開來源。
此修補只更新 Connector 內嵌依賴；Spark 3.5.1 runtime 的另一份 Jackson databind 2.15.2 仍需依公司的掃描範圍處理。尚未連線真實 Doris 執行讀寫測試。

官方設定文件：[Namespace](https://central.sonatype.org/register/namespace/)、[簽章](https://central.sonatype.org/publish/requirements/gpg/)、[發布要求](https://central.sonatype.org/publish/requirements/)。
