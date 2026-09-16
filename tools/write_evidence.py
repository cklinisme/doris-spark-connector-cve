"""Turn successful local verification into portable evidence and a CycloneDX inventory."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "release-output"
report = json.loads((OUT / "audit.json").read_text(encoding="utf-8"))
build_log = ROOT / ".build/build.log"
if report["buildLogSha256"] != hashlib.sha256(build_log.read_bytes()).hexdigest():
    raise SystemExit("Audit does not match the current build log")
jar = ROOT / "spark-doris-connector/spark-doris-connector-spark-3.5/target" / report["artifact"]
if report["sha256"] != hashlib.sha256(jar.read_bytes()).hexdigest():
    raise SystemExit("Audit does not match the current JAR")
cve = json.loads((OUT / "cve-2026-54512.json").read_text(encoding="utf-8"))
if cve["status"] != "passed" or cve["artifactSha256"] != report["sha256"]:
    raise SystemExit("CVE-2026-54512 regression must pass for this exact artifact")
if cve["testSourceSha256"] != hashlib.sha256((ROOT / "tools/Cve54512Regression.java").read_bytes()).hexdigest():
    raise SystemExit("CVE-2026-54512 regression source changed; rerun the regression")
smoke = (ROOT / ".build/smoke.log").read_text(encoding="utf-8", errors="replace")
if "PASS: shaded Jackson 2.18.10" not in smoke or report["errors"] or report["osvStatus"] != "complete":
    raise SystemExit("Build, audit, and smoke verification must complete first")
counts = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
suites = []
for path in sorted((ROOT / "spark-doris-connector").glob("*/target/surefire-reports/TEST-*.xml")):
    suite = ET.parse(path).getroot()
    suites.append({"name": suite.get("name"), **{key: int(suite.get(key, "0")) for key in counts}})
    for key in counts:
        counts[key] += int(suite.get(key, "0"))
# A class containing both JUnit 4 and 5 methods produces two executions; its
# XML filename may be reused. Reactor summaries retain the full execution total.
summaries = re.findall(r"^\[INFO\] Tests run: (\d+), Failures: (\d+), Errors: (\d+), Skipped: (\d+)\s*$",
                       build_log.read_text(encoding="utf-8", errors="replace"), flags=re.MULTILINE)
if summaries:
    counts = dict(zip(counts.keys(), (sum(int(row[i]) for row in summaries) for i in range(4))))
if counts["failures"] or counts["errors"] or counts["tests"] == 0:
    raise SystemExit("Unit tests are not successful")
for required in ("RowConvertorsTest", "V2ExpressionBuilderTest"):
    if not any(suite["name"].endswith(required) and suite["tests"] > 0 for suite in suites):
        raise SystemExit(f"Missing JUnit 5 test execution: {required}")
(OUT / "test-summary.json").write_text(json.dumps({"totals": counts, "suites": suites}, indent=2), encoding="utf-8")
components = []
for component in report["components"]:
    purl = f'pkg:maven/{component["groupId"]}/{component["artifactId"]}@{component["version"]}'
    components.append({"type": "library", "group": component["groupId"], "name": component["artifactId"],
                       "version": component["version"], "purl": purl, "bom-ref": purl})
bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
       "metadata": {"timestamp": report["checkedAt"], "component": {"type": "library", "group": "io.github.cklinisme",
            "name": "spark-doris-connector-spark-3.5", "version": "26.1.0-cve.1",
            "hashes": [{"alg": "SHA-256", "content": report["sha256"]}]}}, "components": components}
(OUT / "sbom.cdx.json").write_text(json.dumps(bom, indent=2), encoding="utf-8")
shutil.copy2(jar, OUT / jar.name)
(OUT / (jar.name + ".sha256")).write_text(report["sha256"], encoding="ascii")
for name in ("build.log", "audit.log", "smoke.log"):
    shutil.copy2(ROOT / ".build" / name, OUT / name)
(OUT / "VERIFICATION.md").write_text(f'''# 修補版驗證結果

- 查核時間（UTC）：{report["checkedAt"]}
- 原始基準：Apache Doris Connector tag 26.1.0 / a25f7a1845760e45111e7eccac2f4087601cd563
- 目標：Java / Spark 3.5.1 / Scala 2.12；本機使用 JDK 11 驗證。
- 單元測試：{counts["tests"]} 個，失敗 {counts["failures"]}，錯誤 {counts["errors"]}，略過 {counts["skipped"]}。
- 原本漏跑的 RowConvertorsTest 與 V2ExpressionBuilderTest 已確實執行。
- 最終 JAR：`{report["artifact"]}`。
- SHA-256：`{report["sha256"]}`。
- 已識別套件：{len(report["components"])} 個；OSV 回報 {len(report["findings"])} 筆。
- JAR 結構與 Jackson 版本檢查：通過。
- Java Spark 3.5.1 local job、Doris JSON 解析、JavaTime、Spark JSON 與 provider 登錄：通過。

## 公司阻擋的 CVE-2026-54512

- 公司回報評級：Critical；FasterXML 公告評級：High／CVSS 3.1 8.1。
- [官方公告 GHSA-j3rv-43j4-c7qm](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-j3rv-43j4-c7qm)。
- Jackson 2.x 受影響範圍：2.10.0–2.18.7、2.19.0–2.21.3；2.18 分支自 2.18.8 修補。
- 本成品內嵌 databind **2.18.10**，已涵蓋修補；無需為此 CVE 再換版本。
- 針對成品的獨立回歸測試：3 種未允許的泛型參數被拒，未建立測試 bean；正常輸入通過。
- 舊版 2.13.5 對照：{'已使用無害 bean 重現漏洞' if cve.get('baseline') else '此次未執行；可使用 --baseline 重跑'}。
- 回歸測試時間（UTC）：{cve['checkedAt']}；結果與上列 JAR SHA-256 綁定。
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
''', encoding="utf-8")
print(f"Verified {counts['tests']} tests; {len(components)} components; {len(report['findings'])} OSV findings. Evidence written to release-output/")
# Copyright 2026 Local security fork contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
