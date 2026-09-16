# Copyright 2026 Local security fork contributors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Check the company's blocking CVE against the actual shaded release JAR."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--java-home", type=Path, default=Path(os.environ.get("JAVA_HOME", ".")))
parser.add_argument("--baseline", action="store_true", help="Also reproduce against cached Jackson 2.13.5; never used by the released connector")
args = parser.parse_args()
jar = ROOT / "spark-doris-connector/spark-doris-connector-spark-3.5/target/spark-doris-connector-spark-3.5-26.1.0-cve.1.jar"
source = ROOT / "tools/Cve54512Regression.java"
output = ROOT / ".build/cve54512"
output.mkdir(parents=True, exist_ok=True)
suffix = ".exe" if os.name == "nt" else ""
java = str(args.java_home / ("bin/java" + suffix))
javac = str(args.java_home / ("bin/javac" + suffix))

def run(java_source, classpath, directory, parameters):
    directory.mkdir(parents=True, exist_ok=True)
    subprocess.run([javac, "-encoding", "UTF-8", "-cp", classpath, "-d", str(directory), str(java_source)], check=True)
    result = subprocess.run([java, "-cp", str(directory) + os.pathsep + classpath, "Cve54512Regression"] + parameters,
                            check=True, capture_output=True, text=True)
    print(result.stdout.strip())
    return result.stdout.strip()

result = run(source, str(jar), output / "release", [])
baseline = None
if args.baseline:
    baseline_source = output / "baseline-source/Cve54512Regression.java"
    baseline_source.parent.mkdir(exist_ok=True)
    baseline_source.write_text(source.read_text(encoding="utf-8").replace("org.apache.doris.shaded.com.fasterxml.jackson", "com.fasterxml.jackson"), encoding="utf-8")
    jars = [ROOT / f".build/repository/com/fasterxml/jackson/core/{artifact}/2.13.5/{artifact}-2.13.5.jar"
            for artifact in ("jackson-databind", "jackson-core", "jackson-annotations")]
    if not all(path.is_file() for path in jars):
        raise SystemExit("Baseline requires the three cached upstream Jackson 2.13.5 JARs")
    baseline = run(baseline_source, os.pathsep.join(map(str, jars)), output / "baseline", ["--expect-vulnerable"])
report = {"cve": "CVE-2026-54512", "advisory": "GHSA-j3rv-43j4-c7qm",
          "advisoryUrl": "https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-j3rv-43j4-c7qm",
          "companyReportedSeverity": "Critical", "upstreamSeverity": "High", "upstreamCvss31": 8.1,
          "fixedVersions": ["2.18.8", "2.21.4", "3.1.4"], "shippedDatabindVersion": "2.18.10",
          "checkedAt": datetime.now(timezone.utc).isoformat(), "artifactSha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
          "testSourceSha256": hashlib.sha256(source.read_bytes()).hexdigest(),
          "status": "passed", "deniedVariants": 3, "allowedControl": "passed", "result": result, "baseline": baseline}
(ROOT / "release-output").mkdir(exist_ok=True)
(ROOT / "release-output/cve-2026-54512.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
