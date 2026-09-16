# Copyright 2026 cklinisme
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Download directly from public Central and compare with the prepared release.

No credentials or Maven cache are used. Exit 2 means not yet publicly available.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "release-output"
RELATIVE = "io/github/cklinisme/spark-doris-connector-spark-3.5/26.1.0-cve.1"
STEM = "spark-doris-connector-spark-3.5-26.1.0-cve.1"
BASE = "https://repo.maven.apache.org/maven2/" + RELATIVE
prepared = OUT / "maven" / RELATIVE
destination = OUT / "public-download"
files = [STEM + suffix for suffix in (".pom", ".jar", "-sources.jar", "-javadoc.jar")]
verified = []
for name in files:
    local = prepared / name
    expected = hashlib.sha256(local.read_bytes()).hexdigest()
    request = urllib.request.Request(BASE + "/" + name, headers={"User-Agent": "DorisSecurityForkReleaseVerification/1"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            print("NOT PUBLISHED: Central returned HTTP 404 for " + name)
            raise SystemExit(2)
        raise
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise SystemExit("Central content differs from the prepared release: " + name)
    destination.mkdir(exist_ok=True)
    (destination / name).write_bytes(data)
    verified.append({"file": name, "sha256": actual, "url": BASE + "/" + name})
result = {"status": "passed", "checkedAt": datetime.now(timezone.utc).isoformat(),
          "publicDownloadVerified": True, "files": verified}
(OUT / "public-download-verification.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
print("PASS: anonymous public Central download matches all four prepared release files")
