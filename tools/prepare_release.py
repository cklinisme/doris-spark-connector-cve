"""Create a single-artifact Maven repository, then optionally sign a Central bundle.

No uploads happen here. --sign requires the publisher's existing GPG key.
The published POM has no dependency on unpublished fork parent/base modules.
"""
import argparse
import hashlib
import html
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile
from xml.sax.saxutils import escape

from audit_artifact import inspect_jar

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = "spark-doris-connector-spark-3.5"
VERSION = "26.1.0-cve.1"
MODULES = ["spark-doris-connector-base", "spark-doris-connector-spark-3-base", ARTIFACT]

parser = argparse.ArgumentParser()
parser.add_argument("--group-id", default="io.github.cklinisme")
parser.add_argument("--repository-url", required=True, help="Fork URL; it must exist before signing/publication (may be planned for an unsigned preview)")
parser.add_argument("--developer-id", default="cklinisme")
parser.add_argument("--developer-name", default="cklinisme")
parser.add_argument("--sign", action="store_true")
parser.add_argument("--gpg-key", help="GPG signing key fingerprint (required with --sign)")
parser.add_argument("--gpg-executable", default="gpg")
parser.add_argument("--gnupg-home")
parser.add_argument("--passphrase-stdin", action="store_true", help="Read passphrase from stdin, never command-line arguments")
args = parser.parse_args()
if args.group_id != "io.github.cklinisme":
    raise SystemExit("Change the source POM groupIds and rebuild before publishing a different groupId")
if not args.repository_url.startswith("https://"):
    raise SystemExit("An HTTPS fork repository URL is required")
if args.sign and not args.gpg_key:
    raise SystemExit("--gpg-key must name your existing signing key")
jar = ROOT / "spark-doris-connector" / ARTIFACT / "target" / f"{ARTIFACT}-{VERSION}.jar"
components, errors = inspect_jar(jar)
if errors:
    raise SystemExit("Artifact verification failed: " + "; ".join(errors))
if not any(c["groupId"] == args.group_id and c["artifactId"] == ARTIFACT and c["version"] == VERSION for c in components):
    raise SystemExit("The embedded JAR coordinates do not match the release coordinates")
base = ROOT / "release-output"
jar_hash = hashlib.sha256(jar.read_bytes()).hexdigest()
audit = json.loads((base / "audit.json").read_text(encoding="utf-8"))
cve = json.loads((base / "cve-2026-54512.json").read_text(encoding="utf-8"))
tests = json.loads((base / "test-summary.json").read_text(encoding="utf-8"))["totals"]
if audit["sha256"] != jar_hash or audit["errors"] or audit["osvStatus"] != "complete" or audit["findings"]:
    raise SystemExit("Release must match a fully audited JAR with no reported OSV findings")
if cve["artifactSha256"] != jar_hash or cve["status"] != "passed":
    raise SystemExit("CVE regression must pass for the exact release JAR")
if tests["tests"] == 0 or tests["failures"] or tests["errors"] or tests["skipped"]:
    raise SystemExit("All release tests must execute successfully")
gpg = [args.gpg_executable] + (["--homedir", str(args.gnupg_home)] if args.gnupg_home else [])
passphrase = sys.stdin.readline().rstrip("\r\n") if args.passphrase_stdin else None
if args.passphrase_stdin and not passphrase:
    raise SystemExit("Empty signing passphrase")
repo = base / "maven"
dest = repo / args.group_id.replace(".", "/") / ARTIFACT / VERSION
dest.mkdir(parents=True, exist_ok=True)
stem = f"{ARTIFACT}-{VERSION}"
main = dest / f"{stem}.jar"
shutil.copy2(jar, main)
files = [main]
url = escape(args.repository_url.rstrip("/"))
pom = dest / f"{stem}.pom"
pom.write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
 <modelVersion>4.0.0</modelVersion>
 <groupId>{escape(args.group_id)}</groupId><artifactId>{ARTIFACT}</artifactId><version>{VERSION}</version>
 <packaging>jar</packaging><name>Doris Spark 3.5 Connector - community security fork</name>
 <description>Unofficial Apache Doris connector 26.1.0 fork for Spark 3.5.1 and Scala 2.12, with shaded Jackson 2.18.10.</description>
 <url>{url}</url>
 <licenses><license><name>Apache License, Version 2.0</name><url>https://www.apache.org/licenses/LICENSE-2.0.txt</url><distribution>repo</distribution></license></licenses>
 <developers><developer><id>{escape(args.developer_id)}</id><name>{escape(args.developer_name)}</name><url>https://github.com/{escape(args.developer_id)}</url></developer></developers>
 <scm><connection>scm:git:{url}.git</connection><developerConnection>scm:git:{url}.git</developerConnection><url>{url}</url><tag>v{VERSION}</tag></scm>
 <dependencies>
  <dependency><groupId>org.apache.spark</groupId><artifactId>spark-sql_2.12</artifactId><version>3.5.1</version><scope>provided</scope></dependency>
  <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.7</version><scope>provided</scope></dependency>
 </dependencies>
</project>
''', encoding="utf-8")
files.append(pom)
sources = dest / f"{stem}-sources.jar"
with zipfile.ZipFile(sources, "w", zipfile.ZIP_DEFLATED) as archive:
    entries = {}
    for module in MODULES:
        for language in ("java", "scala"):
            folder = ROOT / "spark-doris-connector" / module / "src/main" / language
            for source in sorted(folder.rglob("*")):
                if not source.is_file():
                    continue
                name = source.relative_to(folder).as_posix()
                if name in entries and entries[name] != source.read_bytes():
                    raise RuntimeError(f"Conflicting source: {name}")
                entries[name] = source.read_bytes()
    for name, content in entries.items():
        archive.writestr(name, content)
    for name in ("LICENSE.txt", "NOTICE.txt"):
        archive.write(ROOT / name, "META-INF/" + name)
files.append(sources)
# Accurate usage documentation; mixed Scala/Java API javadocs are not generated.
# Central explicitly permits documentation JARs containing a README and source links.
docs = dest / f"{stem}-javadoc.jar"
with zipfile.ZipFile(docs, "w", zipfile.ZIP_DEFLATED) as archive:
    archive.write(ROOT / "SECURITY-FORK.md", "README.md")
    archive.writestr("index.html", '<!doctype html><html lang="en"><meta charset="utf-8"><title>Doris connector security fork</title>'
        '<h1>Doris connector security fork</h1><p>This documentation archive contains the build, security, and usage guide in README.md.</p>'
        f'<p>Java and Scala source: <a href="{html.escape(args.repository_url, quote=True)}">repository</a>. '
        'Generated API Javadocs are not included; complete connector source is in the sources JAR.</p></html>')
files.append(docs)
included = list(files)
for file in files:
    if args.sign:
        signature = file.with_name(file.name + ".asc")
        signing = gpg + ["--batch", "--yes", "--armor", "--detach-sign", "--local-user", args.gpg_key]
        if passphrase is not None:
            signing += ["--pinentry-mode", "loopback", "--passphrase-fd", "0"]
        subprocess.run(signing + ["--output", str(signature), str(file)],
                       input=(passphrase + "\n") if passphrase is not None else None, text=True, check=True)
        subprocess.run(gpg + ["--verify", str(signature), str(file)], check=True)
        included.append(signature)
    for algorithm in ("md5", "sha1", "sha256", "sha512"):
        checksum = file.with_name(file.name + "." + algorithm)
        checksum.write_text(hashlib.new(algorithm, file.read_bytes()).hexdigest(), encoding="ascii")
        included.append(checksum)
bundle = base / ("central-bundle.zip" if args.sign else "unsigned-review-bundle.zip")
with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
    for file in included:
        archive.write(file, file.relative_to(repo).as_posix())
print(f"Created {bundle}")
print("Ready for Central validation upload" if args.sign else "UNSIGNED preview only: signing and namespace verification required before Central upload")
# Copyright 2026 cklinisme
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
