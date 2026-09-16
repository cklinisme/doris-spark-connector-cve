"""Inspect the shipped JAR, preserve dependency identity, optionally query OSV.

This checks embedded Maven metadata and relocation, not just the build POM.
It is not a substitute for the company's scanner or a complete binary SCA scan.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import urllib.request
import zipfile


def request_json(url, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.load(response)


def inspect_jar(jar):
    components = {}
    errors = []
    with zipfile.ZipFile(jar) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            errors.append("Duplicate ZIP entries exist")
        for name in names:
            if name.startswith("META-INF/maven/") and name.endswith("/pom.properties"):
                props = {}
                for line in archive.read(name).decode("utf-8").splitlines():
                    if "=" in line and not line.startswith("#"):
                        key, value = line.split("=", 1)
                        props[key.strip()] = value.strip()
                if all(key in props for key in ("groupId", "artifactId", "version")):
                    gav = f'{props["groupId"]}:{props["artifactId"]}:{props["version"]}'
                    components[gav] = {key: props[key] for key in ("groupId", "artifactId", "version")}
        # SBT-built Scala modules have build.properties rather than Maven metadata.
        scala_metadata = "org/apache/doris/shaded/com/fasterxml/jackson/module/scala/build.properties"
        if scala_metadata in names:
            props = dict(line.split("=", 1) for line in archive.read(scala_metadata).decode().splitlines()
                         if "=" in line and not line.startswith("#"))
            component = {"groupId": "com.fasterxml.jackson.module", "artifactId": "jackson-module-scala_2.12", "version": props.get("version", "unknown")}
            components[":".join(component.values())] = component
        jackson = [c for c in components.values() if c["groupId"].startswith("com.fasterxml.jackson")]
        required = {"jackson-databind", "jackson-core", "jackson-annotations", "jackson-module-scala_2.12", "jackson-datatype-jsr310"}
        missing = required - {c["artifactId"] for c in jackson}
        if missing:
            errors.append(f"Missing Jackson component metadata: {sorted(missing)}")
        for component in jackson:
            if component["version"] != "2.18.10":
                errors.append(f"Unexpected Jackson version: {component}")
        if "org/apache/doris/shaded/com/fasterxml/jackson/databind/ObjectMapper.class" not in names:
            errors.append("Relocated ObjectMapper is missing")
        if any(n.startswith("com/fasterxml/jackson/") and n.endswith(".class") for n in names):
            errors.append("Unrelocated Jackson classes would conflict with Spark")
        # Doris deliberately implements helpers under Spark's package for API access.
        # Check runtime classes, not those genuine connector sources.
        if any(n in names for n in ("org/apache/spark/SparkContext.class", "org/apache/spark/sql/SparkSession.class")):
            errors.append("Spark runtime was accidentally bundled")
        if "META-INF/services/org.apache.spark.sql.sources.DataSourceRegister" not in names:
            errors.append("Spark Doris data source service registration is missing")
        # AWS re-shades Jackson core before we shade the SDK. Its Maven identity
        # alone hides upstream Jackson CVEs, so read the version from its bytecode.
        aws_version_class = "org/apache/doris/shaded/software/amazon/awssdk/thirdparty/jackson/core/json/PackageVersion.class"
        if aws_version_class not in names:
            errors.append("AWS nested Jackson PackageVersion.class is missing")
        else:
            data = archive.read(aws_version_class)
            offset, index = 10, 1
            pool_count = struct.unpack_from(">H", data, 8)[0]
            strings = []
            while index < pool_count:
                tag = data[offset]
                offset += 1
                if tag == 1:
                    size = struct.unpack_from(">H", data, offset)[0]
                    offset += 2
                    strings.append(data[offset:offset + size].decode("utf-8", errors="replace"))
                    offset += size
                elif tag in (5, 6):
                    offset += 8
                    index += 1
                elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                    offset += 4
                elif tag in (7, 8, 16, 19, 20):
                    offset += 2
                elif tag == 15:
                    offset += 3
                else:
                    raise ValueError(f"Unknown class constant pool tag {tag}")
                index += 1
            versions = [value for value in strings if re.fullmatch(r"2\.\d+\.\d+", value)]
            if len(versions) != 1:
                errors.append(f"Ambiguous AWS nested Jackson version: {versions}")
            else:
                components["aws-nested-jackson-core"] = {"groupId": "com.fasterxml.jackson.core", "artifactId": "jackson-core",
                    "version": versions[0], "evidence": aws_version_class, "embeddedBy": "software.amazon.awssdk:third-party-jackson-core"}
    return sorted(components.values(), key=lambda c: (c["groupId"], c["artifactId"])), errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("jar", type=Path)
    parser.add_argument("--output", type=Path, default=Path("release-output/audit.json"))
    parser.add_argument("--osv", action="store_true")
    parser.add_argument("--build-log", type=Path, help="Log from this JAR's successful build; adds dependencies lacking embedded metadata")
    parser.add_argument("--fail-on-any", action="store_true", help="Fail on any OSV finding, not only Jackson")
    args = parser.parse_args()
    components, errors = inspect_jar(args.jar)
    build_log_hash = None
    if args.build_log:
        log = args.build_log.read_text(encoding="utf-8", errors="replace")
        if "BUILD SUCCESS" not in log:
            raise RuntimeError("Build log does not record a successful build")
        extra = {}
        for gav in re.findall(r"Including ([^ ]+) in the shaded jar", log):
            parts = gav.split(":")
            if len(parts) < 4:
                raise RuntimeError(f"Unrecognized shade coordinate: {gav}")
            extra[(parts[0], parts[1], parts[-1])] = {
                "groupId": parts[0], "artifactId": parts[1], "version": parts[-1]}
        if not extra:
            raise RuntimeError("Build log contains no shade inventory")
        for component in components:
            extra[(component["groupId"], component["artifactId"], component["version"])] = component
        components = sorted(extra.values(), key=lambda c: (c["groupId"], c["artifactId"], c["version"]))
        build_log_hash = hashlib.sha256(args.build_log.read_bytes()).hexdigest()
    report = {"checkedAt": datetime.now(timezone.utc).isoformat(), "artifact": args.jar.name,
              "sha256": hashlib.sha256(args.jar.read_bytes()).hexdigest(),
              "scope": "Embedded metadata and optional Maven Shade build inventory; excludes external Spark runtime and cannot fully identify previously shaded third-party binaries",
              "buildLogSha256": build_log_hash,
              "errors": errors, "components": components, "osvStatus": "not-run", "findings": []}
    if args.osv:
        for component in components:
            # Query only known upstream dependencies, not this unpublished fork.
            if component["groupId"] == "io.github.cklinisme":
                continue
            query = {"package": {"ecosystem": "Maven", "name": f'{component["groupId"]}:{component["artifactId"]}'}, "version": component["version"]}
            while True:
                result = request_json("https://api.osv.dev/v1/query", query)
                for vuln in result.get("vulns", []):
                    if not vuln.get("withdrawn"):
                        report["findings"].append({"component": component, "id": vuln["id"], "aliases": vuln.get("aliases", []),
                            "summary": vuln.get("summary", ""), "severity": vuln.get("database_specific", {}).get("severity"),
                            "affected": vuln.get("affected", []), "references": vuln.get("references", [])})
                if not result.get("next_page_token"):
                    break
                query["page_token"] = result["next_page_token"]
        report["osvStatus"] = "complete"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Embedded components: {len(components)}; structural errors: {len(errors)}; OSV findings: {len(report['findings'])}")
    for component in components:
        if component["groupId"].startswith("com.fasterxml.jackson"):
            print(f'{component["artifactId"]}: {component["version"]}')
    for error in errors:
        print(error, file=sys.stderr)
    blocked = errors or any(args.fail_on_any or f["component"]["groupId"].startswith("com.fasterxml.jackson") for f in report["findings"])
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
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
