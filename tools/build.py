"""Reproducible local build, packaged-JAR audit and independent Spark smoke test."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--maven", default=shutil.which("mvn"), help="Path to mvn or mvn.cmd")
parser.add_argument("--java-home", default=os.environ.get("JAVA_HOME"), help="JDK 11 home")
parser.add_argument("--maven-repository", type=Path, help="Optional Maven dependency cache directory")
parser.add_argument("--osv", action="store_true", help="Also query the live OSV vulnerability API")
args = parser.parse_args()
if not args.maven or not args.java_home:
    parser.error("Set JAVA_HOME and provide Maven on PATH or --maven")
build = ROOT / ".build"
build.mkdir(exist_ok=True)
env = dict(os.environ, JAVA_HOME=args.java_home)
env["PATH"] = str(Path(args.java_home) / "bin") + os.pathsep + env.get("PATH", "")


def run(command, log_name):
    print(f"Running {log_name}", flush=True)
    with (build / log_name).open("w", encoding="utf-8") as log:
        completed = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    if completed.returncode:
        print((build / log_name).read_text(encoding="utf-8", errors="replace")[-10000:])
        raise SystemExit(completed.returncode)


maven = [args.maven, "-B", "-ntp", "-Dmaven.repo.local=" + str(args.maven_repository.resolve() if args.maven_repository else build / "repository")]
run(maven + ["-f", "spark-doris-connector/pom.xml", "-P", "spark-3.5", "-pl", "spark-doris-connector-spark-3.5", "-am",
             "-Dspark.version=3.5.1", "clean", "verify"], "build.log")
jar = "spark-doris-connector/spark-doris-connector-spark-3.5/target/spark-doris-connector-spark-3.5-26.1.0-cve.1.jar"
run([sys.executable, "tools/audit_artifact.py", jar, "--build-log", str(build / "build.log")] + (["--osv"] if args.osv else []), "audit.log")
run(maven + ["-f", "tools/smoke/pom.xml", "dependency:build-classpath", "-Dmdep.outputFile=" + str(build / "spark-classpath.txt")], "smoke-resolve.log")
run([sys.executable, "tools/run_smoke.py", "--java-home", args.java_home], "smoke.log")
run([sys.executable, "tools/run_cve54512.py", "--java-home", args.java_home], "cve-2026-54512.log")
if args.osv:
    run([sys.executable, "tools/write_evidence.py"], "evidence.log")
print("Build, packaged-artifact audit and Spark smoke test passed. Logs are in .build/.")
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
