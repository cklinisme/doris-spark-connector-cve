"""Compile and run against the FINAL shaded JAR and an independent Spark classpath."""
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--java-home", type=Path, default=Path(os.environ.get("JAVA_HOME", ".")))
parser.add_argument("--classpath-file", type=Path, default=ROOT / ".build/spark-classpath.txt")
args = parser.parse_args()
jar = ROOT / "spark-doris-connector/spark-doris-connector-spark-3.5/target/spark-doris-connector-spark-3.5-26.1.0-cve.1.jar"
output = ROOT / ".build/smoke-classes"
output.mkdir(parents=True, exist_ok=True)
cp = str(jar) + os.pathsep + args.classpath_file.read_text(encoding="utf-8").strip()
suffix = ".exe" if os.name == "nt" else ""
subprocess.run([str(args.java_home / ("bin/javac" + suffix)), "-encoding", "UTF-8", "-cp", cp,
                "-d", str(output), str(ROOT / "tools/ShadedJacksonSmoke.java")], check=True)
env = dict(os.environ, SPARK_LOCAL_IP="127.0.0.1")
subprocess.run([str(args.java_home / ("bin/java" + suffix)), "-Xmx1g", "-Dfile.encoding=UTF-8", "-cp",
                str(output) + os.pathsep + cp, "ShadedJacksonSmoke"], check=True, env=env)
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
