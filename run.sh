#!/bin/bash
# ─────────────────────────────────────────────────────────
#  Local HTTPS Proxy — Run (Linux / macOS)
# ─────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$SCRIPT_DIR/local-https-proxy.jar"

if [ ! -f "$JAR" ]; then
  echo "local-https-proxy.jar not found!"
  echo "Build with: mvn package -DskipTests"
  exit 1
fi

echo ""
java -jar "$JAR"
