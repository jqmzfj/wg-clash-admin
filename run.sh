#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")"

LOG_FILE="${LOG_FILE:-./run.log}"

echo "====================" | tee -a "$LOG_FILE"
echo "$(date) 开始执行" | tee -a "$LOG_FILE"

python3 generate_clash_yaml.py 2>&1 | tee -a "$LOG_FILE"

chmod 644 ./clash-config.yaml

echo "$(date) 执行结束" | tee -a "$LOG_FILE"
