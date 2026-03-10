#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${1:-benchmark-output}"
ITER="${ITER:-200}"
MSG_SIZE="${MSG_SIZE:-256}"
RTT_MS="${RTT_MS:-20}"
BANDWIDTH_MBPS="${BANDWIDTH_MBPS:-50}"

mkdir -p "$OUT_DIR"

REPORT_MD="$OUT_DIR/report.md"
REPORT_CSV="$OUT_DIR/report.csv"

# 运行协议对比并同时保存 markdown 报告和 CSV 数据。
go run ./cmd/protocol-bench \
  -n "$ITER" \
  -msg-size "$MSG_SIZE" \
  -rtt-ms "$RTT_MS" \
  -bandwidth-mbps "$BANDWIDTH_MBPS" \
  -csv "$REPORT_CSV" | tee "$REPORT_MD"

echo ""
echo "Benchmark finished"
echo "Markdown: $REPORT_MD"
echo "CSV: $REPORT_CSV"
