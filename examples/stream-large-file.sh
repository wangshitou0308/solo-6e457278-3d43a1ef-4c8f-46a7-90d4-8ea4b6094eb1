#!/usr/bin/env bash
# 大批量 NDJSON 流式作业端到端示例：multipart 上传 -> 轮询进度 -> 下载结果。
# 用法：bash examples/stream-large-file.sh [/path/to/big.ndjson]
#   不传参数时用内置示例日志生成一个 2000 行的临时 NDJSON。
# 服务需已在 :8080 启动（python run.py）。
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8080}"
HERE="$(cd "$(dirname "$0")" && pwd)"

LOGS="${1:-}"
if [[ -z "$LOGS" ]]; then
  LOGS="$(mktemp -t big-logs.XXXXXX.ndjson)"
  trap 'rm -f "$LOGS"' EXIT
  python3 - "$LOGS" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, "w", encoding="utf-8") as fh:
    for i in range(2000):
        fh.write(json.dumps({
            "ts": "2026-09-10T08:00:00Z", "seq": i, "service": "order-api",
            "user": {"id": i, "email": f"user{i}@example.com", "phone": "13800001234"},
            "client_ip": "10.23.56.78",
            "message": f"ticket {i} contact 13800001234 from 10.23.56.78",
        }, ensure_ascii=False) + "\n")
print(path)
PY
fi
echo "== 上传文件: $LOGS ($(wc -c < "$LOGS") 字节) =="

# multipart：file 为 NDJSON 文件；strategy 字段直接取策略文件内容（不发送文件名）
RESP=$(curl -fsS -X POST "$BASE/api/v1/stream-jobs" \
  -H "Idempotency-Key: example-stream-$(date +%s)" \
  -F "strategy=<$HERE/sample-strategy.json;type=application/json" \
  -F "file=@$LOGS;type=application/x-ndjson")
JOB_ID=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["job"]["id"])' <<<"$RESP")
echo "job_id=$JOB_ID（202 已接受）"

echo "== 轮询进度 =="
while :; do
  JOB=$(curl -fsS "$BASE/api/v1/stream-jobs/$JOB_ID")
  STATUS=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' <<<"$JOB")
  [[ "$STATUS" == "queued" || "$STATUS" == "running" ]] || break
  python3 -c '
import json,sys
j=json.load(sys.stdin)
print("  %-8s %6.2f%%  records=%d audit=%d risk=%d" % (
    j["status"], j["progress_pct"], j["records_processed"],
    j["audit_count"], j["risk_count"]))' <<<"$JOB"
  sleep 0.5
done
python3 -c '
import json,sys
j=json.load(sys.stdin)
print("最终状态:", j["status"])
print("记录/审计/风险:", j["records_processed"], j["audit_count"], j["risk_count"])
if j["status"]=="failed": print("失败行号:", j["error_line"], j["error_message"]); sys.exit(1)' <<<"$JOB"

echo "== 分页审计（前 5 条）与残留风险（前 5 条）=="
curl -fsS "$BASE/api/v1/stream-jobs/$JOB_ID/audit?limit=5&offset=0" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("audit total =",d["total"]); [print(" ",a) for a in d["items"]]'
curl -fsS "$BASE/api/v1/stream-jobs/$JOB_ID/risks?limit=5&offset=0" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("risks total =",d["total"])'

echo "== 下载结果 =="
curl -fsS "$BASE/api/v1/stream-jobs/$JOB_ID/download" -o /tmp/redacted-stream.ndjson
echo "已下载 /tmp/redacted-stream.ndjson：$(wc -l < /tmp/redacted-stream.ndjson) 行；首行："
head -1 /tmp/redacted-stream.ndjson

echo "== 幂等演示：同一 Idempotency-Key 重放返回 200（换成新策略则会 409）=="
