#!/usr/bin/env bash
# 用示例策略对示例日志做完整的试跑 → 正式处理 → 下载流程。
# 用法：bash examples/quickstart.sh （服务需已在 :8080 启动）
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8080}"

echo "== 1. 健康检查 =="
curl -fsS "$BASE/healthz"; echo

echo "== 2. 策略试运行（dry-run，不落库）=="
python3 - "$BASE" <<'PY'
import json, sys, urllib.request

base = sys.argv[1]
strategy = json.load(open("examples/sample-strategy.json", encoding="utf-8"))
logs = open("examples/sample-logs.ndjson", encoding="utf-8").read()
body = json.dumps({"format": "ndjson", "content": logs, "strategy": strategy}).encode()
req = urllib.request.Request(base + "/api/v1/strategies/validate", data=body,
                             headers={"Content-Type": "application/json"})
res = json.load(urllib.request.urlopen(req))
print("needs_review =", res["needs_review"])
print("audit        =", res["stats"]["audit_entries"], "条（不含原值）")
print("risks        =", [(r["field_path"], r["detector"]) for r in res["risks"]])
print("首条脱敏记录:")
print(json.dumps(res["records"][0], ensure_ascii=False, indent=2))
PY

echo "== 3. 正式处理（带幂等键，重复提交只会返回同一作业）=="
JOB_ID=$(python3 - "$BASE" <<'PY'
import json, sys, urllib.request

base = sys.argv[1]
strategy = json.load(open("examples/sample-strategy.json", encoding="utf-8"))
logs = open("examples/sample-logs.ndjson", encoding="utf-8").read()
body = json.dumps({"format": "ndjson", "content": logs, "strategy": strategy}).encode()
req = urllib.request.Request(
    base + "/api/v1/jobs", data=body,
    headers={"Content-Type": "application/json", "Idempotency-Key": "incident-20260910-001"},
)
res = json.load(urllib.request.urlopen(req))
print(res["job"]["id"])
PY
)
echo "job_id=$JOB_ID"

echo "== 4. 下载脱敏文件 =="
curl -fsS "$BASE/api/v1/jobs/$JOB_ID/download" -o /tmp/redacted.ndjson
echo "已下载到 /tmp/redacted.ndjson："
cat /tmp/redacted.ndjson

echo
echo "大文件（超过 10 MiB / 需要断点续跑）请用 multipart 流式作业："
echo "  bash examples/stream-large-file.sh /path/to/big.ndjson"
