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
echo
echo "== 5. 令牌关联域（token_context）：隔离域替身 =="
python3 - "$BASE" <<'PY'
import json, sys, urllib.request

base = sys.argv[1]
strategy = json.load(open("examples/sample-strategy.json", encoding="utf-8"))
logs = open("examples/sample-logs.ndjson", encoding="utf-8").read()

def call(ctx=None):
    body_obj = {"format": "ndjson", "content": logs, "strategy": strategy}
    if ctx is not None:
        body_obj["token_context"] = ctx
    req = urllib.request.Request(
        base + "/api/v1/strategies/validate",
        data=json.dumps(body_obj).encode(),
        headers={"Content-Type": "application/json"},
    )
    return json.load(urllib.request.urlopen(req))

g = call()                                  # 未传 -> 全局域
a1 = call("incident-20260911-alpha")        # 隔离域 A
a2 = call("incident-20260911-alpha")        # 同样的上下文
b = call("incident-20260911-beta")          # 不同上下文 -> 不同域
print("域指纹:", g["domain_fingerprint"], a1["domain_fingerprint"], b["domain_fingerprint"])
tg, ta1, ta2, tb = (r["records"][0]["user"]["phone"] for r in (g, a1, a2, b))
print("手机号替身:")
print("  全局        ", tg)
print("  域 A（两次）", ta1, ta2, "-> 相同" if ta1 == ta2 else "-> 不一致！")
print("  域 B        ", tb)
assert ta1 == ta2 and ta1 != tb and ta1 != tg
print("结论：同上下文同替身、不同上下文不同替身；服务只返回域指纹，不保存上下文原文。")
PY

