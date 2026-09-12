#!/usr/bin/env bash
# 断点续传上传会话端到端示例：创建会话 -> Content-Range 乱序分片 -> 进度/缺失区间
# -> 幂等重传 -> 完成转入脱敏作业 -> 轮询作业 -> 下载结果。
# 用法：bash examples/resumable-upload.sh [/path/to/big.ndjson]
#   不传参数时用内置示例日志生成一个 2000 行的临时 NDJSON。
#   KIND=zip bash examples/resumable-upload.sh  演示 ZIP 诊断包断点续传。
# 服务需已在 :8080 启动（python run.py）。
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8080}"
HERE="$(cd "$(dirname "$0")" && pwd)"
KIND="${KIND:-ndjson}"
TOKEN_CONTEXT="${TOKEN_CONTEXT:-incident-20260912-resumable-001}"
CHUNK_SIZE="${CHUNK_SIZE:-65536}"

# ---------- 1. 准备待上传文件 ----------
LOGS="${1:-}"
if [[ -z "$LOGS" ]]; then
  if [[ "$KIND" == "zip" ]]; then
    LOGS="$(mktemp -t diag-bundle.XXXXXX.zip)"
    trap 'rm -f "$LOGS"' EXIT
    python3 - "$LOGS" <<'PY'
import json, sys, zipfile
path = sys.argv[1]
with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
    lines = []
    for i in range(500):
        lines.append(json.dumps({
            "ts": "2026-09-12T08:00:00Z", "seq": i, "service": "order-api",
            "user": {"email": f"user{i}@example.com", "phone": "13800001234"},
            "client_ip": "10.23.56.78",
        }, ensure_ascii=False))
    zf.writestr("logs/app.ndjson", "\n".join(lines) + "\n")
    zf.writestr("notes.txt", "contact 13800001234 from 10.23.56.78\n")
print(path)
PY
  else
    LOGS="$(mktemp -t big-logs.XXXXXX.ndjson)"
    trap 'rm -f "$LOGS"' EXIT
    python3 - "$LOGS" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, "w", encoding="utf-8") as fh:
    for i in range(2000):
        fh.write(json.dumps({
            "ts": "2026-09-12T08:00:00Z", "seq": i, "service": "order-api",
            "user": {"id": i, "email": f"user{i}@example.com", "phone": "13800001234"},
            "client_ip": "10.23.56.78",
            "message": f"ticket {i} contact 13800001234 from 10.23.56.78",
        }, ensure_ascii=False) + "\n")
print(path)
PY
  fi
fi
echo "== 待上传文件: $LOGS ($(wc -c < "$LOGS") 字节, kind=$KIND) =="

# ---------- 2. 计算总字节数与整体 SHA-256，创建上传会话 ----------
read -r SIZE SHA256 <<<"$(python3 - "$LOGS" <<'PY'
import hashlib, sys
data = open(sys.argv[1], "rb").read()
print(len(data), hashlib.sha256(data).hexdigest())
PY
)"
echo "== 创建上传会话（bytes_total=$SIZE）=="
# token_context 必填：断点续传会话必须声明令牌关联域（服务只持久化不可逆域标识）
RESP=$(python3 - "$BASE" "$KIND" "$SIZE" "$SHA256" "$TOKEN_CONTEXT" "$HERE/sample-strategy.json" <<'PY'
import json, sys, urllib.request
base, kind, size, sha256, ctx, strategy_path = sys.argv[1:7]
body = json.dumps({
    "kind": kind,
    "bytes_total": int(size),
    "content_sha256": sha256,
    "strategy": json.load(open(strategy_path, encoding="utf-8")),
    "token_context": ctx,
    "source_filename": "upload." + ("zip" if kind == "zip" else "ndjson"),
}).encode()
req = urllib.request.Request(
    base + "/api/v1/upload-sessions", data=body,
    headers={"Content-Type": "application/json",
             "Idempotency-Key": "example-resumable-" + sha256[:16]})
print(urllib.request.urlopen(req).read().decode())
PY
)
SID=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["session"]["id"])' <<<"$RESP")
python3 -c '
import json,sys
s=json.load(sys.stdin)["session"]
print("session_id:", s["id"])
print("关联域指纹:", s["domain_fingerprint"], " 状态:", s["status"])
print("缺失区间:", s["missing_ranges"])' <<<"$RESP"

# ---------- 3. 乱序提交分片（模拟网络不稳时的断点续传） ----------
echo "== 以 Content-Range 乱序上传分片（每片 $CHUNK_SIZE 字节）=="
python3 - "$BASE" "$SID" "$LOGS" "$SIZE" "$CHUNK_SIZE" <<'PY'
import hashlib, json, sys, urllib.request

base, sid, path, size, chunk_size = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
data = open(path, "rb").read()
ranges = [(s, min(s + chunk_size, size)) for s in range(0, size, chunk_size)]
order = list(range(len(ranges)))
# 乱序：奇数片优先，偶数片随后（模拟重连后补传）
order = order[1::2] + order[0::2]
for idx in order:
    start, end = ranges[idx]
    chunk = data[start:end]
    req = urllib.request.Request(
        f"{base}/api/v1/upload-sessions/{sid}/chunks",
        data=chunk, method="PUT",
        headers={"Content-Range": f"bytes {start}-{end - 1}/{size}",
                 "X-Chunk-SHA256": hashlib.sha256(chunk).hexdigest(),
                 "Content-Type": "application/octet-stream"})
    res = json.load(urllib.request.urlopen(req))
    s = res["session"]
    print(f"  片 {idx + 1}/{len(ranges)} [{start},{end}) -> "
          f"replayed={res['replayed']} 进度 {s['progress_pct']}% "
          f"缺失 {len(s['missing_ranges'])} 段")
PY

# ---------- 4. 幂等演示：重传已登记分片（内容一致 -> replayed=true） ----------
echo "== 幂等演示：重传首个分片（内容一致，应为幂等回放）=="
python3 - "$BASE" "$SID" "$LOGS" "$SIZE" "$CHUNK_SIZE" <<'PY'
import hashlib, json, sys, urllib.request
base, sid, path, size, chunk_size = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
data = open(path, "rb").read(chunk_size)
req = urllib.request.Request(
    f"{base}/api/v1/upload-sessions/{sid}/chunks",
    data=data, method="PUT",
    headers={"Content-Range": f"bytes 0-{len(data) - 1}/{size}",
             "Content-Type": "application/octet-stream"})
res = json.load(urllib.request.urlopen(req))
print("  replayed =", res["replayed"], "（相同区间内容一致 -> 幂等回放）")
PY

# ---------- 5. 查询进度（缺失区间应为空） ----------
echo "== 完成前进度 =="
curl -fsS "$BASE/api/v1/upload-sessions/$SID" | python3 -c '
import json,sys
s=json.load(sys.stdin)
print("  状态:", s["status"], " 进度:", s["progress_pct"], "%")
print("  已收区间:", s["received_ranges"])
print("  缺失区间:", s["missing_ranges"])
assert s["missing_ranges"] == [], "仍有缺失分片"'

# ---------- 6. 完成会话：整体摘要校验通过后转入脱敏作业 ----------
echo "== 完成会话（整体 SHA-256 校验 -> 转入脱敏作业）=="
JOB_KIND="stream-jobs"
[[ "$KIND" == "zip" ]] && JOB_KIND="bundle-jobs"
RESP=$(curl -fsS -X POST "$BASE/api/v1/upload-sessions/$SID/complete")
JOB_ID=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["job"]["id"])' <<<"$RESP")
echo "  job_id=$JOB_ID（已转入 $JOB_KIND）"

echo "== 轮询作业状态 =="
while :; do
  JOB=$(curl -fsS "$BASE/api/v1/$JOB_KIND/$JOB_ID")
  STATUS=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' <<<"$JOB")
  [[ "$STATUS" == "queued" || "$STATUS" == "running" ]] || break
  sleep 0.5
done
python3 -c '
import json,sys
j=json.load(sys.stdin)
print("  最终状态:", j["status"], " 关联域:", j["domain_fingerprint"])
assert j["status"] == "succeeded", j' <<<"$JOB"

echo "== 完成后会话进度（字节数/区间与 100% 一致）=="
curl -fsS "$BASE/api/v1/upload-sessions/$SID" | python3 -c '
import json,sys
s=json.load(sys.stdin)
print("  状态:", s["status"], " 进度:", s["progress_pct"], "%",
      " 已收:", s["bytes_received"], "/", s["bytes_total"])
print("  已收区间:", s["received_ranges"], " 缺失区间:", s["missing_ranges"])
assert s["bytes_received"] == s["bytes_total"] and s["missing_ranges"] == []'

echo "== 下载脱敏结果 =="
OUT="/tmp/redacted-resumable.$KIND"
curl -fsS "$BASE/api/v1/$JOB_KIND/$JOB_ID/download" -o "$OUT"
echo "  已下载 $OUT（$(wc -c < "$OUT") 字节）"
[[ "$KIND" == "ndjson" ]] && head -1 "$OUT"
echo "完成。"
