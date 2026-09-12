#!/usr/bin/env bash
# 本地数据保留与安全清理：配置保留策略 → 加保留锁 → 预览 → 提交执行 → 查进度/审计。
#
# 关键安全语义（见 docs/ 与 /docs）：
#   * 预览只返回待删作业、文件类别与预计释放空间，绝不返回日志/结果内容；
#   * 执行必须回传预览摘要（target_fingerprint 与计数）；目标变化返回 409；
#   * 保留锁未到期、运行中作业、保留期未满的结果不会被删除；
#   * 符号链接/越界路径拒绝删除；文件缺失按已删处理；部分失败可重试，重启自动继续。
#
# 用法：bash examples/retention-cleanup.sh （服务需已在 :8080 启动）
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8080}"

echo "== 1. 查询当前保留策略（内置默认 + 自定义覆盖） =="
curl -fsS "$BASE/api/v1/retention/policy" | python3 -m json.tool

echo
echo "== 2. 为某作业类型设置保留期限（按 类型×终态×复核状态） =="
# 小批量成功、无需复核的结果保留 7 天；重复 PUT 幂等覆盖
curl -fsS -X PUT "$BASE/api/v1/retention/rules" \
  -H 'Content-Type: application/json' \
  -d '{"job_kind":"batch","terminal_status":"succeeded","needs_review":"false","retention_days":7}' \
  | python3 -c 'import json,sys; print("已设置；当前规则数:", len(json.load(sys.stdin)["rules"]))'
# 永久保留：retention_days 置 null；删除自定义覆盖回退内置默认：
#   curl -X DELETE "$BASE/api/v1/retention/rules/batch/succeeded/false"

echo
echo "== 3. 给指定作业加保留锁（原因 + 到期时间，UTC ISO 8601） =="
# 先取一个作业 id（演示用列表第一个；没有作业时跳过）
JOB_ID=$(curl -fsS "$BASE/api/v1/jobs?limit=1" \
  | python3 -c 'import json,sys; items=json.load(sys.stdin)["items"]; print(items[0]["id"] if items else "")')
if [ -n "$JOB_ID" ]; then
  EXPIRES=$(python3 -c 'import datetime; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=30)).isoformat(timespec="seconds"))')
  curl -fsS -X PUT "$BASE/api/v1/retention/locks" \
    -H 'Content-Type: application/json' \
    -d "{\"job_kind\":\"batch\",\"job_id\":\"$JOB_ID\",\"reason\":\"合规调查保留 30 天\",\"expires_at\":\"$EXPIRES\"}" \
    | python3 -m json.tool
  echo "（提前释放：curl -X DELETE $BASE/api/v1/retention/locks/batch/$JOB_ID）"
else
  echo "（暂无作业，跳过加锁；可先跑 examples/quickstart.sh 生成一个）"
fi

echo
echo "== 4. 清理预览（不删任何东西，不返回日志内容） =="
PREVIEW=$(curl -fsS -X POST "$BASE/api/v1/retention/cleanup/preview" \
  -H 'Content-Type: application/json' -d '{}')
echo "$PREVIEW" | python3 -m json.tool
FP=$(echo "$PREVIEW" | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_fingerprint"])')
JOBS=$(echo "$PREVIEW" | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_count"])')
FILES=$(echo "$PREVIEW" | python3 -c 'import json,sys; print(json.load(sys.stdin)["file_count"])')
BYTES=$(echo "$PREVIEW" | python3 -c 'import json,sys; print(json.load(sys.stdin)["bytes_total"])')
echo "目标指纹=$FP 作业=$JOBS 文件=$FILES 预计释放=$BYTES 字节"

if [ "$JOBS" = "0" ]; then
  echo "没有到期作业，无需执行。"
  exit 0
fi

echo
echo "== 5. 提交执行（必须回传预览摘要；带幂等键，重复提交回放同一计划） =="
EXEC=$(curl -fsS -X POST "$BASE/api/v1/retention/cleanup/execute" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: cleanup-'"$(date +%Y%m%d%H%M%S)" \
  -d "{\"preview_id\":\"$FP\",\"target_fingerprint\":\"$FP\",\"job_count\":$JOBS,\"file_count\":$FILES,\"bytes_total\":$BYTES}")
echo "$EXEC" | python3 -m json.tool
PLAN=$(echo "$EXEC" | python3 -c 'import json,sys; print(json.load(sys.stdin)["plan"]["plan_id"])')

echo
echo "== 6. 轮询计划进度 =="
for _ in $(seq 1 20); do
  PLAN_JSON=$(curl -fsS "$BASE/api/v1/retention/cleanup/plans/$PLAN")
  STATUS=$(echo "$PLAN_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')
  echo "  status=$STATUS"
  case "$STATUS" in
    succeeded|partial|failed) break ;;
  esac
  sleep 1
done
echo "$PLAN_JSON" | python3 -m json.tool
echo "partial/failed 时重试失败项：curl -X POST $BASE/api/v1/retention/cleanup/plans/$PLAN/retry"

echo
echo "== 7. 查询保留/清理审计（只含动作、目标与计数，不含任何日志内容） =="
curl -fsS "$BASE/api/v1/retention/audit?limit=20" | python3 -m json.tool
