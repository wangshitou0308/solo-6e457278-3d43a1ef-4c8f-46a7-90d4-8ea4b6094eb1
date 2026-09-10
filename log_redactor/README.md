# 本地日志脱敏 API（Log Redactor）

供后端团队在**提交故障样本前**使用的本地日志脱敏服务。接收 JSON / NDJSON 日志批次与
脱敏策略，按**字段路径、键名、正则、内置敏感信息识别器**命中规则，执行
**删除、掩码、确定性令牌化**，生成不含原值的审计清单，并对残留高风险内容标记
「需复核」。全部功能**离线运行**，数据只落在本机。

- 语言/框架：Python 3.9+ · FastAPI · Pydantic v2 · SQLite（标准库）
- 确定性令牌：HMAC-SHA256 + 本地主密钥，无网络依赖
- 交互式文档：启动后访问 `http://127.0.0.1:8080/docs`（Swagger UI）、`/redoc`
- 离线 OpenAPI 描述文件：[`../docs/openapi.json`](../docs/openapi.json)

## 能力一览

| 能力 | 说明 |
| --- | --- |
| 批次格式 | JSON（对象或数组）、NDJSON（每行一个对象，审计/风险带行号） |
| 字段路径 | JSONPath 风格通配：`$.user.email`、`**.ip`、`items[*].id` |
| 键名匹配 | 精确（`key_names`）、通配（`key_globs`，如 `*_token`）、正则（`key_patterns`） |
| 内容匹配 | 值正则（`value_patterns`）、内置识别器（`detectors`） |
| 内置识别器 | 邮箱、中国大陆手机号、IPv4/IPv6、访问令牌（Bearer/JWT/`key=xxx`/长随机串）、身份证（校验码+日期校验）、银行卡（Luhn 校验） |
| 动作 | `delete`（置空，保留键结构）、`mask`（可配置掩码字符与首尾保留位数，数字保留数值类型）、`tokenize`（基于本地密钥的确定性替身） |
| 类型保留 | 令牌化保留原值类型：字符串→`T-xxxx` 字符串、整数→等宽整数、浮点→保留符号/小数点的浮点；`bool`/`null` 不处理 |
| 确定性 | **同一值整批恒为同一替身，且与命中哪条规则无关**——同一敏感值即使被不同规则（字段规则/内容规则）命中，替身也完全一致（跨作业，密钥不变时同样一致）；数值按类型分别映射 |
| 结构保留 | 只改标量值，嵌套对象/数组层级与非敏感字段原样保留；令牌输出为 `T-XXXX` 字符串 |
| 审计 | 命中规则、记录序号、NDJSON 行号、字段路径、动作、命中维度、替换次数；**绝不记录原始值** |
| 需复核 | 处理后仍被高风险识别器命中的内容写入风险清单，作业 `needs_review=true` |
| 幂等 | 请求头 `Idempotency-Key` 相同的重复提交直接回放首个作业 |
| 大批量流式作业 | `POST /api/v1/stream-jobs` 以 multipart 上传 NDJSON 大文件：原始文件 **0600 临时落盘**、逐行脱敏（不读入整包）、安全检查点记录字节/记录/审计/风险进度，可取消、可在**重启后从检查点继续**，成功后原子发布结果；幂等键同时校验文件内容**与策略**摘要 |
| 试运行 | `POST /strategies/validate` 即时返回脱敏结果，不写库、不落文件 |

## 快速开始

```bash
pip install -r requirements.txt
python run.py                 # 默认监听 127.0.0.1:8080
# ▶ 交互式文档: http://127.0.0.1:8080/docs
```

用内置示例跑通「试跑 → 正式处理 → 下载」：

```bash
bash examples/quickstart.sh
```

或直接 `curl`：

```bash
# 1) 取示例策略
curl -s http://127.0.0.1:8080/api/v1/sample/strategy -o /tmp/strategy.json
# 2) 取示例日志
curl -s http://127.0.0.1:8080/api/v1/sample/logs.ndjson -o /tmp/logs.ndjson
# 3) 试运行（用 python/jq 把两者组装成请求体）
python3 -c '
import json,urllib.request
body=json.dumps({"format":"ndjson",
  "content":open("/tmp/logs.ndjson").read(),
  "strategy":json.load(open("/tmp/strategy.json"))}).encode()
r=urllib.request.urlopen(urllib.request.Request(
  "http://127.0.0.1:8080/api/v1/strategies/validate",data=body,
  headers={"Content-Type":"application/json"}))
print(json.dumps(json.load(r),ensure_ascii=False,indent=2))'
```

## 策略编写

```json
{
  "name": "my-incident-policy",
  "version": "1.0",
  "rules": [
    {
      "id": "delete-credentials",
      "name": "删除凭据字段",
      "match": {
        "key_names": ["password", "authorization"],
        "key_globs": ["*secret*", "*token*"]
      },
      "action": "delete"
    },
    {
      "id": "mask-email",
      "name": "掩码邮箱字段",
      "match": { "field_paths": ["**.email"] },
      "action": "mask",
      "mask_char": "*",
      "keep_prefix": 1,
      "keep_suffix": 0
    },
    {
      "id": "tokenize-phone",
      "name": "令牌化手机号",
      "match": { "key_names": ["phone", "mobile"], "detectors": ["phone"] },
      "action": "tokenize"
    },
    {
      "id": "mask-ip-in-text",
      "name": "掩码自由文本里的 IP",
      "match": { "detectors": ["ipv4", "ipv6"] },
      "action": "mask"
    }
  ],
  "risk_detectors": ["email", "phone", "ipv4", "access_token", "id_card", "bank_card"]
}
```

匹配语义：

- **整字段规则**：含字段/键名维度、不含 `value_patterns`/`detectors`，动作作用于整个标量值；
- **内容规则**：含 `value_patterns`/`detectors`，只替换字符串中命中的片段；可再用字段/键名
  维度限定作用范围（如只在 `$.message` 内识别）；
- 路径组与键名组之间为 AND；键名组内（精确/通配/正则）为 OR；
- 同一片段被多条内容规则覆盖时，**先定义的规则优先**，片段被消费不重复处理；
- 整字段规则按策略顺序首个命中者生效。

## API 摘要

| 方法 & 路径 | 说明 |
| --- | --- |
| `POST /api/v1/strategies/validate` | 策略试运行：返回脱敏记录、审计、风险、统计，不落库 |
| `POST /api/v1/strategies/check` | 仅校验策略语法 |
| `POST /api/v1/jobs` | 正式处理；支持请求头 `Idempotency-Key`；返回作业信息与完整结果 |
| `GET /api/v1/jobs?needs_review=true` | 作业列表，可按需复核过滤、分页 |
| `GET /api/v1/jobs/{id}` | 作业详情：元数据、统计、审计清单、残留风险 |
| `GET /api/v1/jobs/{id}/records` | 脱敏后记录 |
| `GET /api/v1/jobs/{id}/audit` | 仅审计清单 |
| `GET /api/v1/jobs/{id}/download` | 下载脱敏文件，保持提交时的 JSON / NDJSON 格式；JSON 顶层数组（含单元素数组）原样保留，不会解包成对象 |
| `POST /api/v1/stream-jobs` | **大批量 NDJSON**：`multipart/form-data` 上传（`file` + `strategy`），返回 202 与作业 id；原始文件 0600 临时落盘，逐行脱敏、检查点推进 |
| `GET /api/v1/stream-jobs` / `.../{id}` | 流式作业列表（按状态过滤、分页）与状态/实时进度（字节、记录、审计、风险、百分比） |
| `POST /api/v1/stream-jobs/{id}/cancel` | 取消作业；停在检查点边界，原始文件与未完成输出被清理（取消意图跨重启生效） |
| `GET /api/v1/stream-jobs/{id}/audit` / `.../risks` | 分页查询审计清单 / 残留风险（`limit`、`offset`） |
| `GET /api/v1/stream-jobs/{id}/download` | 下载原子发布的 NDJSON 结果；**仅 succeeded 可下载**，未完成返回 409 |
| `GET /api/v1/sample/strategy` / `.../sample/logs.ndjson` | 可直接启动的示例 |
| `GET /healthz` | 健康检查 + 主密钥指纹 |

审计条目示例（**无原值**）：

```json
{
  "record_index": 0,
  "line_no": 1,
  "field_path": "$.user.phone",
  "key_name": "phone",
  "rule_id": "tokenize-phone-field",
  "rule_name": "令牌化手机号字段",
  "action": "tokenize",
  "match_type": "field",
  "hit_by": ["field_match"],
  "occurrences": 1
}
```

残留风险示例（处理后仍发现高风险内容时，作业被标记需人工复核）：

```json
{ "record_index": 1, "line_no": 2, "field_path": "$.note",
  "detector": "bank_card", "length": 19 }
```

## 大批量 NDJSON 流式作业（multipart 上传）

超过小批量 10 MiB 请求体上限、或需要断点续跑的 NDJSON 文件，走流式接口。上传后立即
返回 `202` 与作业 id，后台逐行处理，用状态接口轮询进度；成功后原子发布结果文件，未完成
（queued/running/failed/cancelled）一律不能下载。

```bash
# 1) 上传（multipart：file 为 NDJSON，strategy 为策略 JSON 文本）
curl -sS -X POST http://127.0.0.1:8080/api/v1/stream-jobs \
  -H "Idempotency-Key: incident-20260910-big-001" \
  -F "strategy=<examples/sample-strategy.json;type=application/json" \
  -F "file=@big-logs.ndjson;type=application/x-ndjson"
# -> 202 {"replayed": false, "job": {"id": "…", "status": "queued", "progress_pct": 0.0, …}}

# 2) 轮询状态与实时进度（已处理字节/记录/审计/风险）
curl -sS http://127.0.0.1:8080/api/v1/stream-jobs/$JOB_ID
# -> {"status":"running","bytes_total":…,"bytes_processed":…,
#     "records_processed":12000,"audit_count":…,"risk_count":…,"progress_pct":63.2}

# 3) 需要时取消（停在下一检查点边界，清理原始文件与未完成输出）
curl -sS -X POST http://127.0.0.1:8080/api/v1/stream-jobs/$JOB_ID/cancel

# 4) 分页查看审计与残留风险
curl -sS "http://127.0.0.1:8080/api/v1/stream-jobs/$JOB_ID/audit?limit=200&offset=0"
curl -sS "http://127.0.0.1:8080/api/v1/stream-jobs/$JOB_ID/risks?limit=200&offset=0"

# 5) succeeded 后下载；非 succeeded 返回 409
curl -fS http://127.0.0.1:8080/api/v1/stream-jobs/$JOB_ID/download -o redacted.ndjson
```

Python（requests，流式友好）：

```python
import requests, time

with open("big-logs.ndjson", "rb") as f:
    r = requests.post(
        "http://127.0.0.1:8080/api/v1/stream-jobs",
        headers={"Idempotency-Key": "incident-20260910-big-001"},
        files={"file": ("big-logs.ndjson", f, "application/x-ndjson")},
        data={"strategy": open("examples/sample-strategy.json", encoding="utf-8").read()},
        timeout=300,
    )
r.raise_for_status()  # 409=同键但文件/策略与上次不一致
job = r.json()["job"]
while job["status"] in ("queued", "running"):
    time.sleep(2)
    job = requests.get(f"http://127.0.0.1:8080/api/v1/stream-jobs/{job['id']}").json()
assert job["status"] == "succeeded", job
with open("redacted.ndjson", "wb") as out:
    with requests.get(f"http://127.0.0.1:8080/api/v1/stream-jobs/{job['id']}/download",
                      stream=True) as dl:
        for chunk in dl.iter_content(1 << 20):
            out.write(chunk)
```

流式作业的关键保证：

- **不落整包到内存**：上传按 1 MiB 块拷贝到 `$REDACTOR_DATA_DIR/streams/raw/`（0600），
  worker 按二进制行读取，仅维护检查点级缓冲。
- **安全检查点**：默认每 100 条记录（`REDACTOR_CHECKPOINT_RECORDS` 可调）先 fsync 输出、
  再在同一事务提交字节偏移、记录/审计/风险计数。服务在任意时刻被 kill，重启后从最近检查点
  继续，partial 输出严格截断到检查点字节，不会重复或 NUL 填充。
- **原子发布**：全部记录处理完后 `rename` 到 `streams/out/{id}.ndjson`；即使在发布后、
  状态落库前崩溃，重启也会校验成品（可解析且记录数与检查点一致）并补登 succeeded。
- **清理**：成功后删除原始文件、保留成品；失败/取消同时删除原始文件与未完成输出。
- **幂等含策略**：`Idempotency-Key` 同时绑定文件 SHA-256 与**规范化策略 SHA-256**；
  同键同文件但策略不同返回 409，不会回放旧策略的结果（仅 JSON 排版差异不算不同策略）。
- **格式错误**：记录物理行号（空行占行号不占记录序号），作业置 failed，错误行不写入输出。

## 本地密钥

- 默认：首次启动在数据目录生成 **32 字节原始随机**密钥 `data/master.key`（以 0600 权限
  创建）；删除该文件会让历史令牌全部换新，相当于轮换密钥。
- 加载既有密钥时按原始字节读取（**不做 strip/解码**，长度必须为 32 字节），
  并自动把文件权限收紧为 `0600`。
- 推荐：通过环境变量注入密钥（不落盘）：

  ```bash
  REDACTOR_MASTER_KEY="$(openssl rand -hex 32)" python run.py
  ```

- `/healthz` 返回密钥指纹（HMAC 摘要前 8 字节），可用于确认两次运行是否同一密钥。
- 令牌源为 `HMAC-SHA256(key, 全局命名空间 + 类型前缀 + value)`：字符串取前 18 字节做 Base32
  （`T-XXXX`），数值从 HMAC 数字流构造等宽替身；不可逆推原值，映射与规则无关。
- 审计的 `hit_by` 只记录维度名（`field_match`、`detector:<名称>`、`value_pattern#<序号>`），
  不写入原始正则文本或任何命中的原文。

## 数据与配置

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `REDACTOR_DATA_DIR` | `./data` | SQLite、主密钥、脱敏输出文件（`jobs/`）与流式作业临时/成品文件（`streams/raw|partial|out/`）目录 |
| `REDACTOR_MASTER_KEY` | 自动生成文件 | 确定性令牌主密钥 |
| `REDACTOR_CHECKPOINT_RECORDS` | `100` | 流式作业每处理多少条记录做一次安全检查点（1–10000） |

小批量 JSON 接口请求体上限 10 MiB；**流式 multipart 上传不受此限**（逐块落盘）。
SQLite 位于 `$REDACTOR_DATA_DIR/redactor.db`，审计/风险表只存位置与动作，不存任何原始敏感值。

## 测试

```bash
python -m pytest -q        # 99 个用例：识别器、路径通配、动作、确定性、API、幂等、流式作业（取消/检查点恢复/原子发布）、下载
```

## 安全边界（请知悉）

- 本工具降低误提交风险，不替代人工复核；**`needs_review=true` 的作业应人工确认后再外发**。
- 确定性令牌允许关联分析但也允许“等值连接”，请结合场景决定是否对跨作业分析使用不同密钥。
- 识别器基于正则/校验码，可能存在漏报与误报；可叠加自定义正则规则并扩充 `risk_detectors`。
- 服务默认只监听 `127.0.0.1`；如需团队共享请自行置于内网与访问控制之后。
