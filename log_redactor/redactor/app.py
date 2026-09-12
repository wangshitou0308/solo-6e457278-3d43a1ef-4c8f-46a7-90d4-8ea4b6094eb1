"""本地日志脱敏 HTTP API（FastAPI）。

接口概览
--------
* ``POST /api/v1/strategies/validate``  策略试运行（不落库，返回脱敏结果与审计）
* ``POST /api/v1/strategies/diff``      策略变更对照（基线 vs 候选，CI 放行判定）
* ``POST /api/v1/jobs``                 正式处理，支持 ``Idempotency-Key``
* ``GET  /api/v1/jobs``                 作业列表（可按需复核过滤）
* ``GET  /api/v1/jobs/{job_id}``        作业详情、统计、审计清单、残留风险
* ``GET  /api/v1/jobs/{job_id}/records`` 脱敏后记录
* ``GET  /api/v1/jobs/{job_id}/audit``  仅取审计清单
* ``GET  /api/v1/jobs/{job_id}/download`` 下载脱敏文件（保持 JSON/NDJSON）
* ``POST /api/v1/stream-jobs``          大批量 NDJSON：multipart 上传，流式作业
* ``GET  /api/v1/stream-jobs``          流式作业列表（可按状态过滤、分页）
* ``GET  /api/v1/stream-jobs/{job_id}`` 流式作业状态与实时进度
* ``POST /api/v1/stream-jobs/{job_id}/cancel`` 取消作业（可跨重启生效）
* ``GET  /api/v1/stream-jobs/{job_id}/audit`` 分页审计清单
* ``GET  /api/v1/stream-jobs/{job_id}/risks`` 分页残留风险
* ``GET  /api/v1/stream-jobs/{job_id}/download`` 下载已完成的 NDJSON 结果
* ``POST /api/v1/bundle-jobs``          诊断包（ZIP）：multipart 上传压缩包+策略
* ``GET  /api/v1/bundle-jobs``          诊断包作业列表（可按状态过滤、分页）
* ``GET  /api/v1/bundle-jobs/{job_id}`` 诊断包作业状态与进度
* ``POST /api/v1/bundle-jobs/{job_id}/cancel`` 取消诊断包作业（可跨重启生效）
* ``GET  /api/v1/bundle-jobs/{job_id}/audit`` 分页审计清单（带来源路径）
* ``GET  /api/v1/bundle-jobs/{job_id}/risks`` 分页残留风险（带来源路径）
* ``GET  /api/v1/bundle-jobs/{job_id}/manifest`` 处理清单（跳过/失败原因）
* ``GET  /api/v1/bundle-jobs/{job_id}/download`` 下载结果 ZIP（脱敏文件+清单）
* ``POST /api/v1/upload-sessions``      断点续传会话：声明类型/总字节/整体摘要/策略/关联域
* ``GET  /api/v1/upload-sessions/{session_id}`` 上传进度（已收/缺失区间）
* ``PUT  /api/v1/upload-sessions/{session_id}/chunks`` Content-Range 乱序分片上传
* ``POST /api/v1/upload-sessions/{session_id}/abort`` 终止会话并清理暂存
* ``POST /api/v1/upload-sessions/{session_id}/complete`` 校验完整性并转入脱敏作业
* ``GET  /api/v1/{jobs,stream-jobs,bundle-jobs}/{job_id}/receipt`` 完整性凭证查询
* ``GET  /api/v1/{jobs,stream-jobs,bundle-jobs}/{job_id}/receipt/download`` 凭证下载
* ``POST /api/v1/{jobs,stream-jobs,bundle-jobs}/{job_id}/receipt/verify`` 凭证校验
* ``GET/PUT/DELETE /api/v1/retention/...``  本地数据保留策略、保留锁、清理预览/执行/
  计划进度/重试与审计（预览不返回日志内容；目标变化拒绝执行；符号链接/越界拒绝删除）
* ``GET  /api/v1/sample/strategy``、``/sample/logs.ndjson``  可直接启动的示例
* ``GET  /healthz``                     健康检查（含主密钥指纹）

全部功能离线运行，不发起任何外部网络请求。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from contextlib import asynccontextmanager

from fastapi import Body, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.openapi.utils import get_openapi

from . import config, receipts, retention, upload_sessions
from .bundle_jobs import (
    build_manifest,
    bundle_registry,
    ensure_bundle_dirs,
    final_output_path as bundle_final_output_path,
    raw_path as bundle_raw_path,
    recover_bundle_jobs,
    run_bundle_job,
)
from .bundle_zip import BundleRejection, max_total_bytes, validate_bundle
from .crypto import (
    MasterKey,
    domain_id_hex,
    key_fingerprint,
    validate_token_context,
)
from .crypto import resolve_token_domain
from .database import Database, utcnow_iso
from .engine import run_strategy
from .parsing import ParsedBatch, PayloadError, parse_batch_indexed
from .models import (
    BatchPayload,
    CleanupExecuteRequest,
    CleanupPlanList,
    CleanupPlanModel,
    CleanupPreviewRequest,
    CleanupPreviewResponse,
    CreateJobRequest,
    CreateRetentionLockRequest,
    CreateUploadSessionRequest,
    DryRunRequest,
    JobDetail,
    JobList,
    JobModel,
    ReceiptVerifyResponse,
    RetentionAuditPage,
    RetentionLockList,
    RetentionLockModel,
    RetentionPolicyResponse,
    RunResult,
    Strategy,
    StrategyDiffRequest,
    StrategyDiffResponse,
    UploadSessionModel,
    UpsertRetentionRuleRequest,
)
from .samples import sample_ndjson, sample_strategy_dict
from .strategy_diff import run_strategy_diff
from .stream_jobs import (
    ensure_stream_dirs,
    final_output_path,
    raw_path,
    recover_stream_jobs,
    registry as stream_registry,
    run_stream_job,
)

MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MiB，小批量 JSON 接口的请求体上限
# 流式/诊断包上传走 multipart 落盘，不受小批量请求体上限约束
STREAM_UPLOAD_PATH = "/api/v1/stream-jobs"
BUNDLE_UPLOAD_PATH = "/api/v1/bundle-jobs"
# 断点续传分片（PUT .../chunks）流式落盘，同样豁免小批量请求体上限
UPLOAD_SESSIONS_PREFIX = "/api/v1/upload-sessions"
UPLOAD_CHUNK = 1024 * 1024  # 1 MiB：multipart 流式落盘的拷贝块大小

app = FastAPI(
    title="本地日志脱敏 API",
    version="1.7.0",
    description=(
        "供后端团队提交故障样本前使用的本地日志脱敏服务。支持按字段路径/键名/正则/内置识别器"
        "（邮箱、手机号、IP、访问令牌、身份证、银行卡）命中，动作包括删除、掩码与基于本地"
        "密钥的确定性令牌化；生成不含原值的审计清单，并对残留高风险内容标记需复核。\n\n"
        "## 令牌关联域（token_context）\n"
        "小批量、流式 NDJSON、诊断包与策略对照入口均可传 `token_context`（最长 128 字符）。"
        "服务用主密钥为上下文计算**不可逆域标识**并派生域专属子密钥：同一主密钥下，相同"
        "上下文与同一原值恒为同一替身，不同上下文必为不同替身。服务**只持久化域标识**"
        "（对外以域指纹 `dom:<hex>` 展示），**不保存上下文原文**；上下文无法从域指纹逆推。"
        "未传时沿用全局映射（域指纹 `global`，替身与历史行为完全一致）；`delete`/`mask` "
        "动作与关联域无关。流式作业与诊断包重启续跑自动沿用创建时的关联域。"
        "`Idempotency-Key` 同时绑定内容、策略与关联域，同键换域返回 409；策略对照的基线"
        "与候选共用同一关联域。\n\n"
        "**隐私取舍**：全局域便于跨作业/跨事件做等值关联分析，但替身本身也是跨批次的"
        "稳定连接键；隔离域切断跨上下文的等值连接（同一实体在不同事件中的替身不同），"
        "代价是失去跨域关联能力，且需要调用方自行记住上下文取值（服务无法替你找回）。\n\n"
        "## 策略变更对照（strategies/diff）\n"
        "在同一批 JSON/NDJSON 上以同一主密钥分别执行基线与候选策略（纯内存，不落库、不生成"
        "文件），按记录、行号、字段路径与内容命中位置（原文内偏移）对齐：汇总候选新增/失去的"
        "覆盖、动作变化、胜出规则变化与残留风险增减；仅规则改名且处理一致时不算覆盖改善。"
        "调用方可为新增残留风险、失去处理与输出类型变化设置上限，响应返回 pass/fail 与逐项"
        "依据供 CI 放行判定。差异项只含位置、规则、动作、识别器与计数，不回显原始值、正则"
        "文本或处理后仍含敏感信息的值。\n\n"
        "## 大批量 NDJSON 流式作业（stream-jobs）\n"
        "通过 multipart/form-data 上传大文件，原始文件以 0600 权限临时落盘，服务逐行解析、"
        "脱敏并定期写入安全检查点（字节偏移/记录数/审计数/风险数），不把整包读入内存；"
        "支持 Idempotency-Key 内容校验（同键不同内容返回 409）、取消、服务重启后从检查点"
        "继续、格式错误记录行号并终止；成功后原子发布结果文件，未完成作业不可下载。\n\n"
        "## 诊断包作业（bundle-jobs）\n"
        "通过 multipart/form-data 上传 ZIP 诊断包与脱敏策略，逐个处理包内 "
        ".json/.ndjson/.log/.txt 文件：结构化文件走字段+内容规则，纯文本按行应用内容规则，"
        "输出保留包内相对路径与原换行风格。拒绝路径穿越、符号链接、重复路径、加密条目及"
        "超过文件数/单文件/展开总量/压缩比上限的压缩包；二进制与不支持类型不写入结果，"
        "只在结果 ZIP 的 redaction-manifest.json 清单列明原因。审计与残留风险带来源路径"
        "与行号/记录位置，不含原值；同一 Idempotency-Key 仅在压缩包与策略均一致时回放，"
        "否则 409；支持进度查询、取消与重启续跑，终态清理原始包，成功后原子发布结果 ZIP。\n\n"
        "## 断点续传上传会话（upload-sessions）\n"
        "网络不稳时 NDJSON 与 ZIP 诊断包不必整包重传：先声明式创建会话（文件类型、"
        "总字节数、整体 SHA-256、脱敏策略与 token_context，可带 Idempotency-Key），"
        "再用 `Content-Range: bytes <start>-<end>/<total>` 乱序提交分片；分片以 0600 "
        "权限流式暂存并逐片登记 SHA-256 索引，进度接口返回已收/缺失区间。相同区间内容"
        "一致的重传幂等回放（200）；区间重叠冲突、越界或逐片摘要不符一律拒绝且保留已有"
        "分片。会话与分片索引在服务重启后恢复；过期或终止时清理暂存文件。完成时要求分片"
        "恰好覆盖全部字节并通过整体 SHA-256 校验：NDJSON 转入既有流式作业，ZIP 经原有"
        "安全检查后转入诊断包作业，策略、令牌关联域与 Idempotency-Key 全部沿用创建时的"
        "声明；完成后会话禁止继续写入。\n\n"
        "## 脱敏结果完整性凭证（receipt）\n"
        "小批量、流式 NDJSON 与诊断包作业在**成功发布结果**时生成独立 JSON 凭证：记录"
        "格式版本、输入与规范化策略摘要、关联域指纹、统计计数与输出文件摘要（诊断包另列"
        "结果 ZIP 内各文件的路径与摘要），**不含原始值、处理后值、策略正文或密钥材料**。"
        "凭证由主密钥派生的凭证子密钥按固定字段顺序计算 HMAC-SHA256 标签。三类作业均提供"
        "凭证查询、下载与校验接口；校验重算标签与现有结果摘要，区分凭证被改动、结果缺失、"
        "内容不符、密钥不匹配与格式不支持，**不重新脱敏、不返回文件内容**。取消/失败的"
        "异步作业不生成凭证；幂等回放指向同一凭证；重启后仍可校验已发布结果。\n\n"
        "## 本地数据保留与安全清理（retention）\n"
        "统一管理三类作业（小批量 `batch`、流式 NDJSON `stream`、诊断包 `bundle`）的"
        "记录、结果文件与完整性凭证的保留期限：可按**作业类型 × 终态 × 是否需复核**"
        "配置保留天数（含永久保留），内置默认策略可覆盖或删除自定义覆盖后回退；可为指定"
        "作业设置带原因与到期时间的**保留锁**。清理预览只返回待删作业、文件类别与预计"
        "释放空间，**不读取、不返回任何日志或审计内容**。执行清理必须回传预览摘要与"
        "目标指纹：目标发生变化（新增/删除文件、锁、期限等）一律拒绝（409）；保留锁"
        "未到期、运行中作业与复核期限未满的结果不得删除。执行先持久化清理计划，再仅在"
        "限定数据目录内删除文件并随后删除关联数据库记录；文件缺失按已删处理（幂等），"
        "符号链接与越界路径拒绝跟随并记录，部分失败可重试，**服务重启后自动继续**。"
    ),
    contact={"name": "platform-security"},
)

# 惰性初始化：导入模块时不在文件系统生成任何数据；测试也可直接替换这两个全局
db: Database | None = None
master_key: MasterKey | None = None


def get_db() -> Database:
    global db
    if db is None:
        db = Database()
    return db


def get_master_key() -> MasterKey:
    global master_key
    if master_key is None:
        master_key = MasterKey.load()
    return master_key


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # 服务启动：确保目录就位，并从安全检查点恢复未完成的流式/诊断包/清理/上传会话
    ensure_stream_dirs()
    ensure_bundle_dirs()
    upload_sessions.ensure_upload_dirs()
    recover_stream_jobs(get_db, get_master_key)
    recover_bundle_jobs(get_db, get_master_key)
    upload_sessions.recover_upload_sessions(get_db)
    retention.recover_cleanup_plans(get_db)
    yield


# app 在本函数之前构造，此处补挂生命周期（恢复未完成的流式作业）
app.router.lifespan_context = lifespan


def _parse_or_422(content: str, fmt: str) -> tuple[ParsedBatch, list[int | None]]:
    try:
        return parse_batch_indexed(content, fmt)
    except PayloadError as exc:
        detail = {"message": str(exc)}
        if exc.line is not None:
            detail["line"] = exc.line
        raise HTTPException(status_code=422, detail=detail) from exc


def _validate_form_token_context(token_context: str | None) -> str | None:
    """校验 multipart 表单中的 token_context（在拷贝上传文件之前调用）。

    非法请求直接 422，不创建任何临时文件或数据库记录。
    """
    try:
        return validate_token_context(token_context)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"message": str(exc)}) from exc


def _execute(payload: BatchPayload) -> tuple[ParsedBatch, RunResult]:
    parsed, _line_nos = _parse_or_422(payload.content, payload.format)
    token_key, domain_fp, _domain_id = resolve_token_domain(
        get_master_key(), payload.token_context
    )
    result = run_strategy(
        payload.strategy,
        parsed.records,
        token_key,
        is_ndjson=(payload.format == "ndjson"),
        domain_fingerprint=domain_fp,
    )
    # 审计展示的始终是主密钥指纹（隔离域下 token_key 是派生子密钥）
    result.key_fingerprint = key_fingerprint(get_master_key())
    return parsed, result


def _run_response(result: RunResult) -> dict[str, Any]:
    return result.model_dump(mode="json")


# ---------- 中间件：请求体大小限制 ----------


@app.middleware("http")
async def _limit_body(request: Request, call_next):
    # multipart 流式上传与断点续传分片逐块落盘、不读入内存，豁免小批量 10 MiB 上限
    path = request.url.path
    exempt = (
        request.method == "POST"
        and path in (STREAM_UPLOAD_PATH, BUNDLE_UPLOAD_PATH)
    ) or (
        request.method == "PUT"
        and path.startswith(UPLOAD_SESSIONS_PREFIX + "/")
        and path.endswith("/chunks")
    )
    cl = request.headers.get("content-length")
    if not exempt and cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={"message": f"请求体超过 {MAX_BODY_BYTES} 字节限制；"
                                f"大文件请改用 {STREAM_UPLOAD_PATH} multipart 上传"},
        )
    return await call_next(request)


# ---------- 健康与元信息 ----------


@app.get("/healthz", tags=["meta"], summary="健康检查")
def healthz() -> dict[str, str]:
    return {"status": "ok", "key_fingerprint": key_fingerprint(get_master_key())}


@app.get("/api/v1/sample/strategy", tags=["samples"], summary="示例脱敏策略")
def get_sample_strategy() -> dict[str, Any]:
    return sample_strategy_dict()


@app.get("/api/v1/sample/logs.ndjson", tags=["samples"], summary="示例 NDJSON 日志")
def get_sample_logs() -> Response:
    return Response(content=sample_ndjson(), media_type="application/x-ndjson; charset=utf-8")


# ---------- 策略 ----------


@app.post(
    "/api/v1/strategies/validate",
    tags=["strategy"],
    summary="策略试运行（dry-run）",
    description="按策略处理批次并返回脱敏结果、审计清单与残留风险；不写库、不产生作业、不生成文件。",
)
def validate_strategy(req: DryRunRequest) -> dict[str, Any]:
    _records, result = _execute(req)
    return {"mode": "dry-run", **_run_response(result)}


@app.post(
    "/api/v1/strategies/check",
    tags=["strategy"],
    summary="仅校验策略语法",
)
def check_strategy(strategy: Strategy) -> dict[str, Any]:
    return {"valid": True, "name": strategy.name, "rules": len(strategy.rules)}


@app.post(
    "/api/v1/strategies/diff",
    tags=["strategy"],
    summary="策略变更对照（基线 vs 候选，CI 放行判定）",
    description=(
        "在同一批 JSON/NDJSON 上以**同一主密钥**分别执行 `baseline` 与 `candidate` "
        "两份策略（纯内存对照：不写库、不产生作业、不生成文件），按记录、行号、字段路径"
        "与内容命中位置（原文内偏移）对齐，返回：\n\n"
        "* **覆盖增减**（coverage_gained/lost）：候选新增或失去的处理覆盖；仅规则改名"
        "（id/名称变化）而处理一致时记为胜出规则变化，**不算覆盖改善**；\n"
        "* **动作变化**（action_changes）：同一位置两侧均被处理但动作不同；\n"
        "* **胜出规则变化**（winner_changes）：动作一致但胜出规则 id 不同；\n"
        "* **输出类型变化**（type_changes）：同一叶子输出值的 JSON 类型名变化（不记录值）；\n"
        "* **残留风险增减**（risks_new/resolved）：按记录/行号/字段路径/识别器聚合计数。\n\n"
        "`limits` 可为新增残留风险、失去处理与输出类型变化设置上限，`passed` 与 `checks` "
        "给出 pass/fail 及逐项依据，供 CI 决定是否放行。NDJSON 空行占行号、规则顺序变化"
        "造成的重叠命中均按原文坐标稳定对齐；两份策略相同则差异为空。\n\n"
        "请求体可传 `token_context`（最长 128 字符）：**基线与候选共用同一关联域**"
        "执行（不传则共用全局域），因此对照不会因域隔离产生伪差异；服务只持久化"
        "不可逆域标识，不保存上下文原文。\n\n"
        "差异项只含位置、规则、动作、识别器与计数，**不回显原始值、正则文本或处理后仍含"
        "敏感信息的值**。"
    ),
    response_model=StrategyDiffResponse,
    responses={422: {"description": "日志内容解析失败或策略非法"}},
)
def diff_strategies(req: StrategyDiffRequest) -> StrategyDiffResponse:
    parsed, line_nos = _parse_or_422(req.content, req.format)
    token_key, domain_fp, _domain_id = resolve_token_domain(
        get_master_key(), req.token_context
    )
    return run_strategy_diff(
        parsed.records,
        line_nos,
        is_ndjson=(req.format == "ndjson"),
        baseline=req.baseline,
        candidate=req.candidate,
        limits=req.limits,
        key=token_key,
        master_key=get_master_key(),
        domain_fingerprint=domain_fp,
    )


# ---------- 作业 ----------


def _output_path(job_id: str, fmt: str) -> Path:
    suffix = "ndjson" if fmt == "ndjson" else "json"
    return config.settings.data_dir / "jobs" / f"{job_id}.{suffix}"


def _write_output(path: Path, records: list[Any], fmt: str, *, as_array: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "ndjson":
        text = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records)
    elif as_array:
        # 保留提交时的顶层数组结构，单元素数组也不能解包成对象
        text = json.dumps(records, ensure_ascii=False, indent=2) + "\n"
    else:
        text = json.dumps(records[0], ensure_ascii=False, indent=2) + "\n"
    path.write_text(text, encoding="utf-8")


@app.post(
    "/api/v1/jobs",
    tags=["jobs"],
    summary="正式创建脱敏作业",
    description=(
        "携带 `Idempotency-Key` 时，回放条件为**内容、规范化策略与令牌关联域**"
        "三者均与首次提交一致；任一不同返回 **409 冲突**，不会回放旧结果。"
        "请求体可传 `token_context`（最长 128 字符）启用令牌隔离域。"
    ),
    responses={
        200: {"description": "已有作业（幂等命中）"},
        201: {"description": "新作业已处理"},
        409: {"description": "Idempotency-Key 冲突（同键内容/策略/关联域不同）"},
        422: {"description": "日志解析失败、策略非法或 token_context 超长"},
    },
)
def create_job(
    req: CreateJobRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key",
                                         description="同一键只回放内容、策略与关联域均一致的提交"),
) -> JSONResponse:
    if idempotency_key is not None:
        idempotency_key = idempotency_key.strip()
        if len(idempotency_key) > 128:
            raise HTTPException(status_code=400, detail="Idempotency-Key 最长 128 字符")

    # 幂等三元组摘要：规范化内容字节 + 规范化策略 + 关联域标识
    content_bytes = req.content.encode("utf-8")
    content_sha = hashlib.sha256(content_bytes).hexdigest()
    strategy_canonical = req.strategy.model_dump_json()
    strategy_sha = hashlib.sha256(strategy_canonical.encode("utf-8")).hexdigest()
    domain_hex = domain_id_hex(get_master_key(), req.token_context)

    if idempotency_key is not None:
        row = get_db().get_idempotent(idempotency_key)
        if row:
            # 既回放也冲突判定，都必须在写任何文件/记录之前完成
            _check_idempotency_triplet(
                row, content_sha=content_sha, strategy_sha=strategy_sha,
                domain_id=domain_hex,
            )
            existing = get_db().get_job(row["id"])
            return JSONResponse(status_code=200, content={"replayed": True,
                                                          "job": _job_dict(existing)})  # type: ignore[arg-type]

    parsed, result = _execute(req)
    job_id = uuid.uuid4().hex
    filename = f"{job_id}.{req.format}"
    out_path = _output_path(job_id, req.format)
    _write_output(out_path, result.records, req.format,
                  as_array=parsed.top_level_is_array)
    # 完整性凭证与结果文件一同发布（只含摘要/指纹/计数，不落任何值）
    receipt_path = receipts.receipt_path_for_output(out_path)
    receipts.publish_batch_receipt(
        get_master_key(),
        job_id=job_id,
        fmt=req.format,
        content_sha256=content_sha,
        content_bytes=len(content_bytes),
        strategy_name=req.strategy.name,
        strategy_version=req.strategy.version,
        strategy_sha256=strategy_sha,
        domain_fingerprint=result.domain_fingerprint,
        stats=receipts.batch_stats(result.stats),
        output_path=out_path,
    )
    try:
        job = get_db().save_job(
            job_id=job_id,
            idempotency_key=idempotency_key,
            fmt=req.format,
            strategy_name=req.strategy.name,
            strategy_version=req.strategy.version,
            result_stats=result.stats,
            needs_review=result.needs_review,
            output_filename=filename,
            output_format=req.format,
            top_level_is_array=parsed.top_level_is_array,
            key_fingerprint=result.key_fingerprint,
            audit=result.audit,
            risks=result.risks,
            content_sha256=content_sha,
            strategy_sha256=strategy_sha,
            content_bytes=len(content_bytes),
            domain_id=domain_hex,
        )
    except sqlite3.IntegrityError:
        # 并发提交相同幂等键：对方先落库，回放或冲突（清理本请求的冗余文件）
        winner = get_db().get_idempotent(idempotency_key) if idempotency_key else None
        out_path.unlink(missing_ok=True)
        receipt_path.unlink(missing_ok=True)
        if winner:
            _check_idempotency_triplet(
                winner, content_sha=content_sha, strategy_sha=strategy_sha,
                domain_id=domain_hex,
            )
            return JSONResponse(status_code=200,
                                content={"replayed": True, "job": _job_dict(get_db().get_job(winner["id"]))})  # type: ignore[arg-type]
        raise
    return JSONResponse(
        status_code=201,
        content={"replayed": False, "job": _job_dict(job), "result": _run_response(result)},
    )


def _job_dict(job: JobModel) -> dict[str, Any]:
    d = job.model_dump(mode="json")
    d["download_url"] = f"/api/v1/jobs/{job.id}/download"
    return d


@app.get("/api/v1/jobs", response_model=JobList, tags=["jobs"], summary="查询作业列表")
def list_jobs(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    needs_review: bool | None = Query(default=None),
) -> JobList:
    items, total = get_db().list_jobs(limit=limit, offset=offset, needs_review=needs_review)
    return JobList(items=items, total=total)


def _require_job(job_id: str) -> JobModel:
    job = get_db().get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"作业不存在: {job_id}")
    return job


@app.get("/api/v1/jobs/{job_id}", response_model=JobDetail, tags=["jobs"],
         summary="查询作业结果（含审计与残留风险）")
def get_job(job_id: str) -> JobDetail:
    detail = get_db().get_job_detail(job_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"作业不存在: {job_id}")
    return detail


@app.get("/api/v1/jobs/{job_id}/records", tags=["jobs"],
         summary="读取脱敏后记录（JSON）")
def get_job_records(job_id: str) -> dict[str, Any]:
    job = _require_job(job_id)
    path = _output_path(job_id, job.format)
    if not path.exists():
        raise HTTPException(status_code=410, detail="输出文件已被清理")
    text = path.read_text("utf-8")
    if job.format == "ndjson":
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
        as_array = True
    else:
        parsed_file = json.loads(text)
        if isinstance(parsed_file, list):
            records = parsed_file
            as_array = True
        else:
            records = [parsed_file]
            as_array = False
    return {"job_id": job_id, "format": job.format,
            "top_level_is_array": as_array, "records": records}


@app.get("/api/v1/jobs/{job_id}/audit", tags=["jobs"], summary="仅取审计清单")
def get_job_audit(job_id: str) -> dict[str, Any]:
    detail = get_db().get_job_detail(job_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"作业不存在: {job_id}")
    return {"job_id": job_id, "count": len(detail.audit), "audit": detail.audit}


@app.get("/api/v1/jobs/{job_id}/download", tags=["jobs"],
         summary="下载脱敏文件（保持提交时的 JSON/NDJSON 格式）")
def download_job(job_id: str) -> Response:
    job = _require_job(job_id)
    path = _output_path(job_id, job.format)
    if not path.exists():
        raise HTTPException(status_code=410, detail="输出文件已被清理")
    media = "application/x-ndjson" if job.format == "ndjson" else "application/json"
    raw = path.read_bytes()
    return Response(
        content=raw,
        media_type=f"{media}; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="redacted-{job.output_filename}"'},
    )


# ---------- 大批量 NDJSON 流式作业 ----------


def _ensure_recovery() -> None:
    """未触发 lifespan 的部署形态（如测试/嵌入式）下惰性恢复一次。"""
    ensure_stream_dirs()
    recover_stream_jobs(get_db, get_master_key)


def _stream_job_dict(job) -> dict[str, Any]:
    return job.model_dump(mode="json")


def _idempotency_conflict(job_id: str, reason: str) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={
            "message": f"Idempotency-Key 已用于{reason}不同的上传",
            "existing_job_id": job_id,
        },
    )


def _check_idempotency_triplet(row, *, content_sha: str, strategy_sha: str,
                               domain_id: str | None) -> None:
    """幂等键同时绑定内容、策略与令牌关联域；任一不同即 409。

    ``domain_id`` 传 hex 串，全局域传 None；行内以空串表示全局域。
    """
    if row["content_sha256"] != content_sha:
        raise _idempotency_conflict(row["id"], "文件内容")
    if row["strategy_sha256"] != strategy_sha:
        raise _idempotency_conflict(row["id"], "策略")
    if row["domain_id"] != (domain_id or ""):
        raise _idempotency_conflict(row["id"], "令牌关联域")


def _require_stream_job(job_id: str):
    job = get_db().get_stream_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"流式作业不存在: {job_id}")
    return job


@app.post(
    "/api/v1/stream-jobs",
    tags=["stream-jobs"],
    summary="上传 NDJSON 大文件并创建流式脱敏作业",
    description=(
        "以 `multipart/form-data` 上传：`file` 为 NDJSON 文件，`strategy` 为策略 JSON，"
        "可选 `token_context` 为令牌关联域上下文（最长 128 字符）。"
        "原始文件以 **0600** 权限临时落盘，服务**逐行**解析脱敏（不把整包读入内存），"
        "并持续记录已处理字节数、记录数、审计数与残留风险数。\n\n"
        "携带 `token_context` 时，令牌化在该上下文的隔离域内进行：相同上下文与原值"
        "恒为同一替身、不同上下文必为不同替身；服务只持久化不可逆域标识（域指纹），"
        "**不保存上下文原文**；**重启续跑自动沿用原关联域**。不传则沿用全局映射；"
        "delete/mask 不受影响。\n\n"
        "携带 `Idempotency-Key` 时：相同键且**上传内容、规范化策略与令牌关联域**"
        "三者均一致才回放首个作业（200）；任一不同返回 **409 冲突**，不会回放旧结果。"
        "作业可取消，服务重启后从安全检查点继续；"
        "格式错误记录行号并终止。完成后原始文件即被删除并原子发布结果文件。"
    ),
    status_code=202,
    responses={
        200: {"description": "幂等命中，回放已有作业"},
        202: {"description": "已接受上传，后台流式处理中"},
        409: {"description": "Idempotency-Key 冲突（同键内容/策略/关联域不同）"},
        422: {"description": "策略非法、文件内容为空或 token_context 超长"},
    },
)
async def create_stream_job(
    strategy: str = Form(description="脱敏策略 JSON（与小批量接口同一结构）"),
    file: UploadFile = File(description="NDJSON 日志文件，每行一个 JSON 值"),
    token_context: str | None = Form(
        default=None,
        max_length=128,
        description="令牌关联域上下文（最长 128 字符）；只持久化不可逆域标识，"
                    "不传沿用全局映射，重启续跑自动沿用本作业的关联域",
    ),
    idempotency_key: str | None = Header(
        default=None, alias="Idempotency-Key",
        description="同一键只回放内容、策略与关联域均一致的上传；任一不同返回 409",
    ),
) -> JSONResponse:
    _ensure_recovery()

    # 非法 token_context 必须最先失败：不拷贝上传文件、不创建任何记录
    token_context = _validate_form_token_context(token_context)

    if idempotency_key is not None:
        idempotency_key = idempotency_key.strip()
        if len(idempotency_key) > 128:
            raise HTTPException(status_code=400, detail="Idempotency-Key 最长 128 字符")

    # 关联域在拷贝大文件之前解析（同时校验主密钥可用）；只保留不可逆域标识
    domain_hex = domain_id_hex(get_master_key(), token_context)

    # 先校验策略（在拷贝大文件之前快速失败）
    try:
        strategy_model = Strategy.model_validate_json(strategy)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"message": f"策略校验失败：{exc}"}) from exc
    # 规范化策略（Pydantic 规范序列化）后取摘要：键顺序/空白差异不算不同策略，
    # 规则内容差异必然体现为不同摘要，并参与幂等一致性判断
    strategy_canonical = strategy_model.model_dump_json()
    strategy_sha = hashlib.sha256(strategy_canonical.encode("utf-8")).hexdigest()

    job_id = uuid.uuid4().hex
    ensure_stream_dirs()
    staged = raw_path(job_id)

    # 逐块拷贝到 0600 临时文件：先以安全权限创建，再流式写入，避免权限窗口
    digest = hashlib.sha256()
    bytes_total = 0
    fd = os.open(str(staged), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        while True:
            chunk = await file.read(UPLOAD_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            bytes_total += len(chunk)
            os.write(fd, chunk)
        os.fsync(fd)
    finally:
        os.close(fd)
        await file.close()
    os.chmod(staged, 0o600)

    if bytes_total == 0:
        staged.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail={"message": "上传文件为空"})

    content_sha = digest.hexdigest()
    source_name = Path(file.filename or "upload.ndjson").name

    # 幂等：同键且文件+策略+关联域都一致才回放，任一不同返回冲突（临时文件立即清理）
    if idempotency_key:
        row = get_db().get_stream_idempotent(idempotency_key)
        if row is not None:
            staged.unlink(missing_ok=True)
            _check_idempotency_triplet(
                row, content_sha=content_sha, strategy_sha=strategy_sha,
                domain_id=domain_hex,
            )
            existing = get_db().get_stream_job(row["id"])
            return JSONResponse(
                status_code=200,
                content={"replayed": True, "job": _stream_job_dict(existing)},
            )

    try:
        job = get_db().create_stream_job(
            job_id=job_id,
            idempotency_key=idempotency_key,
            strategy_json=strategy_canonical,
            strategy_sha256=strategy_sha,
            source_filename=source_name,
            content_sha256=content_sha,
            bytes_total=bytes_total,
            key_fingerprint=key_fingerprint(get_master_key()),
            domain_id=domain_hex,
        )
    except sqlite3.IntegrityError:
        # 并发使用相同幂等键：以先落库者为准
        staged.unlink(missing_ok=True)
        winner = (
            get_db().get_stream_idempotent(idempotency_key) if idempotency_key else None
        )
        if winner:
            existing = get_db().get_stream_job(winner["id"])
            _check_idempotency_triplet(
                winner, content_sha=content_sha, strategy_sha=strategy_sha,
                domain_id=domain_hex,
            )
            return JSONResponse(
                status_code=200,
                content={"replayed": True, "job": _stream_job_dict(existing)},
            )
        raise

    stream_registry.start(
        job_id, lambda: run_stream_job(job_id, get_db, get_master_key)
    )
    job = get_db().get_stream_job(job_id)
    return JSONResponse(
        status_code=202, content={"replayed": False, "job": _stream_job_dict(job)}
    )


@app.get("/api/v1/stream-jobs", tags=["stream-jobs"],
         summary="流式作业列表（可按状态过滤、分页）")
def list_stream_jobs(
    status: str | None = Query(default=None,
                               description="queued/running/succeeded/failed/cancelled"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    if status is not None and status not in (
        "queued", "running", "succeeded", "failed", "cancelled"
    ):
        raise HTTPException(status_code=400, detail="非法 status 过滤值")
    _ensure_recovery()
    items, total = get_db().list_stream_jobs(status=status, limit=limit, offset=offset)
    return {"total": total, "limit": limit, "offset": offset,
            "items": [i.model_dump(mode="json") for i in items]}


@app.get("/api/v1/stream-jobs/{job_id}", tags=["stream-jobs"],
         summary="流式作业状态与实时进度",
         description="返回作业状态、已处理字节数/记录数/审计数/风险数与进度百分比；"
                     "失败时带格式错误行号。")
def get_stream_job(job_id: str) -> dict[str, Any]:
    _ensure_recovery()
    job = _require_stream_job(job_id)
    return _stream_job_dict(job)


@app.post("/api/v1/stream-jobs/{job_id}/cancel", tags=["stream-jobs"],
          summary="取消流式作业",
          description="取消意图同时写入内存与数据库（重启后仍生效）；worker 在检查点"
                      "边界停止，状态置为 cancelled，原始文件与未完成输出被清理。",
          responses={409: {"description": "作业已终结，无法取消"}})
def cancel_stream_job(job_id: str) -> dict[str, Any]:
    job = _require_stream_job(job_id)
    if job.status not in ("queued", "running"):
        raise HTTPException(
            status_code=409,
            detail={"message": f"作业已处于终态 {job.status}，无法取消",
                    "status": job.status},
        )
    get_db().request_stream_cancel(job_id)
    stream_registry.request_cancel(job_id)
    latest = get_db().get_stream_job(job_id)
    return {"cancelling": True, "job": _stream_job_dict(latest)}


@app.get("/api/v1/stream-jobs/{job_id}/audit", tags=["stream-jobs"],
         summary="分页查询流式作业的审计清单（不含原始值）")
def get_stream_job_audit(
    job_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    _require_stream_job(job_id)
    page = get_db().paginate_stream_audit(job_id, limit=limit, offset=offset)
    return page.model_dump(mode="json")


@app.get("/api/v1/stream-jobs/{job_id}/risks", tags=["stream-jobs"],
         summary="分页查询流式作业的残留风险")
def get_stream_job_risks(
    job_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    _require_stream_job(job_id)
    page = get_db().paginate_stream_risks(job_id, limit=limit, offset=offset)
    return page.model_dump(mode="json")


@app.get("/api/v1/stream-jobs/{job_id}/download", tags=["stream-jobs"],
         summary="下载已完成的 NDJSON 脱敏结果",
         description="仅 succeeded 作业可下载（原子发布的结果文件）；"
                     "排队/运行/失败/取消的作业返回 409。",
         responses={409: {"description": "作业未完成，结果不可下载"}})
def download_stream_job(job_id: str):
    job = _require_stream_job(job_id)
    if job.status != "succeeded":
        raise HTTPException(
            status_code=409,
            detail={"message": f"作业状态为 {job.status}，未完成作业不得下载",
                    "status": job.status},
        )
    path = final_output_path(job_id)
    if not path.exists():
        raise HTTPException(status_code=410, detail="结果文件已被清理")
    return FileResponse(
        path,
        media_type="application/x-ndjson; charset=utf-8",
        filename=f"redacted-{job_id}.ndjson",
    )


# ---------- 诊断包（ZIP）作业 ----------


def _ensure_bundle_recovery() -> None:
    """未触发 lifespan 的部署形态（如测试/嵌入式）下惰性恢复一次。"""
    ensure_bundle_dirs()
    recover_bundle_jobs(get_db, get_master_key)


def _bundle_job_dict(job) -> dict[str, Any]:
    return job.model_dump(mode="json")


def _require_bundle_job(job_id: str):
    job = get_db().get_bundle_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"诊断包作业不存在: {job_id}")
    return job


@app.post(
    "/api/v1/bundle-jobs",
    tags=["bundle-jobs"],
    summary="上传 ZIP 诊断包并创建脱敏作业",
    description=(
        "以 `multipart/form-data` 上传：`file` 为 ZIP 诊断包，`strategy` 为策略 JSON，"
        "可选 `token_context` 为令牌关联域上下文（最长 128 字符）。"
        "逐个处理包内 `.json`/`.ndjson`/`.log`/`.txt`：结构化文件走字段+内容规则，"
        "纯文本按行应用内容规则，输出保留包内相对路径与原换行风格。\n\n"
        "压缩包先过安全校验：拒绝路径穿越、符号链接、重复路径、加密条目，以及超过"
        "文件数/单文件/展开总量/压缩比上限的包（422 并列出全部原因）。二进制与不支持"
        "类型不写入结果，只在清单列明原因。携带 `token_context` 时令牌化在隔离域内进行，"
        "服务只持久化不可逆域标识（域指纹），**不保存上下文原文**，**重启续跑自动沿用"
        "原关联域**，清单与状态返回域指纹；不传则沿用全局映射。携带 `Idempotency-Key` "
        "时：相同键且**压缩包、规范化策略与令牌关联域**三者均一致才回放首个作业（200），"
        "任一不同返回 **409**。作业可取消、可在服务重启后从文件级检查点续跑；"
        "终态清理原始压缩包，成功后原子发布结果 ZIP（仅含脱敏文件与 "
        "redaction-manifest.json 清单）。"
    ),
    status_code=202,
    responses={
        200: {"description": "幂等命中，回放已有作业"},
        202: {"description": "已接受上传，后台处理中"},
        409: {"description": "Idempotency-Key 冲突（同键内容/策略/关联域不同）"},
        413: {"description": "压缩包超过上传大小上限"},
        422: {"description": "策略非法、压缩包为空、未通过安全校验或 token_context 超长"},
    },
)
async def create_bundle_job(
    strategy: str = Form(description="脱敏策略 JSON（与小批量接口同一结构）"),
    file: UploadFile = File(description="ZIP 诊断包（.json/.ndjson/.log/.txt 会被处理）"),
    token_context: str | None = Form(
        default=None,
        max_length=128,
        description="令牌关联域上下文（最长 128 字符）；只持久化不可逆域标识，"
                    "不传沿用全局映射，重启续跑自动沿用本作业的关联域",
    ),
    idempotency_key: str | None = Header(
        default=None, alias="Idempotency-Key",
        description="同一键只回放压缩包、策略与关联域均一致的上传；任一不同返回 409",
    ),
) -> JSONResponse:
    _ensure_bundle_recovery()

    # 非法 token_context 必须最先失败：不拷贝上传文件、不创建任何记录
    token_context = _validate_form_token_context(token_context)

    if idempotency_key is not None:
        idempotency_key = idempotency_key.strip()
        if len(idempotency_key) > 128:
            raise HTTPException(status_code=400, detail="Idempotency-Key 最长 128 字符")

    # 关联域在拷贝大文件之前解析；只保留不可逆域标识
    domain_hex = domain_id_hex(get_master_key(), token_context)

    # 先校验策略（在拷贝大文件之前快速失败）
    try:
        strategy_model = Strategy.model_validate_json(strategy)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"message": f"策略校验失败：{exc}"}) from exc
    # 规范化策略后取摘要：键顺序/空白差异不算不同策略
    strategy_canonical = strategy_model.model_dump_json()
    strategy_sha = hashlib.sha256(strategy_canonical.encode("utf-8")).hexdigest()

    job_id = uuid.uuid4().hex
    ensure_bundle_dirs()
    staged = bundle_raw_path(job_id)

    # 逐块拷贝到 0600 临时文件；压缩态大小不得超过展开总量上限
    digest = hashlib.sha256()
    bytes_total = 0
    upload_cap = max_total_bytes()
    fd = os.open(str(staged), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        while True:
            chunk = await file.read(UPLOAD_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            bytes_total += len(chunk)
            if bytes_total > upload_cap:
                raise HTTPException(
                    status_code=413,
                    detail={"message": f"压缩包超过上传大小上限（{upload_cap} 字节）"},
                )
            os.write(fd, chunk)
        os.fsync(fd)
    except Exception:
        staged.unlink(missing_ok=True)
        raise
    finally:
        os.close(fd)
        await file.close()
    os.chmod(staged, 0o600)

    if bytes_total == 0:
        staged.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail={"message": "上传文件为空"})

    # 安全校验：不安全的压缩包整体拒绝（422 并列出全部原因）
    try:
        entries = validate_bundle(staged)
    except BundleRejection as exc:
        staged.unlink(missing_ok=True)
        raise HTTPException(
            status_code=422,
            detail={"message": "压缩包未通过安全校验", "reasons": exc.reasons},
        ) from exc

    content_sha = digest.hexdigest()
    source_name = Path(file.filename or "bundle.zip").name

    # 幂等：同键且压缩包+策略+关联域都一致才回放，任一不同返回冲突（临时文件立即清理）
    if idempotency_key:
        row = get_db().get_bundle_idempotent(idempotency_key)
        if row is not None:
            staged.unlink(missing_ok=True)
            _check_idempotency_triplet(
                row, content_sha=content_sha, strategy_sha=strategy_sha,
                domain_id=domain_hex,
            )
            existing = get_db().get_bundle_job(row["id"])
            return JSONResponse(
                status_code=200,
                content={"replayed": True, "job": _bundle_job_dict(existing)},
            )

    try:
        job = get_db().create_bundle_job(
            job_id=job_id,
            idempotency_key=idempotency_key,
            strategy_json=strategy_canonical,
            strategy_sha256=strategy_sha,
            source_filename=source_name,
            content_sha256=content_sha,
            bytes_total=bytes_total,
            files_total=len(entries),
            key_fingerprint=key_fingerprint(get_master_key()),
            domain_id=domain_hex,
        )
    except sqlite3.IntegrityError:
        # 并发使用相同幂等键：以先落库者为准
        staged.unlink(missing_ok=True)
        winner = (
            get_db().get_bundle_idempotent(idempotency_key) if idempotency_key else None
        )
        if winner:
            existing = get_db().get_bundle_job(winner["id"])
            _check_idempotency_triplet(
                winner, content_sha=content_sha, strategy_sha=strategy_sha,
                domain_id=domain_hex,
            )
            return JSONResponse(
                status_code=200,
                content={"replayed": True, "job": _bundle_job_dict(existing)},
            )
        raise

    bundle_registry.start(
        job_id, lambda: run_bundle_job(job_id, get_db, get_master_key)
    )
    job = get_db().get_bundle_job(job_id)
    return JSONResponse(
        status_code=202, content={"replayed": False, "job": _bundle_job_dict(job)}
    )


@app.get("/api/v1/bundle-jobs", tags=["bundle-jobs"],
         summary="诊断包作业列表（可按状态过滤、分页）")
def list_bundle_jobs(
    status: str | None = Query(default=None,
                               description="queued/running/succeeded/failed/cancelled"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    if status is not None and status not in (
        "queued", "running", "succeeded", "failed", "cancelled"
    ):
        raise HTTPException(status_code=400, detail="非法 status 过滤值")
    _ensure_bundle_recovery()
    items, total = get_db().list_bundle_jobs(status=status, limit=limit, offset=offset)
    return {"total": total, "limit": limit, "offset": offset,
            "items": [i.model_dump(mode="json") for i in items]}


@app.get("/api/v1/bundle-jobs/{job_id}", tags=["bundle-jobs"],
         summary="诊断包作业状态与进度",
         description="返回作业状态、文件/记录/审计/风险计数、当前处理文件与进度百分比。")
def get_bundle_job(job_id: str) -> dict[str, Any]:
    _ensure_bundle_recovery()
    job = _require_bundle_job(job_id)
    return _bundle_job_dict(job)


@app.post("/api/v1/bundle-jobs/{job_id}/cancel", tags=["bundle-jobs"],
          summary="取消诊断包作业",
          description="取消意图同时写入内存与数据库（重启后仍生效）；worker 在文件"
                      "边界停止，状态置为 cancelled，原始压缩包与暂存输出被清理。",
          responses={409: {"description": "作业已终结，无法取消"}})
def cancel_bundle_job(job_id: str) -> dict[str, Any]:
    job = _require_bundle_job(job_id)
    if job.status not in ("queued", "running"):
        raise HTTPException(
            status_code=409,
            detail={"message": f"作业已处于终态 {job.status}，无法取消",
                    "status": job.status},
        )
    get_db().request_bundle_cancel(job_id)
    bundle_registry.request_cancel(job_id)
    latest = get_db().get_bundle_job(job_id)
    return {"cancelling": True, "job": _bundle_job_dict(latest)}


@app.get("/api/v1/bundle-jobs/{job_id}/audit", tags=["bundle-jobs"],
         summary="分页查询诊断包作业的审计清单（带来源路径，不含原始值）")
def get_bundle_job_audit(
    job_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    _require_bundle_job(job_id)
    page = get_db().paginate_bundle_audit(job_id, limit=limit, offset=offset)
    return page.model_dump(mode="json")


@app.get("/api/v1/bundle-jobs/{job_id}/risks", tags=["bundle-jobs"],
         summary="分页查询诊断包作业的残留风险（带来源路径）")
def get_bundle_job_risks(
    job_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    _require_bundle_job(job_id)
    page = get_db().paginate_bundle_risks(job_id, limit=limit, offset=offset)
    return page.model_dump(mode="json")


@app.get("/api/v1/bundle-jobs/{job_id}/manifest", tags=["bundle-jobs"],
         summary="诊断包处理清单（每个文件的状态与跳过/失败原因）",
         description="与结果 ZIP 内的 redaction-manifest.json 同源；未完成的作业"
                     "返回截至当前的进度清单（completed_at 为 null）。")
def get_bundle_job_manifest(job_id: str) -> dict[str, Any]:
    job = _require_bundle_job(job_id)
    files = get_db().bundle_files_for_manifest(job_id)
    completed_at = job.updated_at if job.status == "succeeded" else None
    return build_manifest(job, files, completed_at=completed_at)


@app.get("/api/v1/bundle-jobs/{job_id}/download", tags=["bundle-jobs"],
         summary="下载已完成的结果 ZIP（脱敏文件 + 清单）",
         description="仅 succeeded 作业可下载（原子发布的结果 ZIP）；"
                     "排队/运行/失败/取消的作业返回 409。",
         responses={409: {"description": "作业未完成，结果不可下载"}})
def download_bundle_job(job_id: str):
    job = _require_bundle_job(job_id)
    if job.status != "succeeded":
        raise HTTPException(
            status_code=409,
            detail={"message": f"作业状态为 {job.status}，未完成作业不得下载",
                    "status": job.status},
        )
    path = bundle_final_output_path(job_id)
    if not path.exists():
        raise HTTPException(status_code=410, detail="结果文件已被清理")
    name = Path(job.source_filename).name or "bundle.zip"
    if not name.lower().endswith(".zip"):
        name += ".zip"
    return FileResponse(
        path,
        media_type="application/zip",
        filename=f"redacted-{name}",
    )


# ---------- 断点续传上传会话 ----------


def _ensure_upload_recovery() -> None:
    """未触发 lifespan 的部署形态（如测试/嵌入式）下惰性恢复一次。"""
    upload_sessions.ensure_upload_dirs()
    upload_sessions.recover_upload_sessions(get_db)


def _require_upload_session(session_id: str):
    row = get_db().get_upload_session(session_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"上传会话不存在: {session_id}")
    return row


def _lazy_expire_session(row):
    """访问时惰性过期：到期的 uploading 会话置为 expired 并清理暂存。"""
    if row["status"] == "uploading" and row["expires_at"] <= utcnow_iso():
        upload_sessions.abort_session(get_db(), row["id"], status="expired")
        row = get_db().get_upload_session(row["id"])
    return row


def _session_not_uploading(row) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={"message": f"会话状态为 {row['status']}，不再接受分片写入",
                "status": row["status"]},
    )


def _session_view(row) -> dict[str, Any]:
    return upload_sessions.session_to_model(row, get_db())


def _validate_idempotency_header(idempotency_key: str | None) -> str | None:
    if idempotency_key is not None:
        idempotency_key = idempotency_key.strip()
        if len(idempotency_key) > 128:
            raise HTTPException(status_code=400, detail="Idempotency-Key 最长 128 字符")
    return idempotency_key


def _session_declaration_matches(row, *, kind: str, bytes_total: int,
                                 content_sha: str, strategy_sha: str,
                                 domain_id: str | None) -> bool:
    """会话级幂等回放判定：声明五元组（类型/总字节/整体摘要/策略/关联域）一致。"""
    return (
        row["kind"] == kind
        and row["bytes_total"] == bytes_total
        and row["content_sha256"] == content_sha
        and row["strategy_sha256"] == strategy_sha
        and (row["domain_id"] or "") == (domain_id or "")
    )


def _job_row_for_session(kind: str, job_id: str):
    if kind == "ndjson":
        return get_db().get_stream_job(job_id)
    return get_db().get_bundle_job(job_id)


def _job_dict_for_session(kind: str, job_id: str) -> dict[str, Any] | None:
    job = _job_row_for_session(kind, job_id)
    if job is None:
        return None
    return job.model_dump(mode="json")


@app.post(
    "/api/v1/upload-sessions",
    tags=["upload-sessions"],
    summary="创建断点续传上传会话（声明类型/总字节/整体摘要/策略/关联域）",
    description=(
        "网络不稳时不必整包重传：先创建会话，声明 `kind`（ndjson/zip）、"
        "`bytes_total`（总字节数）、`content_sha256`（整体 SHA-256）、脱敏策略与"
        "可选 `token_context`（最长 128 字符，只持久化不可逆域标识）；随后用 "
        "`PUT .../chunks` 按 `Content-Range` 乱序提交分片，全部覆盖后调用 "
        "`.../complete` 转入对应的脱敏作业。\n\n"
        "会话默认 24 小时过期（`expires_in_seconds` 可调，最长 7 天）；过期或终止"
        "时暂存文件被清理。携带 `Idempotency-Key` 时：相同键且**类型、总字节、整体"
        "摘要、规范化策略与关联域**五者一致才回放既有会话（200），任一不同返回 "
        "**409**；该键在完成时继续绑定转入的流式/诊断包作业。"
    ),
    status_code=201,
    responses={
        200: {"description": "幂等命中，回放既有会话"},
        201: {"description": "会话已创建，可开始上传分片"},
        400: {"description": "Idempotency-Key 非法"},
        409: {"description": "Idempotency-Key 冲突（同键声明不同）"},
        413: {"description": "ZIP 声明大小超过上传上限"},
        422: {"description": "策略非法、摘要格式非法或 token_context 超长"},
    },
)
def create_upload_session(
    req: CreateUploadSessionRequest,
    idempotency_key: str | None = Header(
        default=None, alias="Idempotency-Key",
        description="同一键只回放声明（类型/总字节/摘要/策略/关联域）一致的会话；"
                    "完成时该键继续绑定转入的脱敏作业",
    ),
) -> JSONResponse:
    _ensure_upload_recovery()
    idempotency_key = _validate_idempotency_header(idempotency_key)

    # 关联域在创建任何文件/记录之前解析；只持久化不可逆域标识
    domain_hex = domain_id_hex(get_master_key(), req.token_context)

    strategy_canonical = req.strategy.model_dump_json()
    strategy_sha = hashlib.sha256(strategy_canonical.encode("utf-8")).hexdigest()

    # ZIP 声明大小不得超过展开总量上限（与 multipart 上传同一约束）
    if req.kind == "zip" and req.bytes_total > max_total_bytes():
        raise HTTPException(
            status_code=413,
            detail={"message": f"声明的压缩包大小超过上传上限（{max_total_bytes()} 字节）"},
        )

    default_name = "upload.ndjson" if req.kind == "ndjson" else "bundle.zip"
    source_name = Path(req.source_filename or default_name).name or default_name

    if idempotency_key:
        # 会话级回放：五元组一致回放，任一不同 409
        existing = get_db().get_upload_session_by_idempotency(idempotency_key)
        if existing is not None:
            if not _session_declaration_matches(
                existing, kind=req.kind, bytes_total=req.bytes_total,
                content_sha=req.content_sha256, strategy_sha=strategy_sha,
                domain_id=domain_hex,
            ):
                raise HTTPException(
                    status_code=409,
                    detail={"message": "Idempotency-Key 已用于声明不同的上传会话",
                            "existing_session_id": existing["id"]},
                )
            return JSONResponse(
                status_code=200,
                content={"replayed": True, "session": _session_view(existing)},
            )
        # 快速失败：该键已绑定到内容/策略/关联域不同的既有作业
        row = (get_db().get_stream_idempotent(idempotency_key)
               if req.kind == "ndjson"
               else get_db().get_bundle_idempotent(idempotency_key))
        if row is not None:
            _check_idempotency_triplet(
                row, content_sha=req.content_sha256, strategy_sha=strategy_sha,
                domain_id=domain_hex,
            )

    session_id = uuid.uuid4().hex
    ttl = req.expires_in_seconds or upload_sessions.session_ttl_seconds()
    expires_at = (
        datetime.now(timezone.utc) + timedelta(seconds=ttl)
    ).isoformat(timespec="seconds")

    # 先建 0600 暂存文件，再落库；落库失败（并发同键）立即清理
    staged = upload_sessions.create_staged_file(session_id)
    try:
        row = get_db().create_upload_session(
            session_id=session_id,
            idempotency_key=idempotency_key,
            kind=req.kind,
            source_filename=source_name,
            bytes_total=req.bytes_total,
            content_sha256=req.content_sha256,
            strategy_json=strategy_canonical,
            strategy_sha256=strategy_sha,
            domain_id=domain_hex,
            key_fingerprint=key_fingerprint(get_master_key()),
            expires_at=expires_at,
        )
    except sqlite3.IntegrityError:
        staged.unlink(missing_ok=True)
        winner = (
            get_db().get_upload_session_by_idempotency(idempotency_key)
            if idempotency_key else None
        )
        if winner is not None:
            if not _session_declaration_matches(
                winner, kind=req.kind, bytes_total=req.bytes_total,
                content_sha=req.content_sha256, strategy_sha=strategy_sha,
                domain_id=domain_hex,
            ):
                raise HTTPException(
                    status_code=409,
                    detail={"message": "Idempotency-Key 已用于声明不同的上传会话",
                            "existing_session_id": winner["id"]},
                )
            return JSONResponse(
                status_code=200,
                content={"replayed": True, "session": _session_view(winner)},
            )
        raise
    return JSONResponse(
        status_code=201, content={"replayed": False, "session": _session_view(row)}
    )


@app.get(
    "/api/v1/upload-sessions/{session_id}",
    tags=["upload-sessions"],
    summary="上传会话状态与进度（已收/缺失区间）",
    description="返回会话状态、已接收字节区间（合并相邻后）、仍缺失区间与进度百分比；"
                "客户端据此只重传缺失分片。",
    response_model=UploadSessionModel,
    responses={404: {"description": "会话不存在"}},
)
def get_upload_session(session_id: str) -> dict[str, Any]:
    _ensure_upload_recovery()
    row = _lazy_expire_session(_require_upload_session(session_id))
    return _session_view(row)


def _parse_chunk_digest_header(value: str | None) -> str | None:
    if value is None:
        return None
    digest = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise HTTPException(
            status_code=400,
            detail={"message": "X-Chunk-SHA256 必须是 64 位 hex 的 SHA-256 摘要"},
        )
    return digest


async def _drain_chunk_body(request: Request, fd: int, offset: int,
                            limit: int) -> tuple[str, int]:
    """把请求体流式写入 fd 的 [offset, offset+limit) 区域，返回 (sha256, 实际字节数)。

    逐块 pwrite 落盘、不读入内存；超出声明长度的字节不落盘也不计入摘要
    （调用方据实际长度与声明长度不符拒绝请求）。
    """
    digest = hashlib.sha256()
    received = 0
    pos = offset
    async for block in request.stream():
        if not block:
            continue
        received += len(block)
        overflow = received - limit
        keep = block if overflow <= 0 else block[: len(block) - overflow]
        if keep:
            digest.update(keep)
            os.pwrite(fd, keep, pos)
            pos += len(keep)
    return digest.hexdigest(), received


def _check_chunk_length(declared_sha: str | None, computed_sha: str,
                        received: int, expected: int) -> None:
    """长度与逐片摘要校验：不符即拒绝（已写入的未登记字节不进索引，无害）。"""
    if received != expected:
        raise HTTPException(
            status_code=400,
            detail={"message": f"请求体长度 {received} 与 Content-Range 声明的 "
                               f"{expected} 字节不符"},
        )
    if declared_sha is not None and declared_sha != computed_sha:
        raise HTTPException(
            status_code=422,
            detail={"message": "分片内容与 X-Chunk-SHA256 声明的摘要不符"},
        )


@app.put(
    "/api/v1/upload-sessions/{session_id}/chunks",
    tags=["upload-sessions"],
    summary="按 Content-Range 上传一个分片（可乱序、可幂等重传）",
    description=(
        "请求头 `Content-Range: bytes <start>-<end>/<total>` 声明分片区间"
        "（`end` 为闭区间，`<total>` 必须等于会话声明的总字节数），请求体为该区间"
        "的原始字节；可选 `X-Chunk-SHA256` 声明本分片摘要（不符即 422）。\n\n"
        "* 分片以 **0600** 权限流式暂存并 fsync 后才登记索引，服务重启后进度不丢；\n"
        "* **相同区间、内容一致**的重传幂等回放（200，`replayed=true`），不重复落盘；\n"
        "* 与已登记分片**重叠冲突**、区间**越界**/总长不符、或同区间**摘要不符**一律"
        "拒绝（409），**已有分片原样保留**；\n"
        "* 会话完成/终止/过期后禁止继续写入（409）。"
    ),
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/octet-stream": {
                    "schema": {"type": "string", "format": "binary",
                               "description": "Content-Range 声明区间的原始字节"}
                }
            },
        }
    },
    responses={
        200: {"description": "分片已登记（或幂等回放）"},
        400: {"description": "Content-Range 格式非法或请求体长度与声明不符"},
        404: {"description": "会话不存在"},
        409: {"description": "区间越界/总长不符、重叠冲突、同区间摘要不符或会话已终态"},
        422: {"description": "分片内容与 X-Chunk-SHA256 声明摘要不符"},
    },
)
async def put_upload_chunk(
    session_id: str,
    request: Request,
    content_range: str | None = Header(
        default=None, alias="Content-Range",
        description="bytes <start>-<end>/<total>（end 闭区间；total 须等于会话声明总长）",
    ),
    x_chunk_sha256: str | None = Header(
        default=None, alias="X-Chunk-SHA256",
        description="可选：本分片内容的 SHA-256（64 位 hex），不符即拒绝",
    ),
) -> dict[str, Any]:
    _ensure_upload_recovery()
    row = _lazy_expire_session(_require_upload_session(session_id))
    if row["status"] != "uploading":
        raise _session_not_uploading(row)

    bytes_total = row["bytes_total"]
    try:
        start, end = upload_sessions.parse_content_range(content_range, bytes_total)
    except upload_sessions.ContentRangeError as exc:
        raise HTTPException(
            status_code=409 if exc.out_of_bounds else 400,
            detail={"message": str(exc)},
        ) from exc
    expected = end - start
    declared_sha = _parse_chunk_digest_header(x_chunk_sha256)

    # 同一会话的分片写入/索引登记串行化，避免索引与暂存文件竞争
    lock = upload_sessions.session_lock(session_id)
    with lock:
        row = _lazy_expire_session(_require_upload_session(session_id))
        if row["status"] != "uploading":
            raise _session_not_uploading(row)

        overlapping = get_db().find_overlapping_chunks(session_id, start, end)
        exact = (
            overlapping[0]
            if len(overlapping) == 1
            and overlapping[0]["start"] == start
            and overlapping[0]["end"] == end
            else None
        )
        if overlapping and exact is None:
            conflicts = [
                {"start": c["start"], "end": c["end"], "bytes": c["end"] - c["start"]}
                for c in overlapping
            ]
            raise HTTPException(
                status_code=409,
                detail={"message": "分片区间与已登记分片重叠冲突，已有分片保持不变",
                        "conflicting_ranges": conflicts},
            )

        if exact is not None:
            # 同区间重传：内容一致才幂等回放；先落到临时文件比对，绝不动已登记分片
            tmp = upload_sessions.uploads_dir() / f".tmp-{session_id}-{uuid.uuid4().hex}"
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                computed, received = await _drain_chunk_body(request, fd, 0, expected)
            finally:
                os.close(fd)
            tmp.unlink(missing_ok=True)
            _check_chunk_length(declared_sha, computed, received, expected)
            if computed != exact["sha256"]:
                raise HTTPException(
                    status_code=409,
                    detail={"message": "相同区间的重传内容与已登记分片摘要不符，"
                                       "已有分片保持不变"},
                )
            return {"replayed": True, "session": _session_view(row)}

        # 新区间：直接流式写入暂存文件对应偏移，fsync 后登记索引
        # （恢复对账重置索引后暂存文件可能缺失，此处按 0600 惰性重建）
        staged = upload_sessions.ensure_staged_file(session_id)
        fd = os.open(str(staged), os.O_WRONLY)
        try:
            computed, received = await _drain_chunk_body(request, fd, start, expected)
            _check_chunk_length(declared_sha, computed, received, expected)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            get_db().add_upload_chunk(session_id, start, end, computed)
        except sqlite3.IntegrityError as exc:
            # 并发登记同一区间（跨进程）：以先登记者为准，按冲突处理
            raise HTTPException(
                status_code=409,
                detail={"message": "分片区间已被并发请求登记，已有分片保持不变"},
            ) from exc
        row = get_db().get_upload_session(session_id)
        return {"replayed": False, "session": _session_view(row)}


@app.post(
    "/api/v1/upload-sessions/{session_id}/abort",
    tags=["upload-sessions"],
    summary="终止上传会话并清理暂存文件",
    description="终止意图立即生效：会话置为 aborted，暂存文件与分片索引被清理，"
                "此后任何分片写入都会被拒绝（409）。重复终止幂等回放（200）。",
    responses={
        404: {"description": "会话不存在"},
        409: {"description": "会话已完成/失败/过期，无法终止"},
    },
)
def abort_upload_session(session_id: str) -> dict[str, Any]:
    _ensure_upload_recovery()
    row = _lazy_expire_session(_require_upload_session(session_id))
    if row["status"] == "aborted":
        return {"aborted": True, "session": _session_view(row)}
    if row["status"] != "uploading":
        raise HTTPException(
            status_code=409,
            detail={"message": f"会话已处于终态 {row['status']}，无法终止",
                    "status": row["status"]},
        )
    lock = upload_sessions.session_lock(session_id)
    with lock:
        row = _lazy_expire_session(_require_upload_session(session_id))
        if row["status"] == "aborted":
            return {"aborted": True, "session": _session_view(row)}
        if row["status"] != "uploading":
            raise HTTPException(
                status_code=409,
                detail={"message": f"会话已处于终态 {row['status']}，无法终止",
                        "status": row["status"]},
            )
        upload_sessions.abort_session(get_db(), session_id, status="aborted")
    row = get_db().get_upload_session(session_id)
    return {"aborted": True, "session": _session_view(row)}


def _finalize_session_replay(row, job_id: str) -> JSONResponse:
    """完成接口的幂等回放：会话指向既有作业（不重复创建），清理暂存。"""
    db = get_db()
    db.update_upload_session_status(row["id"], "completed", job_id=job_id)
    upload_sessions.cleanup_session_files(row["id"])
    db.delete_upload_chunks(row["id"])
    latest = db.get_upload_session(row["id"])
    return JSONResponse(
        status_code=200,
        content={
            "replayed": True,
            "session": _session_view(latest),
            "job": _job_dict_for_session(row["kind"], job_id),
        },
    )


@app.post(
    "/api/v1/upload-sessions/{session_id}/complete",
    tags=["upload-sessions"],
    summary="完成上传会话：校验完整性并转入脱敏作业",
    description=(
        "完成必须满足：分片恰好覆盖 `[0, bytes_total)` 全部字节，且整体 SHA-256 "
        "与创建时声明一致；不满足返回 409（会话保持 uploading，已登记分片保留，"
        "可补齐或修正后重试）。\n\n"
        "校验通过后：NDJSON 转入既有流式作业，ZIP 先过原有安全检查（不通过则会话"
        "置 failed、清理暂存并返回 422 及全部原因）再转入诊断包作业；策略、令牌"
        "关联域与 Idempotency-Key 全部沿用创建时的声明（同键已有一致作业时回放"
        "该作业，不同则 409）。完成后会话禁止继续写入，重复完成幂等回放（200）。"
    ),
    responses={
        200: {"description": "幂等命中：会话已完成或同键作业已存在"},
        201: {"description": "已转入脱敏作业（流式/诊断包）"},
        404: {"description": "会话不存在"},
        409: {"description": "未覆盖全部字节、整体摘要不符、幂等冲突或会话已终态"},
        422: {"description": "ZIP 未通过安全校验（会话置 failed 并清理暂存）"},
    },
)
def complete_upload_session(session_id: str) -> JSONResponse:
    _ensure_upload_recovery()
    row = _lazy_expire_session(_require_upload_session(session_id))
    if row["status"] == "completed" and row["job_id"]:
        return JSONResponse(
            status_code=200,
            content={
                "replayed": True,
                "session": _session_view(row),
                "job": _job_dict_for_session(row["kind"], row["job_id"]),
            },
        )
    if row["status"] != "uploading":
        raise HTTPException(
            status_code=409,
            detail={"message": f"会话状态为 {row['status']}，无法完成",
                    "status": row["status"]},
        )

    lock = upload_sessions.session_lock(session_id)
    with lock:
        row = _lazy_expire_session(_require_upload_session(session_id))
        if row["status"] == "completed" and row["job_id"]:
            return JSONResponse(
                status_code=200,
                content={
                    "replayed": True,
                    "session": _session_view(row),
                    "job": _job_dict_for_session(row["kind"], row["job_id"]),
                },
            )
        if row["status"] != "uploading":
            raise HTTPException(
                status_code=409,
                detail={"message": f"会话状态为 {row['status']}，无法完成",
                        "status": row["status"]},
            )

        db = get_db()
        bytes_total = row["bytes_total"]
        chunks = db.upload_chunks(session_id)
        merged = upload_sessions.merge_ranges(
            [(c["start"], c["end"]) for c in chunks]
        )
        if not upload_sessions.ranges_fully_cover(merged, bytes_total):
            gaps = upload_sessions.missing_ranges(bytes_total, merged)
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "尚未覆盖全部字节，无法完成",
                    "missing_ranges": [
                        {"start": s, "end": e, "bytes": e - s} for s, e in gaps
                    ],
                },
            )

        staged = upload_sessions.staged_path(session_id)
        if not staged.is_file() or staged.stat().st_size != bytes_total:
            raise HTTPException(
                status_code=409,
                detail={"message": "暂存文件缺失或大小与声明不符，无法完成"},
            )
        actual_sha, _size = receipts.sha256_file(staged)
        if actual_sha != row["content_sha256"]:
            raise HTTPException(
                status_code=409,
                detail={"message": "整体 SHA-256 与创建时声明不符；已登记分片保留，"
                                   "请核对后终止会话重新上传"},
            )

        # ZIP 先过原有安全检查；不通过则会话置 failed 并清理暂存
        entries = None
        if row["kind"] == "zip":
            try:
                entries = validate_bundle(staged)
            except BundleRejection as exc:
                upload_sessions.abort_session(
                    db, session_id, status="failed",
                    error_message="压缩包未通过安全校验：" + "；".join(exc.reasons),
                )
                raise HTTPException(
                    status_code=422,
                    detail={"message": "压缩包未通过安全校验", "reasons": exc.reasons},
                ) from exc

        key = row["idempotency_key"]
        if key:
            existing = (db.get_stream_idempotent(key) if row["kind"] == "ndjson"
                        else db.get_bundle_idempotent(key))
            if existing is not None:
                # 同键作业已存在：三元组一致则复用该作业（不重复创建），否则 409
                _check_idempotency_triplet(
                    existing, content_sha=row["content_sha256"],
                    strategy_sha=row["strategy_sha256"],
                    domain_id=row["domain_id"],
                )
                return _finalize_session_replay(row, existing["id"])

        # 转入对应作业：硬链接（零拷贝）安置原始文件，落库成功后启动 worker
        job_id = uuid.uuid4().hex
        if row["kind"] == "ndjson":
            raw = raw_path(job_id)
        else:
            raw = bundle_raw_path(job_id)
        upload_sessions.link_or_copy_staged(staged, raw)
        try:
            if row["kind"] == "ndjson":
                db.create_stream_job(
                    job_id=job_id,
                    idempotency_key=key,
                    strategy_json=row["strategy_json"],
                    strategy_sha256=row["strategy_sha256"],
                    source_filename=row["source_filename"],
                    content_sha256=row["content_sha256"],
                    bytes_total=bytes_total,
                    key_fingerprint=row["key_fingerprint"],
                    domain_id=row["domain_id"],
                )
            else:
                db.create_bundle_job(
                    job_id=job_id,
                    idempotency_key=key,
                    strategy_json=row["strategy_json"],
                    strategy_sha256=row["strategy_sha256"],
                    source_filename=row["source_filename"],
                    content_sha256=row["content_sha256"],
                    bytes_total=bytes_total,
                    files_total=len(entries or []),
                    key_fingerprint=row["key_fingerprint"],
                    domain_id=row["domain_id"],
                )
        except sqlite3.IntegrityError:
            # 并发同键：以先落库的作业为准；暂存文件仍在（硬链接只删新链接）
            raw.unlink(missing_ok=True)
            winner = (
                (db.get_stream_idempotent(key) if row["kind"] == "ndjson"
                 else db.get_bundle_idempotent(key)) if key else None
            )
            if winner is not None:
                _check_idempotency_triplet(
                    winner, content_sha=row["content_sha256"],
                    strategy_sha=row["strategy_sha256"],
                    domain_id=row["domain_id"],
                )
                return _finalize_session_replay(row, winner["id"])
            raise

        # 会话置 completed 并清理暂存与分片索引，然后启动后台作业
        db.update_upload_session_status(session_id, "completed", job_id=job_id)
        upload_sessions.cleanup_session_files(session_id)
        db.delete_upload_chunks(session_id)
        if row["kind"] == "ndjson":
            stream_registry.start(
                job_id, lambda: run_stream_job(job_id, get_db, get_master_key)
            )
        else:
            bundle_registry.start(
                job_id, lambda: run_bundle_job(job_id, get_db, get_master_key)
            )
        latest = db.get_upload_session(session_id)
        return JSONResponse(
            status_code=201,
            content={
                "replayed": False,
                "session": _session_view(latest),
                "job": _job_dict_for_session(row["kind"], job_id),
            },
        )


# ---------- 脱敏结果完整性凭证 ----------


def _resolve_receipt_path(output_path: Path, ensure: Callable[[], bool]) -> Path:
    """定位凭证文件：缺失时先尽力自愈补发；仍不可得则按结果状态报错。"""
    path = receipts.receipt_path_for_output(output_path)
    if not path.exists():
        ensure()
    if receipts.read_receipt(path) is None:
        if not output_path.exists():
            raise HTTPException(status_code=410, detail="结果文件与凭证均已被清理")
        raise HTTPException(status_code=404, detail="凭证不存在或已损坏")
    return path


def _receipt_json(path: Path) -> dict[str, Any]:
    """按原样返回凭证（不做任何字段增删，保证标签可被调用方复核）。"""
    receipt = receipts.read_receipt(path)
    assert receipt is not None  # _resolve_receipt_path 已保证可读
    return receipt


def _receipt_file_response(job_id: str, path: Path) -> FileResponse:
    return FileResponse(
        path,
        media_type="application/json; charset=utf-8",
        filename=f"receipt-{job_id}.json",
    )


def _require_succeeded(status: str) -> None:
    if status != "succeeded":
        raise HTTPException(
            status_code=409,
            detail={"message": f"作业状态为 {status}，未发布结果，无完整性凭证",
                    "status": status},
        )


@app.get(
    "/api/v1/jobs/{job_id}/receipt",
    tags=["receipts"],
    summary="查询小批量作业的完整性凭证",
    description="返回成功发布时生成的 JSON 凭证：格式版本、输入与规范化策略摘要、"
                "关联域指纹、统计计数与输出文件摘要及 HMAC-SHA256 标签；"
                "不含原始值、处理后值、策略正文或密钥材料。",
    responses={404: {"description": "作业或凭证不存在"}, 410: {"description": "结果与凭证已被清理"}},
)
def get_job_receipt(job_id: str) -> dict[str, Any]:
    job = _require_job(job_id)
    out = _output_path(job_id, job.format)
    path = _resolve_receipt_path(
        out,
        lambda: receipts.ensure_batch_receipt(
            get_db(), get_master_key(), job_id, output_path=out
        ),
    )
    return _receipt_json(path)


@app.get(
    "/api/v1/jobs/{job_id}/receipt/download",
    tags=["receipts"],
    summary="下载小批量作业的完整性凭证（JSON 文件）",
    responses={404: {"description": "作业或凭证不存在"}, 410: {"description": "结果与凭证已被清理"}},
)
def download_job_receipt(job_id: str) -> FileResponse:
    job = _require_job(job_id)
    out = _output_path(job_id, job.format)
    path = _resolve_receipt_path(
        out,
        lambda: receipts.ensure_batch_receipt(
            get_db(), get_master_key(), job_id, output_path=out
        ),
    )
    return _receipt_file_response(job_id, path)


@app.post(
    "/api/v1/jobs/{job_id}/receipt/verify",
    tags=["receipts"],
    summary="校验小批量作业凭证（重算标签与现有结果摘要）",
    description=(
        "请求体为待校验的凭证 JSON（通常为先前查询/下载得到的凭证）。服务重算凭证"
        "标签与**现有结果文件**摘要并给出结论，**不重新脱敏、不返回文件内容**。\n\n"
        "`verdict` 取值：`ok`=一致；`unsupported_format`=格式不支持；"
        "`key_mismatch`=密钥不匹配；`receipt_tampered`=凭证被改动；"
        "`job_mismatch`=凭证与本作业不对应；`result_missing`=结果缺失；"
        "`content_mismatch`=内容不符。HTTP 恒为 200，结论看 `verdict`。"
    ),
    response_model=ReceiptVerifyResponse,
    responses={404: {"description": "作业不存在"}, 422: {"description": "请求体不是 JSON 对象"}},
)
def verify_job_receipt(
    job_id: str,
    receipt: dict[str, Any] = Body(description="待校验的完整性凭证 JSON"),
) -> ReceiptVerifyResponse:
    job = _require_job(job_id)
    verdict = receipts.verify_receipt(
        get_master_key(),
        receipt,
        job_id=job_id,
        job_kind=receipts.KIND_BATCH,
        output_path=_output_path(job_id, job.format),
    )
    return ReceiptVerifyResponse(**verdict)


@app.get(
    "/api/v1/stream-jobs/{job_id}/receipt",
    tags=["receipts"],
    summary="查询流式作业的完整性凭证",
    description="仅 succeeded 作业有凭证（成功发布结果时生成）；"
                "排队/运行/失败/取消的作业返回 409。",
    responses={
        404: {"description": "作业或凭证不存在"},
        409: {"description": "作业未完成，尚无凭证"},
        410: {"description": "结果与凭证已被清理"},
    },
)
def get_stream_job_receipt(job_id: str) -> dict[str, Any]:
    job = _require_stream_job(job_id)
    _require_succeeded(job.status)
    out = final_output_path(job_id)
    path = _resolve_receipt_path(
        out,
        lambda: receipts.publish_stream_receipt(
            get_db(), get_master_key(), job_id, output_path=out
        ),
    )
    return _receipt_json(path)


@app.get(
    "/api/v1/stream-jobs/{job_id}/receipt/download",
    tags=["receipts"],
    summary="下载流式作业的完整性凭证（JSON 文件）",
    responses={
        404: {"description": "作业或凭证不存在"},
        409: {"description": "作业未完成，尚无凭证"},
        410: {"description": "结果与凭证已被清理"},
    },
)
def download_stream_job_receipt(job_id: str) -> FileResponse:
    job = _require_stream_job(job_id)
    _require_succeeded(job.status)
    out = final_output_path(job_id)
    path = _resolve_receipt_path(
        out,
        lambda: receipts.publish_stream_receipt(
            get_db(), get_master_key(), job_id, output_path=out
        ),
    )
    return _receipt_file_response(job_id, path)


@app.post(
    "/api/v1/stream-jobs/{job_id}/receipt/verify",
    tags=["receipts"],
    summary="校验流式作业凭证（重算标签与现有结果摘要）",
    description="请求体为待校验的凭证 JSON；仅 succeeded 作业可校验。"
                "判定语义与小批量凭证校验接口一致，不重新脱敏、不返回文件内容。",
    response_model=ReceiptVerifyResponse,
    responses={
        404: {"description": "作业不存在"},
        409: {"description": "作业未完成，无法校验"},
        422: {"description": "请求体不是 JSON 对象"},
    },
)
def verify_stream_job_receipt(
    job_id: str,
    receipt: dict[str, Any] = Body(description="待校验的完整性凭证 JSON"),
) -> ReceiptVerifyResponse:
    job = _require_stream_job(job_id)
    _require_succeeded(job.status)
    verdict = receipts.verify_receipt(
        get_master_key(),
        receipt,
        job_id=job_id,
        job_kind=receipts.KIND_STREAM,
        output_path=final_output_path(job_id),
    )
    return ReceiptVerifyResponse(**verdict)


@app.get(
    "/api/v1/bundle-jobs/{job_id}/receipt",
    tags=["receipts"],
    summary="查询诊断包作业的完整性凭证",
    description="仅 succeeded 作业有凭证；凭证另列结果 ZIP 内各文件的路径与摘要。",
    responses={
        404: {"description": "作业或凭证不存在"},
        409: {"description": "作业未完成，尚无凭证"},
        410: {"description": "结果与凭证已被清理"},
    },
)
def get_bundle_job_receipt(job_id: str) -> dict[str, Any]:
    job = _require_bundle_job(job_id)
    _require_succeeded(job.status)
    out = bundle_final_output_path(job_id)
    path = _resolve_receipt_path(
        out,
        lambda: receipts.publish_bundle_receipt(
            get_db(), get_master_key(), job_id, output_path=out
        ),
    )
    return _receipt_json(path)


@app.get(
    "/api/v1/bundle-jobs/{job_id}/receipt/download",
    tags=["receipts"],
    summary="下载诊断包作业的完整性凭证（JSON 文件）",
    responses={
        404: {"description": "作业或凭证不存在"},
        409: {"description": "作业未完成，尚无凭证"},
        410: {"description": "结果与凭证已被清理"},
    },
)
def download_bundle_job_receipt(job_id: str) -> FileResponse:
    job = _require_bundle_job(job_id)
    _require_succeeded(job.status)
    out = bundle_final_output_path(job_id)
    path = _resolve_receipt_path(
        out,
        lambda: receipts.publish_bundle_receipt(
            get_db(), get_master_key(), job_id, output_path=out
        ),
    )
    return _receipt_file_response(job_id, path)


@app.post(
    "/api/v1/bundle-jobs/{job_id}/receipt/verify",
    tags=["receipts"],
    summary="校验诊断包作业凭证（重算标签、结果 ZIP 与各条目摘要）",
    description="请求体为待校验的凭证 JSON；仅 succeeded 作业可校验。除整体摘要外，"
                "还逐一核对结果 ZIP 内各文件的路径与摘要；不重新脱敏、不返回文件内容。",
    response_model=ReceiptVerifyResponse,
    responses={
        404: {"description": "作业不存在"},
        409: {"description": "作业未完成，无法校验"},
        422: {"description": "请求体不是 JSON 对象"},
    },
)
def verify_bundle_job_receipt(
    job_id: str,
    receipt: dict[str, Any] = Body(description="待校验的完整性凭证 JSON"),
) -> ReceiptVerifyResponse:
    job = _require_bundle_job(job_id)
    _require_succeeded(job.status)
    verdict = receipts.verify_receipt(
        get_master_key(),
        receipt,
        job_id=job_id,
        job_kind=receipts.KIND_BUNDLE,
        output_path=bundle_final_output_path(job_id),
    )
    return ReceiptVerifyResponse(**verdict)


# ---------- 本地数据保留与安全清理 ----------


def _parse_cleanup_now(now: Any) -> object | None:
    """预览/执行请求中的 now 统一规范化为感知 UTC datetime。"""
    return retention._now(now)  # noqa: SLF001 - 同包时间规范化


def _preview_dict_to_response(preview: dict[str, Any]) -> CleanupPreviewResponse:
    return CleanupPreviewResponse(**{k: v for k, v in preview.items()
                                     if k != "job_kinds"})


def _start_cleanup_plan(plan_id: str, *, retry_failed_only: bool = False) -> None:
    """后台执行已持久化的清理计划（代次调度，重试会挤退陈旧 worker）。"""
    retention.start_plan(
        plan_id, get_db, retry_failed_only=retry_failed_only)


@app.get(
    "/api/v1/retention/policy",
    tags=["retention"],
    summary="查询保留策略（内置默认规则 + 自定义覆盖）",
)
def get_retention_policy() -> RetentionPolicyResponse:
    return RetentionPolicyResponse(rules=retention.get_policy(get_db()))


@app.put(
    "/api/v1/retention/rules",
    tags=["retention"],
    summary="设置保留期限规则（按作业类型×终态×复核状态，幂等 upsert）",
    description="重复提交同一规则键即覆盖；`retention_days=null` 表示永久保留。"
                "内置默认规则被覆盖后可通过 DELETE 回退。",
)
def put_retention_rule(
    req: UpsertRetentionRuleRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    _ = idempotency_key  # upsert 本身幂等；保留头以统一调用约定
    get_db().upsert_retention_rule(
        job_kind=req.job_kind, terminal_status=req.terminal_status,
        needs_review=req.needs_review, retention_days=req.retention_days,
    )
    get_db().add_retention_audit(
        "policy.rule.set",
        job_kind=req.job_kind,
        detail={"terminal_status": req.terminal_status,
                "needs_review": req.needs_review,
                "retention_days": req.retention_days},
    )
    return {"updated": True, "rules": [r.model_dump() for r in retention.get_policy(get_db())]}


@app.delete(
    "/api/v1/retention/rules/{job_kind}/{terminal_status}/{needs_review}",
    tags=["retention"],
    summary="删除自定义保留规则（回退到内置默认）",
    responses={
        404: {"description": "规则不存在，或该键为内置默认规则（无自定义覆盖可删）"},
    },
)
def delete_retention_rule(job_kind: str, terminal_status: str, needs_review: str):
    if (job_kind not in retention.JOB_KINDS
            or terminal_status not in retention.TERMINAL_STATUSES
            or needs_review not in ("true", "false", "any")):
        raise HTTPException(status_code=400, detail="非法规则键")
    deleted = get_db().delete_retention_rule(
        job_kind=job_kind, terminal_status=terminal_status, needs_review=needs_review
    )
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="自定义规则不存在（内置默认规则不可删除，可覆盖为永久保留）",
        )
    get_db().add_retention_audit(
        "policy.rule.deleted", job_kind=job_kind,
        detail={"terminal_status": terminal_status, "needs_review": needs_review},
    )
    return {"deleted": True, "rules": [r.model_dump() for r in retention.get_policy(get_db())]}


@app.put(
    "/api/v1/retention/locks",
    tags=["retention"],
    summary="为指定作业设置保留锁（带原因与到期时间）",
    description="同一作业已有生效中的锁返回 409（带原因/到期不同也算冲突）；"
                "原锁已到期则自动失效后建立新锁。",
    responses={
        200: {"description": "保留锁已建立（幂等重放时返回同一把锁）"},
        404: {"description": "目标作业不存在"},
        409: {"description": "该作业已有生效中的保留锁"},
        422: {"description": "到期时间非法（过期/无法解析）"},
    },
)
def put_retention_lock(
    req: CreateRetentionLockRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    _ = idempotency_key
    db = get_db()
    if not retention.job_exists(db, req.job_kind, req.job_id):
        raise HTTPException(status_code=404,
                            detail=f"作业不存在: {req.job_kind}/{req.job_id}")
    current = retention._now()  # noqa: SLF001
    existing = db.active_retention_lock(req.job_kind, req.job_id)
    if existing is not None:
        exp = retention.parse_iso(existing["expires_at"])
        if exp is not None and exp > current:
            # 完全相同的请求幂等回放；原因或到期不同则冲突
            if (existing["reason"] == req.reason
                    and retention._expires_key(exp) == retention._expires_key(req.expires_at)):  # noqa: SLF001
                return {"replayed": True,
                        "lock": retention.lock_row_to_model(existing, current).model_dump(mode="json")}
            raise HTTPException(
                status_code=409,
                detail={"message": "该作业已有生效中的保留锁",
                        "lock": retention.lock_row_to_model(existing, current).model_dump(mode="json")},
            )
    try:
        lock = retention.create_lock(
            db, job_kind=req.job_kind, job_id=req.job_id, reason=req.reason,
            expires_at=req.expires_at, now=current,
        )
    except retention.LockConflictError as exc:
        raise HTTPException(status_code=409, detail={"message": str(exc), **exc.identity}) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"message": str(exc)}) from exc
    return {"replayed": False, "lock": lock.model_dump(mode="json")}


@app.delete(
    "/api/v1/retention/locks/{job_kind}/{job_id}",
    tags=["retention"],
    summary="提前释放保留锁",
    responses={404: {"description": "没有生效中的锁"}},
)
def release_retention_lock(job_kind: str, job_id: str) -> dict[str, Any]:
    if job_kind not in retention.JOB_KINDS:
        raise HTTPException(status_code=400, detail="非法作业类型")
    row = get_db().release_retention_lock(job_kind, job_id)
    if row is None:
        raise HTTPException(status_code=404, detail="没有生效中的保留锁")
    get_db().add_retention_audit(
        "lock.released", job_kind=job_kind, job_id=job_id,
        detail={"reason": "manual_release"},
    )
    current = retention._now()  # noqa: SLF001
    return {"released": True,
            "lock": retention.lock_row_to_model(row, current).model_dump(mode="json")}


@app.get(
    "/api/v1/retention/locks",
    tags=["retention"],
    summary="查询保留锁（可按状态/作业类型过滤、分页）",
)
def list_retention_locks(
    state: str | None = Query(default=None, description="active/expired/released"),
    job_kind: str | None = Query(default=None, description="batch/stream/bundle"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> RetentionLockList:
    if state is not None and state not in ("active", "expired", "released"):
        raise HTTPException(status_code=400, detail="非法 state 过滤值")
    if job_kind is not None and job_kind not in retention.JOB_KINDS:
        raise HTTPException(status_code=400, detail="非法 job_kind 过滤值")
    db = get_db()
    # 与清理评估同一时间基准：查询前统一把到期锁置为 expired
    db.expire_due_locks()
    rows, total = db.list_retention_locks(
        state=state, job_kind=job_kind, limit=limit, offset=offset
    )
    current = retention._now()  # noqa: SLF001
    return RetentionLockList(
        total=total,
        items=[retention.lock_row_to_model(r, current) for r in rows],
    )


@app.post(
    "/api/v1/retention/cleanup/preview",
    tags=["retention"],
    summary="清理预览：待删作业、文件类别与预计释放空间",
    description=(
        "只读取作业元数据与文件 stat（类别/相对路径/大小），**绝不打开或返回"
        "任何日志、结果或审计内容**。排除：运行中（queued/running）作业、"
        "保留锁未到期、期限未满与命中永久保留规则的作业（计数见 `blocked`）。"
        "相同数据状态下重复预览幂等（`target_fingerprint` 相同）。"
    ),
    response_model=CleanupPreviewResponse,
)
def post_cleanup_preview(req: CleanupPreviewRequest) -> CleanupPreviewResponse:
    if req.job_kinds is not None:
        bad = [k for k in req.job_kinds if k not in retention.JOB_KINDS]
        if bad:
            raise HTTPException(status_code=400, detail=f"非法作业类型: {bad}")
    try:
        preview = retention.build_preview(
            get_db(),
            job_kinds=tuple(req.job_kinds) if req.job_kinds else None,
            now=req.now,
        )
    except retention.InvalidNowError as exc:
        raise HTTPException(status_code=400, detail={"message": str(exc)}) from exc
    return _preview_dict_to_response(preview)


@app.post(
    "/api/v1/retention/cleanup/execute",
    tags=["retention"],
    summary="执行清理（须提交预览摘要；目标变化时拒绝，幂等）",
    description=(
        "请求体必须原样回传预览摘要（preview_id、target_fingerprint、各计数、"
        "job_kinds）。服务以相同参数**重新计算目标**：指纹或任一计数不一致即"
        "**409 拒绝**（目标发生变化，请重新预览后提交）。空预览返回 400。\n\n"
        "执行先**持久化清理计划**（plan + 逐项），再后台串行删除；同幂等键或"
        "同目标指纹的重复提交回放既有计划。文件缺失按已删处理（幂等），符号链接"
        "/越界路径拒绝跟随并记录，部分失败可重试，服务重启后自动继续。"
    ),
    status_code=202,
    responses={
        200: {"description": "幂等命中，回放既有清理计划"},
        202: {"description": "计划已持久化并开始执行"},
        400: {"description": "预览摘要不完整或没有任何待删作业"},
        409: {"description": "目标已变化（指纹/计数与当前预览不一致）"},
    },
)
def post_cleanup_execute(
    req: CleanupExecuteRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    if idempotency_key is not None:
        idempotency_key = idempotency_key.strip()
        if len(idempotency_key) > 128:
            raise HTTPException(status_code=400, detail="Idempotency-Key 最长 128 字符")
    if req.preview_id != req.target_fingerprint:
        raise HTTPException(status_code=400, detail="preview_id 与 target_fingerprint 不一致")
    kinds = tuple(req.job_kinds) if req.job_kinds else None
    if kinds is not None:
        bad = [k for k in kinds if k not in retention.JOB_KINDS]
        if bad:
            raise HTTPException(status_code=400, detail=f"非法作业类型: {list(bad)}")

    # 时间校验先于一切（含幂等回放）：未来 now 绝不能借“回放已有计划”绕过，
    # 否则会出现预览入选、执行守卫拒绝的不一致。非法 now 一律 400。
    try:
        evaluated_now = retention.validate_now(req.now)
    except retention.InvalidNowError as exc:
        raise HTTPException(status_code=400, detail={"message": str(exc)}) from exc

    # 幂等键一旦创建过计划就永久标识该计划：带键重复提交（无论目标当前是否
    # 已被本计划清空）恒回放，这是“重复请求保持幂等”的最强保证。
    if idempotency_key:
        existing = get_db().get_cleanup_plan_by_idempotency(idempotency_key)
        if existing is not None:
            plan = retention._plan_model(get_db(), existing)  # noqa: SLF001
            return JSONResponse(
                status_code=200,
                content={"replayed": True, "plan": plan.model_dump(mode="json")},
            )

    current = retention.build_preview(get_db(), job_kinds=kinds, now=evaluated_now)

    # 首次执行：目标发生变化（文件增减、加锁、期限调整等）一律拒绝，要求重新预览
    if current["target_fingerprint"] != req.target_fingerprint:
        raise HTTPException(
            status_code=409,
            detail={"message": "清理目标自预览后已发生变化，请重新预览后提交",
                    "current_fingerprint": current["target_fingerprint"],
                    "submitted_fingerprint": req.target_fingerprint},
        )
    if (current["job_count"] != req.job_count
            or current["file_count"] != req.file_count
            or current["bytes_total"] != req.bytes_total):
        raise HTTPException(
            status_code=409,
            detail={"message": "预览摘要计数与当前目标不一致，请重新预览后提交",
                    "current": {"job_count": current["job_count"],
                                "file_count": current["file_count"],
                                "bytes_total": current["bytes_total"]}},
        )
    if current["job_count"] == 0:
        raise HTTPException(status_code=400, detail="没有任何待删作业；无需执行清理")

    # 无幂等键时：目标未变化且同指纹计划已存在（执行中/已完成）即回放
    existing = get_db().find_cleanup_plan_by_fingerprint(req.target_fingerprint)
    if existing is not None:
        plan = retention._plan_model(get_db(), existing)  # noqa: SLF001
        return JSONResponse(
            status_code=200,
            content={"replayed": True, "plan": plan.model_dump(mode="json")},
        )

    plan_id, _replayed = retention.persist_plan(
        get_db(), preview=current, idempotency_key=idempotency_key
    )
    _start_cleanup_plan(plan_id)
    plan = retention.get_plan(get_db(), plan_id)
    return JSONResponse(
        status_code=202,
        content={"replayed": False, "plan": plan.model_dump(mode="json")},
    )


def _require_plan(plan_id: str) -> CleanupPlanModel:
    plan = retention.get_plan(get_db(), plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail=f"清理计划不存在: {plan_id}")
    return plan


@app.get(
    "/api/v1/retention/cleanup/plans",
    tags=["retention"],
    summary="清理计划列表（可按状态过滤、分页）",
)
def list_cleanup_plans(
    status: str | None = Query(
        default=None, description="pending/running/succeeded/partial/failed"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> CleanupPlanList:
    if status is not None and status not in (
        "pending", "running", "succeeded", "partial", "failed"
    ):
        raise HTTPException(status_code=400, detail="非法 status 过滤值")
    rows, total = get_db().list_cleanup_plans(
        status=status, limit=limit, offset=offset
    )
    return CleanupPlanList(
        total=total, items=[retention._plan_model(get_db(), r) for r in rows]  # noqa: SLF001
    )


@app.get(
    "/api/v1/retention/cleanup/plans/{plan_id}",
    tags=["retention"],
    summary="清理计划进度与逐项结果（含逐文件删除结果/错误）",
    responses={404: {"description": "清理计划不存在"}},
)
def get_cleanup_plan(plan_id: str) -> CleanupPlanModel:
    return _require_plan(plan_id)


@app.post(
    "/api/v1/retention/cleanup/plans/{plan_id}/retry",
    tags=["retention"],
    summary="重试清理计划中失败/未完成的作业项（幂等）",
    description=(
        "只重试状态为 failed 的作业项（文件缺失会按已删处理，其余安全守卫重新"
        "复核）。全部成功则计划转为 succeeded；仍有失败转为 partial。"
    ),
    responses={
        200: {"description": "计划已完成或无失败项，返回当前计划"},
        202: {"description": "已开始重试"},
        404: {"description": "清理计划不存在"},
        409: {"description": "计划已成功，无需重试"},
    },
)
def retry_cleanup_plan(plan_id: str) -> JSONResponse:
    plan = _require_plan(plan_id)
    if plan.status == "succeeded":
        raise HTTPException(status_code=409, detail="清理计划已成功完成，无需重试")
    reset = get_db().reset_failed_plan_items(plan_id)
    if reset == 0 and plan.status not in ("failed", "partial"):
        # 没有失败项（如 pending 等待重启续跑）：直接继续执行
        _start_cleanup_plan(plan_id)
        return JSONResponse(status_code=202,
                            content={"retried": 0,
                                     "plan": _require_plan(plan_id).model_dump(mode="json")})
    # 失败项已复位为 pending：以普通续跑模式处理（覆盖 pending+failed）
    _start_cleanup_plan(plan_id)
    return JSONResponse(
        status_code=202,
        content={"retried_items": reset,
                 "plan": _require_plan(plan_id).model_dump(mode="json")},
    )


@app.get(
    "/api/v1/retention/audit",
    tags=["retention"],
    summary="保留/清理审计查询（可按计划/作业/动作过滤、分页）",
    description="审计只含动作、目标标识、结果与计数，**不含任何日志或结果内容**。",
)
def get_retention_audit(
    plan_id: str | None = Query(default=None),
    job_kind: str | None = Query(default=None),
    job_id: str | None = Query(default=None),
    action: str | None = Query(
        default=None,
        description="policy.rule.set/policy.rule.deleted/lock.created/lock.released/"
                    "cleanup.plan.created/cleanup.plan.started/cleanup.item.done/"
                    "cleanup.item.failed/cleanup.plan.finished/cleanup.plan.retried",
    ),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> RetentionAuditPage:
    if job_kind is not None and job_kind not in retention.JOB_KINDS:
        raise HTTPException(status_code=400, detail="非法 job_kind 过滤值")
    rows, total = get_db().list_retention_audit(
        plan_id=plan_id, job_kind=job_kind, job_id=job_id, action=action,
        limit=limit, offset=offset,
    )
    items = retention.audit_rows_to_models(rows)
    return RetentionAuditPage(total=total, limit=limit, offset=offset, items=items)


# ---------- 错误处理 ----------


@app.exception_handler(PayloadError)
def _payload_error_handler(_request: Request, exc: PayloadError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"message": str(exc), "line": exc.line})


def openapi_schema() -> dict[str, Any]:
    return get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )


def main() -> None:
    import uvicorn

    uvicorn.run("redactor.app:app", host="127.0.0.1", port=8080, reload=False)


if __name__ == "__main__":
    main()
