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
* ``GET  /api/v1/sample/strategy``、``/sample/logs.ndjson``  可直接启动的示例
* ``GET  /healthz``                     健康检查（含主密钥指纹）

全部功能离线运行，不发起任何外部网络请求。
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from contextlib import asynccontextmanager

from fastapi import FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.openapi.utils import get_openapi

from . import config
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
from .database import Database
from .engine import run_strategy
from .models import (
    BatchPayload,
    CreateJobRequest,
    DryRunRequest,
    JobDetail,
    JobList,
    JobModel,
    RunResult,
    Strategy,
    StrategyDiffRequest,
    StrategyDiffResponse,
)
from .parsing import ParsedBatch, PayloadError, parse_batch_indexed
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
UPLOAD_CHUNK = 1024 * 1024  # 1 MiB：multipart 流式落盘的拷贝块大小

app = FastAPI(
    title="本地日志脱敏 API",
    version="1.4.0",
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
        "否则 409；支持进度查询、取消与重启续跑，终态清理原始包，成功后原子发布结果 ZIP。"
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
    # 服务启动：确保目录就位，并从安全检查点恢复未完成的流式/诊断包作业
    ensure_stream_dirs()
    ensure_bundle_dirs()
    recover_stream_jobs(get_db, get_master_key)
    recover_bundle_jobs(get_db, get_master_key)
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
    # multipart 流式上传逐块落盘、不读入内存，豁免小批量 10 MiB 请求体上限
    exempt = request.method == "POST" and request.url.path in (
        STREAM_UPLOAD_PATH, BUNDLE_UPLOAD_PATH,
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
    _write_output(_output_path(job_id, req.format), result.records, req.format,
                  as_array=parsed.top_level_is_array)
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
            domain_id=domain_hex,
        )
    except sqlite3.IntegrityError:
        # 并发提交相同幂等键：对方先落库，回放或冲突（清理本请求的冗余文件）
        winner = get_db().get_idempotent(idempotency_key) if idempotency_key else None
        _output_path(job_id, req.format).unlink(missing_ok=True)
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
