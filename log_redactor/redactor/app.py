"""本地日志脱敏 HTTP API（FastAPI）。

接口概览
--------
* ``POST /api/v1/strategies/validate``  策略试运行（不落库，返回脱敏结果与审计）
* ``POST /api/v1/jobs``                 正式处理，支持 ``Idempotency-Key``
* ``GET  /api/v1/jobs``                 作业列表（可按需复核过滤）
* ``GET  /api/v1/jobs/{job_id}``        作业详情、统计、审计清单、残留风险
* ``GET  /api/v1/jobs/{job_id}/records`` 脱敏后记录
* ``GET  /api/v1/jobs/{job_id}/audit``  仅取审计清单
* ``GET  /api/v1/jobs/{job_id}/download`` 下载脱敏文件（保持 JSON/NDJSON）
* ``GET  /api/v1/sample/strategy``、``/sample/logs.ndjson``  可直接启动的示例
* ``GET  /healthz``                     健康检查（含主密钥指纹）

全部功能离线运行，不发起任何外部网络请求。
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from fastapi.openapi.utils import get_openapi

from . import config
from .crypto import MasterKey, key_fingerprint
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
)
from .parsing import ParsedBatch, PayloadError, parse_batch
from .samples import sample_ndjson, sample_strategy_dict

MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MiB，本地工具足够，同时防止误提交巨型文件

app = FastAPI(
    title="本地日志脱敏 API",
    version="1.0.0",
    description=(
        "供后端团队提交故障样本前使用的本地日志脱敏服务。支持按字段路径/键名/正则/内置识别器"
        "（邮箱、手机号、IP、访问令牌、身份证、银行卡）命中，动作包括删除、掩码与基于本地"
        "密钥的确定性令牌化；生成不含原值的审计清单，并对残留高风险内容标记需复核。"
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


def _execute(payload: BatchPayload) -> tuple[ParsedBatch, RunResult]:
    try:
        parsed = parse_batch(payload.content, payload.format)
    except PayloadError as exc:
        detail = {"message": str(exc)}
        if exc.line is not None:
            detail["line"] = exc.line
        raise HTTPException(status_code=422, detail=detail) from exc
    result = run_strategy(
        payload.strategy,
        parsed.records,
        get_master_key(),
        is_ndjson=(payload.format == "ndjson"),
    )
    return parsed, result


def _run_response(result: RunResult) -> dict[str, Any]:
    return result.model_dump(mode="json")


# ---------- 中间件：请求体大小限制 ----------


@app.middleware("http")
async def _limit_body(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={"message": f"请求体超过 {MAX_BODY_BYTES} 字节限制"},
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
    responses={200: {"description": "已有作业（幂等命中）"}, 201: {"description": "新作业已处理"}},
)
def create_job(
    req: CreateJobRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key",
                                         description="同一键重复提交直接返回首个作业"),
) -> JSONResponse:
    if idempotency_key is not None:
        idempotency_key = idempotency_key.strip()
        if len(idempotency_key) > 128:
            raise HTTPException(status_code=400, detail="Idempotency-Key 最长 128 字符")
        existing_id = get_db().get_idempotent(idempotency_key)
        if existing_id:
            existing = get_db().get_job(existing_id)
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
        )
    except sqlite3.IntegrityError:
        # 并发提交相同幂等键：对方先落库，回放其作业（清理本请求的冗余文件）
        winner = get_db().get_idempotent(idempotency_key) if idempotency_key else None
        _output_path(job_id, req.format).unlink(missing_ok=True)
        if winner:
            return JSONResponse(status_code=200,
                                content={"replayed": True, "job": _job_dict(get_db().get_job(winner))})  # type: ignore[arg-type]
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
