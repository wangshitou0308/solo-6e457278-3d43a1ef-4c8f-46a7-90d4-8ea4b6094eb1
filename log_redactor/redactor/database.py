"""SQLite 持久层：作业元数据、审计清单与残留风险。

仅保存作业结果与审计信息；审计表按设计不包含任何原始值。
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import settings
from .crypto import domain_fingerprint
from .models import (
    AuditEntry,
    AuditPage,
    BundleFileInfo,
    BundleJobModel,
    BundleJobSummary,
    JobDetail,
    JobModel,
    JobSummary,
    RiskFinding,
    RiskPage,
    RunStats,
    StreamJobModel,
    StreamJobSummary,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    created_at TEXT NOT NULL,
    format TEXT NOT NULL,
    strategy_name TEXT NOT NULL,
    strategy_version TEXT NOT NULL,
    record_count INTEGER NOT NULL,
    needs_review INTEGER NOT NULL,
    stats_json TEXT NOT NULL,
    output_filename TEXT NOT NULL,
    output_format TEXT NOT NULL,
    top_level_is_array INTEGER NOT NULL DEFAULT 1,
    key_fingerprint TEXT NOT NULL,
    content_sha256 TEXT NOT NULL DEFAULT '',
    strategy_sha256 TEXT NOT NULL DEFAULT '',
    domain_id TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    job_id TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    line_no INTEGER,
    field_path TEXT NOT NULL,
    key_name TEXT,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    action TEXT NOT NULL,
    match_type TEXT NOT NULL,
    hit_by_json TEXT NOT NULL,
    occurrences INTEGER NOT NULL,
    FOREIGN KEY (job_id) REFERENCES jobs(id)
);
CREATE TABLE IF NOT EXISTS risks (
    job_id TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    line_no INTEGER,
    field_path TEXT NOT NULL,
    detector TEXT NOT NULL,
    length INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_job ON audit(job_id);
CREATE INDEX IF NOT EXISTS idx_risks_job ON risks(job_id);

-- 大批量 NDJSON 流式作业：逐行处理、安全检查点、可取消、可恢复
CREATE TABLE IF NOT EXISTS stream_jobs (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    status TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'ndjson',
    strategy_json TEXT NOT NULL,
    strategy_name TEXT NOT NULL,
    strategy_version TEXT NOT NULL,
    source_filename TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    strategy_sha256 TEXT NOT NULL DEFAULT '',
    bytes_total INTEGER NOT NULL DEFAULT 0,
    bytes_processed INTEGER NOT NULL DEFAULT 0,
    records_processed INTEGER NOT NULL DEFAULT 0,
    audit_count INTEGER NOT NULL DEFAULT 0,
    risk_count INTEGER NOT NULL DEFAULT 0,
    fields_scanned INTEGER NOT NULL DEFAULT 0,
    by_action_json TEXT NOT NULL DEFAULT '{}',
    by_rule_json TEXT NOT NULL DEFAULT '{}',
    last_line_no INTEGER NOT NULL DEFAULT 0,
    error_line INTEGER,
    error_message TEXT,
    output_filename TEXT,
    output_bytes INTEGER NOT NULL DEFAULT 0,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    key_fingerprint TEXT NOT NULL,
    domain_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_stream_jobs_status ON stream_jobs(status);
-- 流式审计/风险与检查点同事务落库，行即检查点边界
CREATE TABLE IF NOT EXISTS stream_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    line_no INTEGER,
    field_path TEXT NOT NULL,
    key_name TEXT,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    action TEXT NOT NULL,
    match_type TEXT NOT NULL,
    hit_by_json TEXT NOT NULL,
    occurrences INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS stream_risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    line_no INTEGER,
    field_path TEXT NOT NULL,
    detector TEXT NOT NULL,
    length INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_stream_audit_job ON stream_audit(job_id);
CREATE INDEX IF NOT EXISTS idx_stream_risks_job ON stream_risks(job_id);

-- 诊断包（ZIP）作业：逐文件处理、文件级安全检查点、可取消、可恢复
CREATE TABLE IF NOT EXISTS bundle_jobs (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    status TEXT NOT NULL,
    strategy_json TEXT NOT NULL,
    strategy_name TEXT NOT NULL,
    strategy_version TEXT NOT NULL,
    source_filename TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    strategy_sha256 TEXT NOT NULL DEFAULT '',
    bytes_total INTEGER NOT NULL DEFAULT 0,
    files_total INTEGER NOT NULL DEFAULT 0,
    files_processed INTEGER NOT NULL DEFAULT 0,
    records_processed INTEGER NOT NULL DEFAULT 0,
    audit_count INTEGER NOT NULL DEFAULT 0,
    risk_count INTEGER NOT NULL DEFAULT 0,
    fields_scanned INTEGER NOT NULL DEFAULT 0,
    by_action_json TEXT NOT NULL DEFAULT '{}',
    by_rule_json TEXT NOT NULL DEFAULT '{}',
    current_file TEXT,
    error_message TEXT,
    output_filename TEXT,
    output_bytes INTEGER NOT NULL DEFAULT 0,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    key_fingerprint TEXT NOT NULL,
    domain_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_bundle_jobs_status ON bundle_jobs(status);
-- 每个来源文件一行：文件级检查点边界；恢复时据此跳过已完成文件
CREATE TABLE IF NOT EXISTS bundle_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    path TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT,
    format TEXT,
    records INTEGER NOT NULL DEFAULT 0,
    lines INTEGER NOT NULL DEFAULT 0,
    audit_entries INTEGER NOT NULL DEFAULT 0,
    risk_findings INTEGER NOT NULL DEFAULT 0,
    output_path TEXT,
    size_in INTEGER NOT NULL DEFAULT 0,
    size_out INTEGER NOT NULL DEFAULT 0,
    UNIQUE(job_id, path)
);
CREATE INDEX IF NOT EXISTS idx_bundle_files_job ON bundle_files(job_id);
-- 诊断包审计/风险比流式表多 source_path（来源文件相对路径），不含原值
CREATE TABLE IF NOT EXISTS bundle_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    source_path TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    line_no INTEGER,
    field_path TEXT NOT NULL,
    key_name TEXT,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    action TEXT NOT NULL,
    match_type TEXT NOT NULL,
    hit_by_json TEXT NOT NULL,
    occurrences INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS bundle_risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    source_path TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    line_no INTEGER,
    field_path TEXT NOT NULL,
    detector TEXT NOT NULL,
    length INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bundle_audit_job ON bundle_audit(job_id);
CREATE INDEX IF NOT EXISTS idx_bundle_risks_job ON bundle_risks(job_id);
"""


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or settings.db_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(jobs)")}
            if "top_level_is_array" not in cols:
                conn.execute(
                    "ALTER TABLE jobs ADD COLUMN top_level_is_array INTEGER NOT NULL DEFAULT 1"
                )
            stream_cols = {
                r["name"] for r in conn.execute("PRAGMA table_info(stream_jobs)")
            }
            if "strategy_sha256" not in stream_cols:
                conn.execute(
                    "ALTER TABLE stream_jobs ADD COLUMN strategy_sha256 TEXT NOT NULL DEFAULT ''"
                )
            # 令牌关联域：只持久化不可逆域标识（hex），全局域为 NULL
            for table in ("jobs", "stream_jobs", "bundle_jobs"):
                tcols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
                if "domain_id" not in tcols:
                    conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN domain_id TEXT"
                    )
            # 小批量作业幂等键升级为同时绑定内容与策略（既有列补齐默认值）
            jobs_cols = {r["name"] for r in conn.execute("PRAGMA table_info(jobs)")}
            if "content_sha256" not in jobs_cols:
                conn.execute(
                    "ALTER TABLE jobs ADD COLUMN content_sha256 TEXT NOT NULL DEFAULT ''"
                )
            if "strategy_sha256" not in jobs_cols:
                conn.execute(
                    "ALTER TABLE jobs ADD COLUMN strategy_sha256 TEXT NOT NULL DEFAULT ''"
                )

    # ---------- 写入 ----------

    def save_job(
        self,
        *,
        job_id: str,
        idempotency_key: str | None,
        fmt: str,
        strategy_name: str,
        strategy_version: str,
        result_stats: RunStats,
        needs_review: bool,
        output_filename: str,
        output_format: str,
        top_level_is_array: bool,
        key_fingerprint: str,
        audit: list[AuditEntry],
        risks: list[RiskFinding],
        content_sha256: str = "",
        strategy_sha256: str = "",
        domain_id: str | None = None,
    ) -> JobModel:
        created_at = utcnow_iso()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO jobs (id, idempotency_key, created_at, format,
                   strategy_name, strategy_version, record_count, needs_review,
                   stats_json, output_filename, output_format,
                   top_level_is_array, key_fingerprint,
                   content_sha256, strategy_sha256, domain_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    job_id,
                    idempotency_key,
                    created_at,
                    fmt,
                    strategy_name,
                    strategy_version,
                    result_stats.records_in,
                    int(needs_review),
                    result_stats.model_dump_json(),
                    output_filename,
                    output_format,
                    int(top_level_is_array),
                    key_fingerprint,
                    content_sha256,
                    strategy_sha256,
                    domain_id,
                ),
            )
            conn.executemany(
                """INSERT INTO audit (job_id, record_index, line_no, field_path,
                   key_name, rule_id, rule_name, action, match_type,
                   hit_by_json, occurrences) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        job_id,
                        a.record_index,
                        a.line_no,
                        a.field_path,
                        a.key_name,
                        a.rule_id,
                        a.rule_name,
                        a.action,
                        a.match_type,
                        json.dumps(a.hit_by, ensure_ascii=False),
                        a.occurrences,
                    )
                    for a in audit
                ],
            )
            conn.executemany(
                """INSERT INTO risks (job_id, record_index, line_no, field_path,
                   detector, length) VALUES (?,?,?,?,?,?)""",
                [
                    (job_id, r.record_index, r.line_no, r.field_path, r.detector, r.length)
                    for r in risks
                ],
            )
        return self.get_job(job_id)  # type: ignore[return-value]

    # ---------- 读取 ----------

    def get_idempotent(self, key: str) -> sqlite3.Row | None:
        """按幂等键取回内容/策略摘要与关联域标识，供回放与冲突判定。"""
        with self._conn() as conn:
            return conn.execute(
                "SELECT id, content_sha256, strategy_sha256, "
                "COALESCE(domain_id, '') AS domain_id "
                "FROM jobs WHERE idempotency_key = ?",
                (key,),
            ).fetchone()

    def _load_audit(self, conn: sqlite3.Connection, job_id: str) -> list[AuditEntry]:
        rows = conn.execute(
            "SELECT * FROM audit WHERE job_id = ? ORDER BY rowid", (job_id,)
        ).fetchall()
        return [
            AuditEntry(
                record_index=r["record_index"],
                line_no=r["line_no"],
                field_path=r["field_path"],
                key_name=r["key_name"],
                rule_id=r["rule_id"],
                rule_name=r["rule_name"],
                action=r["action"],
                match_type=r["match_type"],
                hit_by=json.loads(r["hit_by_json"]),
                occurrences=r["occurrences"],
            )
            for r in rows
        ]

    def _load_risks(self, conn: sqlite3.Connection, job_id: str) -> list[RiskFinding]:
        rows = conn.execute(
            "SELECT * FROM risks WHERE job_id = ? ORDER BY rowid", (job_id,)
        ).fetchall()
        return [
            RiskFinding(
                record_index=r["record_index"],
                line_no=r["line_no"],
                field_path=r["field_path"],
                detector=r["detector"],
                length=r["length"],
            )
            for r in rows
        ]

    @staticmethod
    def _row_to_model(row: sqlite3.Row) -> JobModel:
        return JobModel(
            id=row["id"],
            idempotency_key=row["idempotency_key"],
            created_at=row["created_at"],
            format=row["format"],
            strategy_name=row["strategy_name"],
            strategy_version=row["strategy_version"],
            record_count=row["record_count"],
            needs_review=bool(row["needs_review"]),
            stats=RunStats(**json.loads(row["stats_json"])),
            output_filename=row["output_filename"],
            top_level_is_array=bool(row.keys().count("top_level_is_array")
                                    and row["top_level_is_array"]),
            key_fingerprint=row["key_fingerprint"],
            domain_fingerprint=domain_fingerprint(
                row["domain_id"] if row.keys().count("domain_id") else None
            ),
        )

    def get_job(self, job_id: str) -> JobModel | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return self._row_to_model(row) if row else None

    def get_job_detail(self, job_id: str) -> JobDetail | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if not row:
                return None
            audit = self._load_audit(conn, job_id)
            risks = self._load_risks(conn, job_id)
        model = self._row_to_model(row)
        return JobDetail(**model.model_dump(), audit=audit, risks=risks)

    def list_jobs(self, limit: int = 50, offset: int = 0,
                  needs_review: bool | None = None) -> tuple[list[JobSummary], int]:
        where = "WHERE needs_review = ?" if needs_review is not None else ""
        params: tuple[Any, ...] = (int(needs_review),) if needs_review is not None else ()
        with self._conn() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM jobs {where}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"""SELECT * FROM jobs {where}
                    ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?""",
                params + (limit, offset),
            ).fetchall()
        items = [
            JobSummary(
                id=r["id"],
                created_at=r["created_at"],
                strategy_name=r["strategy_name"],
                record_count=r["record_count"],
                needs_review=bool(r["needs_review"]),
                risk_findings=json.loads(r["stats_json"])["risk_findings"],
            )
            for r in rows
        ]
        return items, total

    # ---------- 流式作业 ----------

    @staticmethod
    def _stream_row_to_model(row: sqlite3.Row) -> StreamJobModel:
        bytes_total = row["bytes_total"] or 0
        bytes_processed = row["bytes_processed"] or 0
        pct = round(bytes_processed * 100.0 / bytes_total, 2) if bytes_total else 0.0
        status = row["status"]
        if status == "succeeded":
            pct = 100.0
        output_filename = row["output_filename"]
        job_id = row["id"]
        return StreamJobModel(
            id=job_id,
            idempotency_key=row["idempotency_key"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            status=status,
            format=row["format"],
            strategy_name=row["strategy_name"],
            strategy_version=row["strategy_version"],
            source_filename=row["source_filename"],
            bytes_total=bytes_total,
            bytes_processed=bytes_processed,
            records_processed=row["records_processed"],
            audit_count=row["audit_count"],
            risk_count=row["risk_count"],
            fields_scanned=row["fields_scanned"],
            by_action=json.loads(row["by_action_json"] or "{}"),
            by_rule=json.loads(row["by_rule_json"] or "{}"),
            last_line_no=row["last_line_no"],
            error_line=row["error_line"],
            error_message=row["error_message"],
            output_filename=output_filename,
            output_bytes=row["output_bytes"] or 0,
            key_fingerprint=row["key_fingerprint"],
            domain_fingerprint=domain_fingerprint(row["domain_id"]),
            content_sha256=row["content_sha256"],
            strategy_sha256=row["strategy_sha256"],
            progress_pct=pct,
            download_url=(f"/api/v1/stream-jobs/{job_id}/download"
                          if status == "succeeded" and output_filename else None),
        )

    def create_stream_job(
        self,
        *,
        job_id: str,
        idempotency_key: str | None,
        strategy_json: str,
        strategy_sha256: str,
        source_filename: str,
        content_sha256: str,
        bytes_total: int,
        key_fingerprint: str,
        domain_id: str | None = None,
    ) -> StreamJobModel:
        import json as _json

        strategy = _json.loads(strategy_json)
        now = utcnow_iso()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO stream_jobs (id, idempotency_key, created_at, updated_at,
                   status, format, strategy_json, strategy_name, strategy_version,
                   source_filename, content_sha256, strategy_sha256, bytes_total,
                   key_fingerprint, domain_id)
                   VALUES (?,?,?,?, 'queued', 'ndjson', ?,?,?,?,?,?,?,?,?)""",
                (
                    job_id, idempotency_key, now, now, strategy_json,
                    strategy.get("name", ""), str(strategy.get("version", "1")),
                    source_filename, content_sha256, strategy_sha256,
                    bytes_total, key_fingerprint, domain_id,
                ),
            )
            row = conn.execute(
                "SELECT * FROM stream_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return self._stream_row_to_model(row)

    def get_stream_job(self, job_id: str) -> StreamJobModel | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM stream_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return self._stream_row_to_model(row) if row else None

    def get_stream_strategy_json(self, job_id: str) -> str | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT strategy_json FROM stream_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return row["strategy_json"] if row else None

    def get_stream_idempotent(self, key: str) -> sqlite3.Row | None:
        with self._conn() as conn:
            return conn.execute(
                "SELECT id, content_sha256, strategy_sha256, "
                "COALESCE(domain_id, '') AS domain_id FROM stream_jobs "
                "WHERE idempotency_key = ?",
                (key,),
            ).fetchone()

    def get_stream_domain_id(self, job_id: str) -> str | None:
        """取作业的令牌关联域标识（worker 重启续跑时据此恢复域子密钥）。"""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT domain_id FROM stream_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return row["domain_id"] if row else None

    def checkpoint_stream_job(
        self,
        job_id: str,
        *,
        bytes_processed: int,
        records_processed: int,
        audit_count: int,
        risk_count: int,
        fields_scanned: int,
        by_action: dict[str, int],
        by_rule: dict[str, int],
        last_line_no: int,
        output_bytes: int,
        audit: list[AuditEntry],
        risks: list[RiskFinding],
    ) -> None:
        """安全检查点：进度、统计与本批审计/风险在同一事务落库。

        与输出文件 fsync 配合：恢复时严格按 rows 截断输出，因此本事务在
        fsync 之后提交（由 worker 保证），崩溃后不会出现“已提交但无输出”的行。
        """
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE stream_jobs SET updated_at=?, status='running',
                   bytes_processed=?, records_processed=?, audit_count=?,
                   risk_count=?, fields_scanned=?, by_action_json=?,
                   by_rule_json=?, last_line_no=?, output_bytes=?
                   WHERE id=?""",
                (
                    utcnow_iso(), bytes_processed, records_processed, audit_count,
                    risk_count, fields_scanned,
                    json.dumps(by_action, ensure_ascii=False),
                    json.dumps(by_rule, ensure_ascii=False),
                    last_line_no, output_bytes, job_id,
                ),
            )
            if audit:
                conn.executemany(
                    """INSERT INTO stream_audit (job_id, record_index, line_no,
                       field_path, key_name, rule_id, rule_name, action, match_type,
                       hit_by_json, occurrences) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    [
                        (
                            job_id, a.record_index, a.line_no, a.field_path,
                            a.key_name, a.rule_id, a.rule_name, a.action,
                            a.match_type,
                            json.dumps(a.hit_by, ensure_ascii=False), a.occurrences,
                        )
                        for a in audit
                    ],
                )
            if risks:
                conn.executemany(
                    """INSERT INTO stream_risks (job_id, record_index, line_no,
                       field_path, detector, length) VALUES (?,?,?,?,?,?)""",
                    [
                        (job_id, r.record_index, r.line_no, r.field_path,
                         r.detector, r.length)
                        for r in risks
                    ],
                )

    def mark_stream_succeeded(
        self, job_id: str, *, output_filename: str
    ) -> StreamJobModel | None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE stream_jobs SET status='succeeded', updated_at=?,
                   cancel_requested=0, output_filename=? WHERE id=?""",
                (utcnow_iso(), output_filename, job_id),
            )
            row = conn.execute(
                "SELECT * FROM stream_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return self._stream_row_to_model(row) if row else None

    def reconcile_published_stream_job(
        self, job_id: str, *, output_filename: str
    ) -> StreamJobModel | None:
        """崩溃恢复对账：成品文件已发布但状态事务未提交时补登 succeeded。

        仅对 queued/running 状态生效（终态作业不会被改写），与正常发布走同一条
        UPDATE，保证状态与可下载文件一一对应。
        """
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE stream_jobs SET status='succeeded', updated_at=?,
                   cancel_requested=0, output_filename=?
                   WHERE id=? AND status IN ('queued','running')""",
                (utcnow_iso(), output_filename, job_id),
            )
            row = conn.execute(
                "SELECT * FROM stream_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return self._stream_row_to_model(row) if row else None

    def mark_stream_failed(
        self, job_id: str, *, message: str, line: int | None
    ) -> StreamJobModel | None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE stream_jobs SET status='failed', updated_at=?,
                   error_message=?, error_line=? WHERE id=?""",
                (utcnow_iso(), message, line, job_id),
            )
            row = conn.execute(
                "SELECT * FROM stream_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return self._stream_row_to_model(row) if row else None

    def mark_stream_cancelled(self, job_id: str) -> StreamJobModel | None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE stream_jobs SET status='cancelled', updated_at=?,
                   cancel_requested=0 WHERE id=?""",
                (utcnow_iso(), job_id),
            )
            row = conn.execute(
                "SELECT * FROM stream_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return self._stream_row_to_model(row) if row else None

    def request_stream_cancel(self, job_id: str) -> None:
        """持久化取消意图：服务重启后恢复作业时仍会被取消。"""
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE stream_jobs SET cancel_requested=1, updated_at=? "
                "WHERE id=? AND status IN ('queued','running')",
                (utcnow_iso(), job_id),
            )

    def stream_cancel_requested(self, job_id: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT cancel_requested FROM stream_jobs WHERE id=?", (job_id,)
            ).fetchone()
        return bool(row and row["cancel_requested"])

    def list_stream_jobs(
        self, *, status: str | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[list[StreamJobSummary], int]:
        where = "WHERE status = ?" if status is not None else ""
        params: tuple[Any, ...] = (status,) if status is not None else ()
        with self._conn() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM stream_jobs {where}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"""SELECT * FROM stream_jobs {where}
                    ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?""",
                params + (limit, offset),
            ).fetchall()
        items = []
        for r in rows:
            m = self._stream_row_to_model(r)
            items.append(
                StreamJobSummary(
                    id=m.id, created_at=m.created_at, status=m.status,
                    strategy_name=m.strategy_name, bytes_total=m.bytes_total,
                    records_processed=m.records_processed, risk_count=m.risk_count,
                    progress_pct=m.progress_pct,
                )
            )
        return items, total

    def _audit_row(self, r: sqlite3.Row) -> AuditEntry:
        return AuditEntry(
            record_index=r["record_index"], line_no=r["line_no"],
            field_path=r["field_path"], key_name=r["key_name"],
            rule_id=r["rule_id"], rule_name=r["rule_name"], action=r["action"],
            match_type=r["match_type"], hit_by=json.loads(r["hit_by_json"]),
            occurrences=r["occurrences"],
        )

    def _risk_row(self, r: sqlite3.Row) -> RiskFinding:
        return RiskFinding(
            record_index=r["record_index"], line_no=r["line_no"],
            field_path=r["field_path"], detector=r["detector"], length=r["length"],
        )

    def paginate_stream_audit(
        self, job_id: str, *, limit: int, offset: int
    ) -> AuditPage:
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) AS c FROM stream_audit WHERE job_id=?", (job_id,)
            ).fetchone()["c"]
            rows = conn.execute(
                """SELECT * FROM stream_audit WHERE job_id=?
                   ORDER BY id ASC LIMIT ? OFFSET ?""",
                (job_id, limit, offset),
            ).fetchall()
        return AuditPage(
            job_id=job_id, total=total, limit=limit, offset=offset,
            items=[self._audit_row(r) for r in rows],
        )

    def paginate_stream_risks(
        self, job_id: str, *, limit: int, offset: int
    ) -> RiskPage:
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) AS c FROM stream_risks WHERE job_id=?", (job_id,)
            ).fetchone()["c"]
            rows = conn.execute(
                """SELECT * FROM stream_risks WHERE job_id=?
                   ORDER BY id ASC LIMIT ? OFFSET ?""",
                (job_id, limit, offset),
            ).fetchall()
        return RiskPage(
            job_id=job_id, total=total, limit=limit, offset=offset,
            items=[self._risk_row(r) for r in rows],
        )

    def resumable_stream_jobs(self) -> list[sqlite3.Row]:
        """服务重启后需要恢复的作业：已排队/运行中（含重启前请求取消的）。"""
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM stream_jobs WHERE status IN ('queued','running') "
                "ORDER BY created_at ASC"
            ).fetchall()

    # ---------- 诊断包（ZIP）作业 ----------

    @staticmethod
    def _bundle_row_to_model(row: sqlite3.Row) -> BundleJobModel:
        files_total = row["files_total"] or 0
        files_processed = row["files_processed"] or 0
        pct = round(files_processed * 100.0 / files_total, 2) if files_total else 0.0
        status = row["status"]
        if status == "succeeded":
            pct = 100.0
        output_filename = row["output_filename"]
        job_id = row["id"]
        return BundleJobModel(
            id=job_id,
            idempotency_key=row["idempotency_key"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            status=status,
            strategy_name=row["strategy_name"],
            strategy_version=row["strategy_version"],
            source_filename=row["source_filename"],
            bytes_total=row["bytes_total"] or 0,
            files_total=files_total,
            files_processed=files_processed,
            records_processed=row["records_processed"],
            audit_count=row["audit_count"],
            risk_count=row["risk_count"],
            fields_scanned=row["fields_scanned"],
            by_action=json.loads(row["by_action_json"] or "{}"),
            by_rule=json.loads(row["by_rule_json"] or "{}"),
            current_file=row["current_file"],
            error_message=row["error_message"],
            output_filename=output_filename,
            output_bytes=row["output_bytes"] or 0,
            key_fingerprint=row["key_fingerprint"],
            domain_fingerprint=domain_fingerprint(row["domain_id"]),
            content_sha256=row["content_sha256"],
            strategy_sha256=row["strategy_sha256"],
            progress_pct=pct,
            download_url=(f"/api/v1/bundle-jobs/{job_id}/download"
                          if status == "succeeded" and output_filename else None),
        )

    def create_bundle_job(
        self,
        *,
        job_id: str,
        idempotency_key: str | None,
        strategy_json: str,
        strategy_sha256: str,
        source_filename: str,
        content_sha256: str,
        bytes_total: int,
        files_total: int,
        key_fingerprint: str,
        domain_id: str | None = None,
    ) -> BundleJobModel:
        strategy = json.loads(strategy_json)
        now = utcnow_iso()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO bundle_jobs (id, idempotency_key, created_at, updated_at,
                   status, strategy_json, strategy_name, strategy_version,
                   source_filename, content_sha256, strategy_sha256, bytes_total,
                   files_total, key_fingerprint, domain_id)
                   VALUES (?,?,?,?, 'queued', ?,?,?,?,?,?,?,?,?,?)""",
                (
                    job_id, idempotency_key, now, now, strategy_json,
                    strategy.get("name", ""), str(strategy.get("version", "1")),
                    source_filename, content_sha256, strategy_sha256,
                    bytes_total, files_total, key_fingerprint, domain_id,
                ),
            )
            row = conn.execute(
                "SELECT * FROM bundle_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return self._bundle_row_to_model(row)

    def get_bundle_job(self, job_id: str) -> BundleJobModel | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM bundle_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return self._bundle_row_to_model(row) if row else None

    def get_bundle_strategy_json(self, job_id: str) -> str | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT strategy_json FROM bundle_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return row["strategy_json"] if row else None

    def get_bundle_idempotent(self, key: str) -> sqlite3.Row | None:
        with self._conn() as conn:
            return conn.execute(
                "SELECT id, content_sha256, strategy_sha256, "
                "COALESCE(domain_id, '') AS domain_id FROM bundle_jobs "
                "WHERE idempotency_key = ?",
                (key,),
            ).fetchone()

    def get_bundle_domain_id(self, job_id: str) -> str | None:
        """取作业的令牌关联域标识（worker 重启续跑时据此恢复域子密钥）。"""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT domain_id FROM bundle_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return row["domain_id"] if row else None

    def update_bundle_current_file(self, job_id: str, path: str | None) -> None:
        """装饰性进度：记录正在处理的包内文件（不参与恢复状态）。

        仅对 queued/running 作业生效，避免与终结事务竞争时把终态翻回 running。
        """
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE bundle_jobs SET updated_at=?, status='running', "
                "current_file=? WHERE id=? AND status IN ('queued','running')",
                (utcnow_iso(), path, job_id),
            )

    def checkpoint_bundle_file(
        self,
        job_id: str,
        *,
        file_row: BundleFileInfo,
        files_processed: int,
        records_processed: int,
        audit_count: int,
        risk_count: int,
        fields_scanned: int,
        by_action: dict[str, int],
        by_rule: dict[str, int],
        audit: list[AuditEntry],
        risks: list[RiskFinding],
    ) -> None:
        """文件级安全检查点：文件结果行、进度与本文件审计/风险同事务落库。

        调用方保证该文件的脱敏输出已 fsync 并原子 rename 到暂存区，
        因此崩溃后不会出现“已提交但无输出”的文件。
        """
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO bundle_files (job_id, path, status, reason, format,
                   records, lines, audit_entries, risk_findings, output_path,
                   size_in, size_out) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    job_id, file_row.path, file_row.status, file_row.reason,
                    file_row.format, file_row.records, file_row.lines,
                    file_row.audit_entries, file_row.risk_findings,
                    file_row.output_path, file_row.size_in, file_row.size_out,
                ),
            )
            conn.execute(
                """UPDATE bundle_jobs SET updated_at=?, status='running',
                   files_processed=?, records_processed=?, audit_count=?,
                   risk_count=?, fields_scanned=?, by_action_json=?,
                   by_rule_json=?, current_file=NULL WHERE id=?""",
                (
                    utcnow_iso(), files_processed, records_processed, audit_count,
                    risk_count, fields_scanned,
                    json.dumps(by_action, ensure_ascii=False),
                    json.dumps(by_rule, ensure_ascii=False), job_id,
                ),
            )
            if audit:
                conn.executemany(
                    """INSERT INTO bundle_audit (job_id, source_path, record_index,
                       line_no, field_path, key_name, rule_id, rule_name, action,
                       match_type, hit_by_json, occurrences)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    [
                        (
                            job_id, a.source_path or file_row.path, a.record_index,
                            a.line_no, a.field_path, a.key_name, a.rule_id,
                            a.rule_name, a.action, a.match_type,
                            json.dumps(a.hit_by, ensure_ascii=False), a.occurrences,
                        )
                        for a in audit
                    ],
                )
            if risks:
                conn.executemany(
                    """INSERT INTO bundle_risks (job_id, source_path, record_index,
                       line_no, field_path, detector, length)
                       VALUES (?,?,?,?,?,?,?)""",
                    [
                        (
                            job_id, r.source_path or file_row.path, r.record_index,
                            r.line_no, r.field_path, r.detector, r.length,
                        )
                        for r in risks
                    ],
                )

    def bundle_done_files(self, job_id: str) -> set[str]:
        """已在检查点落库的文件路径（恢复时跳过，避免重复处理/重复审计）。"""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT path FROM bundle_files WHERE job_id=?", (job_id,)
            ).fetchall()
        return {r["path"] for r in rows}

    def bundle_files_for_manifest(self, job_id: str) -> list[BundleFileInfo]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM bundle_files WHERE job_id=? ORDER BY id ASC", (job_id,)
            ).fetchall()
        return [
            BundleFileInfo(
                path=r["path"], status=r["status"], reason=r["reason"],
                format=r["format"], records=r["records"], lines=r["lines"],
                audit_entries=r["audit_entries"], risk_findings=r["risk_findings"],
                output_path=r["output_path"], size_in=r["size_in"],
                size_out=r["size_out"],
            )
            for r in rows
        ]

    def mark_bundle_succeeded(
        self, job_id: str, *, output_filename: str, output_bytes: int
    ) -> BundleJobModel | None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE bundle_jobs SET status='succeeded', updated_at=?,
                   cancel_requested=0, current_file=NULL, output_filename=?,
                   output_bytes=? WHERE id=?""",
                (utcnow_iso(), output_filename, output_bytes, job_id),
            )
            row = conn.execute(
                "SELECT * FROM bundle_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return self._bundle_row_to_model(row) if row else None

    def reconcile_published_bundle_job(
        self, job_id: str, *, output_filename: str, output_bytes: int
    ) -> BundleJobModel | None:
        """崩溃恢复对账：成品 ZIP 已发布但状态事务未提交时补登 succeeded。"""
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE bundle_jobs SET status='succeeded', updated_at=?,
                   cancel_requested=0, current_file=NULL, output_filename=?,
                   output_bytes=? WHERE id=? AND status IN ('queued','running')""",
                (utcnow_iso(), output_filename, output_bytes, job_id),
            )
            row = conn.execute(
                "SELECT * FROM bundle_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return self._bundle_row_to_model(row) if row else None

    def mark_bundle_failed(
        self, job_id: str, *, message: str
    ) -> BundleJobModel | None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE bundle_jobs SET status='failed', updated_at=?,
                   error_message=?, current_file=NULL WHERE id=?""",
                (utcnow_iso(), message, job_id),
            )
            row = conn.execute(
                "SELECT * FROM bundle_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return self._bundle_row_to_model(row) if row else None

    def mark_bundle_cancelled(self, job_id: str) -> BundleJobModel | None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE bundle_jobs SET status='cancelled', updated_at=?,
                   cancel_requested=0, current_file=NULL WHERE id=?""",
                (utcnow_iso(), job_id),
            )
            row = conn.execute(
                "SELECT * FROM bundle_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return self._bundle_row_to_model(row) if row else None

    def request_bundle_cancel(self, job_id: str) -> None:
        """持久化取消意图：服务重启后恢复作业时仍会被取消。"""
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE bundle_jobs SET cancel_requested=1, updated_at=? "
                "WHERE id=? AND status IN ('queued','running')",
                (utcnow_iso(), job_id),
            )

    def bundle_cancel_requested(self, job_id: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT cancel_requested FROM bundle_jobs WHERE id=?", (job_id,)
            ).fetchone()
        return bool(row and row["cancel_requested"])

    def list_bundle_jobs(
        self, *, status: str | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[list[BundleJobSummary], int]:
        where = "WHERE status = ?" if status is not None else ""
        params: tuple[Any, ...] = (status,) if status is not None else ()
        with self._conn() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM bundle_jobs {where}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"""SELECT * FROM bundle_jobs {where}
                    ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?""",
                params + (limit, offset),
            ).fetchall()
        items = []
        for r in rows:
            m = self._bundle_row_to_model(r)
            items.append(
                BundleJobSummary(
                    id=m.id, created_at=m.created_at, status=m.status,
                    strategy_name=m.strategy_name, files_total=m.files_total,
                    files_processed=m.files_processed,
                    records_processed=m.records_processed, risk_count=m.risk_count,
                    progress_pct=m.progress_pct,
                )
            )
        return items, total

    def _bundle_audit_row(self, r: sqlite3.Row) -> AuditEntry:
        return AuditEntry(
            record_index=r["record_index"], line_no=r["line_no"],
            field_path=r["field_path"], key_name=r["key_name"],
            rule_id=r["rule_id"], rule_name=r["rule_name"], action=r["action"],
            match_type=r["match_type"], hit_by=json.loads(r["hit_by_json"]),
            occurrences=r["occurrences"], source_path=r["source_path"],
        )

    def _bundle_risk_row(self, r: sqlite3.Row) -> RiskFinding:
        return RiskFinding(
            record_index=r["record_index"], line_no=r["line_no"],
            field_path=r["field_path"], detector=r["detector"], length=r["length"],
            source_path=r["source_path"],
        )

    def paginate_bundle_audit(
        self, job_id: str, *, limit: int, offset: int
    ) -> AuditPage:
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) AS c FROM bundle_audit WHERE job_id=?", (job_id,)
            ).fetchone()["c"]
            rows = conn.execute(
                """SELECT * FROM bundle_audit WHERE job_id=?
                   ORDER BY id ASC LIMIT ? OFFSET ?""",
                (job_id, limit, offset),
            ).fetchall()
        return AuditPage(
            job_id=job_id, total=total, limit=limit, offset=offset,
            items=[self._bundle_audit_row(r) for r in rows],
        )

    def paginate_bundle_risks(
        self, job_id: str, *, limit: int, offset: int
    ) -> RiskPage:
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) AS c FROM bundle_risks WHERE job_id=?", (job_id,)
            ).fetchone()["c"]
            rows = conn.execute(
                """SELECT * FROM bundle_risks WHERE job_id=?
                   ORDER BY id ASC LIMIT ? OFFSET ?""",
                (job_id, limit, offset),
            ).fetchall()
        return RiskPage(
            job_id=job_id, total=total, limit=limit, offset=offset,
            items=[self._bundle_risk_row(r) for r in rows],
        )

    def resumable_bundle_jobs(self) -> list[sqlite3.Row]:
        """服务重启后需要恢复的诊断包作业（含重启前请求取消的）。"""
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM bundle_jobs WHERE status IN ('queued','running') "
                "ORDER BY created_at ASC"
            ).fetchall()
