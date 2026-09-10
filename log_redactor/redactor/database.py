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
from .models import (
    AuditEntry,
    JobDetail,
    JobModel,
    JobSummary,
    RiskFinding,
    RunStats,
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
    key_fingerprint TEXT NOT NULL
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
        key_fingerprint: str,
        audit: list[AuditEntry],
        risks: list[RiskFinding],
    ) -> JobModel:
        created_at = utcnow_iso()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO jobs (id, idempotency_key, created_at, format,
                   strategy_name, strategy_version, record_count, needs_review,
                   stats_json, output_filename, output_format, key_fingerprint)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                    key_fingerprint,
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

    def get_idempotent(self, key: str) -> str | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id FROM jobs WHERE idempotency_key = ?", (key,)
            ).fetchone()
        return row["id"] if row else None

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
            key_fingerprint=row["key_fingerprint"],
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
