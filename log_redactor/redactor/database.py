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
    DecodeIssue,
    DecodeIssuePage,
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
    content_bytes INTEGER NOT NULL DEFAULT 0,
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
    decode_depth INTEGER NOT NULL DEFAULT 0,
    outer_field_path TEXT,
    inner_path TEXT,
    FOREIGN KEY (job_id) REFERENCES jobs(id)
);
CREATE TABLE IF NOT EXISTS risks (
    job_id TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    line_no INTEGER,
    field_path TEXT NOT NULL,
    detector TEXT NOT NULL,
    length INTEGER NOT NULL,
    decode_depth INTEGER NOT NULL DEFAULT 0,
    outer_field_path TEXT,
    inner_path TEXT
);
-- 内嵌结构解码未执行（保持原值）的待复核原因，同样不含原值
CREATE TABLE IF NOT EXISTS decode_issues (
    job_id TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    line_no INTEGER,
    field_path TEXT NOT NULL,
    decoder TEXT NOT NULL,
    reason TEXT NOT NULL,
    decode_depth INTEGER NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_job ON audit(job_id);
CREATE INDEX IF NOT EXISTS idx_risks_job ON risks(job_id);
CREATE INDEX IF NOT EXISTS idx_decode_issues_job ON decode_issues(job_id);

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
    decode_issue_count INTEGER NOT NULL DEFAULT 0,
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
    occurrences INTEGER NOT NULL,
    decode_depth INTEGER NOT NULL DEFAULT 0,
    outer_field_path TEXT,
    inner_path TEXT
);
CREATE TABLE IF NOT EXISTS stream_risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    line_no INTEGER,
    field_path TEXT NOT NULL,
    detector TEXT NOT NULL,
    length INTEGER NOT NULL,
    decode_depth INTEGER NOT NULL DEFAULT 0,
    outer_field_path TEXT,
    inner_path TEXT
);
CREATE TABLE IF NOT EXISTS stream_decode_issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    line_no INTEGER,
    field_path TEXT NOT NULL,
    decoder TEXT NOT NULL,
    reason TEXT NOT NULL,
    decode_depth INTEGER NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_stream_audit_job ON stream_audit(job_id);
CREATE INDEX IF NOT EXISTS idx_stream_risks_job ON stream_risks(job_id);
CREATE INDEX IF NOT EXISTS idx_stream_decode_issues_job ON stream_decode_issues(job_id);

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
    decode_issue_count INTEGER NOT NULL DEFAULT 0,
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
    decode_issues INTEGER NOT NULL DEFAULT 0,
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
    occurrences INTEGER NOT NULL,
    decode_depth INTEGER NOT NULL DEFAULT 0,
    outer_field_path TEXT,
    inner_path TEXT
);
CREATE TABLE IF NOT EXISTS bundle_risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    source_path TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    line_no INTEGER,
    field_path TEXT NOT NULL,
    detector TEXT NOT NULL,
    length INTEGER NOT NULL,
    decode_depth INTEGER NOT NULL DEFAULT 0,
    outer_field_path TEXT,
    inner_path TEXT
);
CREATE TABLE IF NOT EXISTS bundle_decode_issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    source_path TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    line_no INTEGER,
    field_path TEXT NOT NULL,
    decoder TEXT NOT NULL,
    reason TEXT NOT NULL,
    decode_depth INTEGER NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_bundle_audit_job ON bundle_audit(job_id);
CREATE INDEX IF NOT EXISTS idx_bundle_risks_job ON bundle_risks(job_id);
CREATE INDEX IF NOT EXISTS idx_bundle_decode_issues_job ON bundle_decode_issues(job_id);

-- 本地数据保留与安全清理：策略规则、保留锁、清理计划与审计
CREATE TABLE IF NOT EXISTS retention_rules (
    job_kind TEXT NOT NULL,
    terminal_status TEXT NOT NULL,
    needs_review TEXT NOT NULL,
    retention_days REAL,
    builtin INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (job_kind, terminal_status, needs_review)
);
CREATE TABLE IF NOT EXISTS retention_locks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_kind TEXT NOT NULL,
    job_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    -- 未释放为 ''（保证唯一约束生效）；释放/失效后写入 ISO 时间
    released_at TEXT NOT NULL DEFAULT '',
    -- ''=生效中（released_at 也为空）；'released'=提前释放；'expired'=到期失效
    release_reason TEXT NOT NULL DEFAULT '',
    -- 同一作业至多存在一把未释放（含未到期）的锁
    UNIQUE(job_kind, job_id, released_at)
);
CREATE INDEX IF NOT EXISTS idx_retention_locks_job ON retention_locks(job_kind, job_id);
CREATE TABLE IF NOT EXISTS cleanup_plans (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    started_at TEXT,
    finished_at TEXT,
    target_fingerprint TEXT NOT NULL,
    submitted_preview_json TEXT NOT NULL,
    jobs_total INTEGER NOT NULL DEFAULT 0,
    jobs_done INTEGER NOT NULL DEFAULT 0,
    jobs_failed INTEGER NOT NULL DEFAULT 0,
    files_processed INTEGER NOT NULL DEFAULT 0,
    bytes_deleted INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
CREATE TABLE IF NOT EXISTS cleanup_plan_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id TEXT NOT NULL,
    job_kind TEXT NOT NULL,
    job_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    planned_files_json TEXT NOT NULL DEFAULT '[]',
    processed INTEGER NOT NULL DEFAULT 0,
    deleted_bytes INTEGER NOT NULL DEFAULT 0,
    outcomes_json TEXT NOT NULL DEFAULT '[]',
    seq INTEGER NOT NULL,
    terminal_status TEXT NOT NULL DEFAULT 'succeeded',
    needs_review INTEGER NOT NULL DEFAULT 0,
    UNIQUE(plan_id, job_kind, job_id)
);
CREATE INDEX IF NOT EXISTS idx_cleanup_items_plan ON cleanup_plan_items(plan_id);
CREATE TABLE IF NOT EXISTS retention_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    action TEXT NOT NULL,
    job_kind TEXT,
    job_id TEXT,
    plan_id TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_retention_audit_ts ON retention_audit(ts, id);
CREATE INDEX IF NOT EXISTS idx_retention_audit_plan ON retention_audit(plan_id);

-- 断点续传上传会话：声明式创建、Content-Range 乱序分片、完成后转入作业
CREATE TABLE IF NOT EXISTS upload_sessions (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    -- uploading=接收分片；completed=已转入作业；aborted=已终止；
    -- expired=已过期；failed=完成校验失败（如 ZIP 安全校验）
    status TEXT NOT NULL,
    kind TEXT NOT NULL,
    source_filename TEXT NOT NULL,
    bytes_total INTEGER NOT NULL,
    content_sha256 TEXT NOT NULL,
    strategy_json TEXT NOT NULL,
    strategy_sha256 TEXT NOT NULL,
    domain_id TEXT,
    key_fingerprint TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    job_id TEXT,
    error_message TEXT
);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_status ON upload_sessions(status);
-- 分片索引：已接收区间（end 开区间）与逐片 SHA-256；重启后据此恢复进度
CREATE TABLE IF NOT EXISTS upload_chunks (
    session_id TEXT NOT NULL,
    start INTEGER NOT NULL,
    end INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (session_id, start, end)
);
CREATE INDEX IF NOT EXISTS idx_upload_chunks_session ON upload_chunks(session_id);
"""


_RULE_NOT_BUILTIN = object()


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
            # 完整性凭证：输入字节数（与内容摘要一同参与凭证记录）
            if "content_bytes" not in jobs_cols:
                conn.execute(
                    "ALTER TABLE jobs ADD COLUMN content_bytes INTEGER NOT NULL DEFAULT 0"
                )
            # 内嵌结构解码：流式/诊断包作业的待复核计数（既有库补齐默认值）
            for table in ("stream_jobs", "bundle_jobs"):
                tcols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
                if "decode_issue_count" not in tcols:
                    conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN "
                        "decode_issue_count INTEGER NOT NULL DEFAULT 0"
                    )
            fcols = {r["name"] for r in conn.execute("PRAGMA table_info(bundle_files)")}
            if "decode_issues" not in fcols:
                conn.execute(
                    "ALTER TABLE bundle_files ADD COLUMN "
                    "decode_issues INTEGER NOT NULL DEFAULT 0"
                )
            # 审计/风险表的内嵌定位列（解码层级、外层字段、内部路径）
            for table in ("audit", "risks", "stream_audit", "stream_risks",
                          "bundle_audit", "bundle_risks"):
                tcols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
                if "decode_depth" not in tcols:
                    conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN "
                        "decode_depth INTEGER NOT NULL DEFAULT 0"
                    )
                if "outer_field_path" not in tcols:
                    conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN outer_field_path TEXT"
                    )
                if "inner_path" not in tcols:
                    conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN inner_path TEXT"
                    )
            # 保留策略：首次初始化内置默认期限（仅当规则表为空时，不覆盖既有配置）
            from .retention import DEFAULT_RETENTION_RULES

            count = conn.execute("SELECT COUNT(*) AS c FROM retention_rules").fetchone()["c"]
            if count == 0:
                now = utcnow_iso()
                conn.executemany(
                    """INSERT OR IGNORE INTO retention_rules
                       (job_kind, terminal_status, needs_review, retention_days,
                        builtin, updated_at) VALUES (?,?,?,?,1,?)""",
                    [
                        (job_kind, status, review, days, now)
                        for job_kind, status, review, days in DEFAULT_RETENTION_RULES
                    ],
                )
            # 清理计划项终态/复核位（开发期表结构升级）
            item_cols = {
                r["name"] for r in conn.execute("PRAGMA table_info(cleanup_plan_items)")
            }
            if item_cols and "terminal_status" not in item_cols:
                conn.execute(
                    "ALTER TABLE cleanup_plan_items ADD COLUMN "
                    "terminal_status TEXT NOT NULL DEFAULT 'succeeded'"
                )
            if item_cols and "needs_review" not in item_cols:
                conn.execute(
                    "ALTER TABLE cleanup_plan_items ADD COLUMN "
                    "needs_review INTEGER NOT NULL DEFAULT 0"
                )
            # 保留锁释放原因（''=生效中 / released=提前释放 / expired=到期失效），
            # 让状态判定只依赖落库列，不再与查询时刻的时间耦合
            lock_cols = {
                r["name"] for r in conn.execute("PRAGMA table_info(retention_locks)")
            }
            if "release_reason" not in lock_cols:
                conn.execute(
                    "ALTER TABLE retention_locks ADD COLUMN "
                    "release_reason TEXT NOT NULL DEFAULT ''"
                )
            # 历史遗留：未释放但已到期的锁一次性补登为到期失效
            conn.execute(
                "UPDATE retention_locks SET release_reason='expired', released_at=? "
                "WHERE released_at='' AND expires_at<=?",
                (utcnow_iso(), utcnow_iso()),
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
        decode_issues: list[DecodeIssue] | None = None,
        content_sha256: str = "",
        strategy_sha256: str = "",
        content_bytes: int = 0,
        domain_id: str | None = None,
    ) -> JobModel:
        created_at = utcnow_iso()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO jobs (id, idempotency_key, created_at, format,
                   strategy_name, strategy_version, record_count, needs_review,
                   stats_json, output_filename, output_format,
                   top_level_is_array, key_fingerprint,
                   content_sha256, strategy_sha256, content_bytes, domain_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                    content_bytes,
                    domain_id,
                ),
            )
            conn.executemany(
                """INSERT INTO audit (job_id, record_index, line_no, field_path,
                   key_name, rule_id, rule_name, action, match_type,
                   hit_by_json, occurrences, decode_depth, outer_field_path,
                   inner_path) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                        a.decode_depth,
                        a.outer_field_path,
                        a.inner_path,
                    )
                    for a in audit
                ],
            )
            conn.executemany(
                """INSERT INTO risks (job_id, record_index, line_no, field_path,
                   detector, length, decode_depth, outer_field_path, inner_path)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                [
                    (job_id, r.record_index, r.line_no, r.field_path, r.detector,
                     r.length, r.decode_depth, r.outer_field_path, r.inner_path)
                    for r in risks
                ],
            )
            if decode_issues:
                conn.executemany(
                    """INSERT INTO decode_issues (job_id, record_index, line_no,
                       field_path, decoder, reason, decode_depth, detail)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    [
                        (job_id, d.record_index, d.line_no, d.field_path,
                         d.decoder, d.reason, d.decode_depth, d.detail)
                        for d in decode_issues
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

    def get_job_receipt_source(self, job_id: str) -> sqlite3.Row | None:
        """取生成/补发小批量作业完整性凭证所需的持久化字段。"""
        with self._conn() as conn:
            return conn.execute(
                "SELECT id, format, strategy_name, strategy_version, stats_json, "
                "output_filename, content_sha256, strategy_sha256, content_bytes, "
                "COALESCE(domain_id, '') AS domain_id FROM jobs WHERE id = ?",
                (job_id,),
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
                decode_depth=r["decode_depth"],
                outer_field_path=r["outer_field_path"],
                inner_path=r["inner_path"],
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
                decode_depth=r["decode_depth"],
                outer_field_path=r["outer_field_path"],
                inner_path=r["inner_path"],
            )
            for r in rows
        ]

    def _load_decode_issues(self, conn: sqlite3.Connection,
                            job_id: str) -> list[DecodeIssue]:
        rows = conn.execute(
            "SELECT * FROM decode_issues WHERE job_id = ? ORDER BY rowid", (job_id,)
        ).fetchall()
        return [
            DecodeIssue(
                record_index=r["record_index"],
                line_no=r["line_no"],
                field_path=r["field_path"],
                decoder=r["decoder"],
                reason=r["reason"],
                decode_depth=r["decode_depth"],
                detail=r["detail"],
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
            receipt_url=f"/api/v1/jobs/{row['id']}/receipt",
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
            decode_issues = self._load_decode_issues(conn, job_id)
        model = self._row_to_model(row)
        return JobDetail(**model.model_dump(), audit=audit, risks=risks,
                         decode_issues=decode_issues)

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
            decode_issue_count=(
                row["decode_issue_count"]
                if row.keys().count("decode_issue_count") else 0
            ),
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
            receipt_url=(f"/api/v1/stream-jobs/{job_id}/receipt"
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
        decode_issues: list[DecodeIssue] | None = None,
        decode_issue_count: int = 0,
    ) -> None:
        """安全检查点：进度、统计与本批审计/风险在同一事务落库。

        与输出文件 fsync 配合：恢复时严格按 rows 截断输出，因此本事务在
        fsync 之后提交（由 worker 保证），崩溃后不会出现“已提交但无输出”的行。
        """
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE stream_jobs SET updated_at=?, status='running',
                   bytes_processed=?, records_processed=?, audit_count=?,
                   risk_count=?, decode_issue_count=?, fields_scanned=?,
                   by_action_json=?, by_rule_json=?, last_line_no=?, output_bytes=?
                   WHERE id=?""",
                (
                    utcnow_iso(), bytes_processed, records_processed, audit_count,
                    risk_count, decode_issue_count, fields_scanned,
                    json.dumps(by_action, ensure_ascii=False),
                    json.dumps(by_rule, ensure_ascii=False),
                    last_line_no, output_bytes, job_id,
                ),
            )
            if audit:
                conn.executemany(
                    """INSERT INTO stream_audit (job_id, record_index, line_no,
                       field_path, key_name, rule_id, rule_name, action, match_type,
                       hit_by_json, occurrences, decode_depth, outer_field_path,
                       inner_path) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    [
                        (
                            job_id, a.record_index, a.line_no, a.field_path,
                            a.key_name, a.rule_id, a.rule_name, a.action,
                            a.match_type,
                            json.dumps(a.hit_by, ensure_ascii=False), a.occurrences,
                            a.decode_depth, a.outer_field_path, a.inner_path,
                        )
                        for a in audit
                    ],
                )
            if risks:
                conn.executemany(
                    """INSERT INTO stream_risks (job_id, record_index, line_no,
                       field_path, detector, length, decode_depth,
                       outer_field_path, inner_path) VALUES (?,?,?,?,?,?,?,?,?)""",
                    [
                        (job_id, r.record_index, r.line_no, r.field_path,
                         r.detector, r.length, r.decode_depth,
                         r.outer_field_path, r.inner_path)
                        for r in risks
                    ],
                )
            if decode_issues:
                conn.executemany(
                    """INSERT INTO stream_decode_issues (job_id, record_index,
                       line_no, field_path, decoder, reason, decode_depth, detail)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    [
                        (job_id, d.record_index, d.line_no, d.field_path,
                         d.decoder, d.reason, d.decode_depth, d.detail)
                        for d in decode_issues
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
            occurrences=r["occurrences"], decode_depth=r["decode_depth"],
            outer_field_path=r["outer_field_path"], inner_path=r["inner_path"],
        )

    def _risk_row(self, r: sqlite3.Row) -> RiskFinding:
        return RiskFinding(
            record_index=r["record_index"], line_no=r["line_no"],
            field_path=r["field_path"], detector=r["detector"], length=r["length"],
            decode_depth=r["decode_depth"],
            outer_field_path=r["outer_field_path"], inner_path=r["inner_path"],
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

    @staticmethod
    def _decode_issue_row(r: sqlite3.Row, *, with_source: bool = False) -> DecodeIssue:
        return DecodeIssue(
            record_index=r["record_index"], line_no=r["line_no"],
            field_path=r["field_path"], decoder=r["decoder"],
            reason=r["reason"], decode_depth=r["decode_depth"],
            detail=r["detail"],
            source_path=r["source_path"] if with_source else None,
        )

    def paginate_stream_decode_issues(
        self, job_id: str, *, limit: int, offset: int
    ) -> DecodeIssuePage:
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) AS c FROM stream_decode_issues WHERE job_id=?",
                (job_id,),
            ).fetchone()["c"]
            rows = conn.execute(
                """SELECT * FROM stream_decode_issues WHERE job_id=?
                   ORDER BY id ASC LIMIT ? OFFSET ?""",
                (job_id, limit, offset),
            ).fetchall()
        return DecodeIssuePage(
            job_id=job_id, total=total, limit=limit, offset=offset,
            items=[self._decode_issue_row(r) for r in rows],
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
            decode_issue_count=(
                row["decode_issue_count"]
                if row.keys().count("decode_issue_count") else 0
            ),
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
            receipt_url=(f"/api/v1/bundle-jobs/{job_id}/receipt"
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
        decode_issues: list[DecodeIssue] | None = None,
        decode_issue_count: int = 0,
    ) -> None:
        """文件级安全检查点：文件结果行、进度与本文件审计/风险同事务落库。

        调用方保证该文件的脱敏输出已 fsync 并原子 rename 到暂存区，
        因此崩溃后不会出现“已提交但无输出”的文件。
        """
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO bundle_files (job_id, path, status, reason, format,
                   records, lines, audit_entries, risk_findings, decode_issues,
                   output_path, size_in, size_out) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    job_id, file_row.path, file_row.status, file_row.reason,
                    file_row.format, file_row.records, file_row.lines,
                    file_row.audit_entries, file_row.risk_findings,
                    file_row.decode_issues,
                    file_row.output_path, file_row.size_in, file_row.size_out,
                ),
            )
            conn.execute(
                """UPDATE bundle_jobs SET updated_at=?, status='running',
                   files_processed=?, records_processed=?, audit_count=?,
                   risk_count=?, decode_issue_count=?, fields_scanned=?,
                   by_action_json=?, by_rule_json=?, current_file=NULL WHERE id=?""",
                (
                    utcnow_iso(), files_processed, records_processed, audit_count,
                    risk_count, decode_issue_count, fields_scanned,
                    json.dumps(by_action, ensure_ascii=False),
                    json.dumps(by_rule, ensure_ascii=False), job_id,
                ),
            )
            if audit:
                conn.executemany(
                    """INSERT INTO bundle_audit (job_id, source_path, record_index,
                       line_no, field_path, key_name, rule_id, rule_name, action,
                       match_type, hit_by_json, occurrences, decode_depth,
                       outer_field_path, inner_path)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    [
                        (
                            job_id, a.source_path or file_row.path, a.record_index,
                            a.line_no, a.field_path, a.key_name, a.rule_id,
                            a.rule_name, a.action, a.match_type,
                            json.dumps(a.hit_by, ensure_ascii=False), a.occurrences,
                            a.decode_depth, a.outer_field_path, a.inner_path,
                        )
                        for a in audit
                    ],
                )
            if risks:
                conn.executemany(
                    """INSERT INTO bundle_risks (job_id, source_path, record_index,
                       line_no, field_path, detector, length, decode_depth,
                       outer_field_path, inner_path)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    [
                        (
                            job_id, r.source_path or file_row.path, r.record_index,
                            r.line_no, r.field_path, r.detector, r.length,
                            r.decode_depth, r.outer_field_path, r.inner_path,
                        )
                        for r in risks
                    ],
                )
            if decode_issues:
                conn.executemany(
                    """INSERT INTO bundle_decode_issues (job_id, source_path,
                       record_index, line_no, field_path, decoder, reason,
                       decode_depth, detail)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    [
                        (
                            job_id, d.source_path or file_row.path, d.record_index,
                            d.line_no, d.field_path, d.decoder, d.reason,
                            d.decode_depth, d.detail,
                        )
                        for d in decode_issues
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
                decode_issues=(
                    r["decode_issues"] if r.keys().count("decode_issues") else 0
                ),
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
            occurrences=r["occurrences"], decode_depth=r["decode_depth"],
            outer_field_path=r["outer_field_path"], inner_path=r["inner_path"],
            source_path=r["source_path"],
        )

    def _bundle_risk_row(self, r: sqlite3.Row) -> RiskFinding:
        return RiskFinding(
            record_index=r["record_index"], line_no=r["line_no"],
            field_path=r["field_path"], detector=r["detector"], length=r["length"],
            decode_depth=r["decode_depth"],
            outer_field_path=r["outer_field_path"], inner_path=r["inner_path"],
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

    def paginate_bundle_decode_issues(
        self, job_id: str, *, limit: int, offset: int
    ) -> DecodeIssuePage:
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) AS c FROM bundle_decode_issues WHERE job_id=?",
                (job_id,),
            ).fetchone()["c"]
            rows = conn.execute(
                """SELECT * FROM bundle_decode_issues WHERE job_id=?
                   ORDER BY id ASC LIMIT ? OFFSET ?""",
                (job_id, limit, offset),
            ).fetchall()
        return DecodeIssuePage(
            job_id=job_id, total=total, limit=limit, offset=offset,
            items=[self._decode_issue_row(r, with_source=True) for r in rows],
        )

    def resumable_bundle_jobs(self) -> list[sqlite3.Row]:
        """服务重启后需要恢复的诊断包作业（含重启前请求取消的）。"""
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM bundle_jobs WHERE status IN ('queued','running') "
                "ORDER BY created_at ASC"
            ).fetchall()

    # ---------- 保留策略规则 ----------

    def list_retention_rules(self) -> list[sqlite3.Row]:
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM retention_rules "
                "ORDER BY job_kind, terminal_status, needs_review"
            ).fetchall()

    def upsert_retention_rule(
        self,
        *,
        job_kind: str,
        terminal_status: str,
        needs_review: str,
        retention_days: float | None,
    ) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO retention_rules
                   (job_kind, terminal_status, needs_review, retention_days,
                    builtin, updated_at)
                   VALUES (?,?,?,?,0,?)
                   ON CONFLICT(job_kind, terminal_status, needs_review) DO UPDATE SET
                     retention_days=excluded.retention_days,
                     builtin=0,
                     updated_at=excluded.updated_at""",
                (job_kind, terminal_status, needs_review, retention_days, utcnow_iso()),
            )

    def delete_retention_rule(
        self, *, job_kind: str, terminal_status: str, needs_review: str
    ) -> bool:
        """删除自定义覆盖并回退内置默认：

        * 键上只有自定义规则 → 删除后补回内置默认行（内置期限不会消失）；
        * 键上本来就是内置默认（无覆盖）→ 返回 False。
        """
        from .retention import DEFAULT_RETENTION_RULES

        builtin_default = next(
            (days for k, s, rv, days in DEFAULT_RETENTION_RULES
             if (k, s, rv) == (job_kind, terminal_status, needs_review)),
            _RULE_NOT_BUILTIN,
        )
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT builtin FROM retention_rules WHERE job_kind=? "
                "AND terminal_status=? AND needs_review=?",
                (job_kind, terminal_status, needs_review),
            ).fetchone()
            if row is None:
                return False
            if row["builtin"]:
                return False
            conn.execute(
                "DELETE FROM retention_rules WHERE job_kind=? AND terminal_status=? "
                "AND needs_review=?",
                (job_kind, terminal_status, needs_review),
            )
            # 该键存在内置默认时补回；否则保持“无规则=永久保留”
            if builtin_default is not _RULE_NOT_BUILTIN:
                conn.execute(
                    """INSERT INTO retention_rules
                       (job_kind, terminal_status, needs_review, retention_days,
                        builtin, updated_at) VALUES (?,?,?,?,1,?)""",
                    (job_kind, terminal_status, needs_review, builtin_default,
                     utcnow_iso()),
                )
        return True

    def get_retention_rule(
        self, *, job_kind: str, terminal_status: str, needs_review: str
    ) -> sqlite3.Row | None:
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM retention_rules WHERE job_kind=? AND terminal_status=? "
                "AND needs_review=?",
                (job_kind, terminal_status, needs_review),
            ).fetchone()

    # ---------- 保留锁 ----------

    def active_retention_lock(self, job_kind: str, job_id: str) -> sqlite3.Row | None:
        """取未释放的锁（过期与否由调用方按 expires_at 判定）。"""
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM retention_locks WHERE job_kind=? AND job_id=? "
                "AND released_at='' ORDER BY id DESC LIMIT 1",
                (job_kind, job_id),
            ).fetchone()

    def create_retention_lock(
        self, *, job_kind: str, job_id: str, reason: str, expires_at: str
    ) -> sqlite3.Row:
        """创建保留锁；同一作业已有未释放锁时由调用方处理冲突/过期失效。"""
        now = utcnow_iso()
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO retention_locks
                   (job_kind, job_id, reason, expires_at, created_at, released_at)
                   VALUES (?,?,?,?,?,'')""",
                (job_kind, job_id, reason, expires_at, now),
            )
            row = conn.execute(
                "SELECT * FROM retention_locks WHERE id=?", (cur.lastrowid,)
            ).fetchone()
        return row

    def expire_retention_lock(self, lock_id: int) -> None:
        """既有未释放锁已过期：标记到期失效（released_at/release_reason 同事务落库）。"""
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE retention_locks SET released_at=?, release_reason='expired' "
                "WHERE id=? AND released_at=''",
                (utcnow_iso(), lock_id),
            )

    def release_retention_lock(self, job_kind: str, job_id: str) -> sqlite3.Row | None:
        """主动释放未到期的锁；没有未释放锁时返回 None。"""
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "UPDATE retention_locks SET released_at=?, release_reason='released' "
                "WHERE job_kind=? AND job_id=? AND released_at=''",
                (utcnow_iso(), job_kind, job_id),
            )
            if cur.rowcount == 0:
                return None
            return conn.execute(
                "SELECT * FROM retention_locks WHERE job_kind=? AND job_id=? "
                "ORDER BY id DESC LIMIT 1",
                (job_kind, job_id),
            ).fetchone()

    def expire_due_locks(self, now_iso: str | None = None) -> int:
        """把所有已到期但尚未标记的未释放锁统一置为到期失效。

        列表查询与清理评估共用同一时间基准（服务当前时间）调用本方法，
        消除“同一把锁一边已到期、一边无法按 expired 查到”的不一致。
        """
        stamp = now_iso or utcnow_iso()
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "UPDATE retention_locks SET released_at=?, release_reason='expired' "
                "WHERE released_at='' AND expires_at<=?",
                (stamp, stamp),
            )
            return cur.rowcount

    def list_retention_locks(
        self, *, state: str | None, job_kind: str | None, limit: int, offset: int
    ) -> tuple[list[sqlite3.Row], int]:
        # 状态只依据落库列判定：active=未释放；expired/released=已释放且有对应原因。
        # 未释放但已到期的锁先由保留模块统一惰性失效，调用方看到的状态与清理评估一致。
        where: list[str] = []
        params: list[Any] = []
        if state == "active":
            where.append("released_at=''")
        elif state in ("expired", "released"):
            where.append("release_reason=?")
            params.append(state)
        if job_kind is not None:
            where.append("job_kind=?")
            params.append(job_kind)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self._conn() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM retention_locks {clause}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"SELECT * FROM retention_locks {clause} "
                "ORDER BY id DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
        return rows, total

    def expire_locks_for_job(self, job_kind: str, job_id: str) -> None:
        """作业被删除时，其保留锁随之失效，避免悬挂的 active 锁。"""
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE retention_locks SET released_at=?, release_reason='expired' "
                "WHERE job_kind=? AND job_id=? AND released_at=''",
                (utcnow_iso(), job_kind, job_id),
            )

    # ---------- 清理计划（跨三类作业的只读查询） ----------

    def get_any_job(self, job_kind: str, job_id: str) -> sqlite3.Row | None:
        """按类型取作业原始行（清理守卫复核状态用）。"""
        table = {"batch": "jobs", "stream": "stream_jobs",
                 "bundle": "bundle_jobs"}.get(job_kind)
        if table is None:
            return None
        with self._conn() as conn:
            return conn.execute(
                f"SELECT * FROM {table} WHERE id=?", (job_id,)
            ).fetchone()

    # ---------- 清理计划 ----------

    def create_cleanup_plan(
        self,
        *,
        plan_id: str,
        idempotency_key: str | None,
        target_fingerprint: str,
        submitted_preview: dict[str, Any],
        # (job_kind, job_id, planned_files_json, terminal_status, needs_review)
        items: list[tuple[str, str, str, str, bool]],
    ) -> None:
        """清理计划先持久化（计划头 + 全部待删作业项），随后 worker 才开始删除。"""
        now = utcnow_iso()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO cleanup_plans
                   (id, idempotency_key, status, created_at, updated_at,
                    target_fingerprint, submitted_preview_json, jobs_total)
                   VALUES (?,?, 'pending', ?, ?, ?, ?, ?)""",
                (plan_id, idempotency_key, now, now,
                 target_fingerprint, json.dumps(submitted_preview, ensure_ascii=False),
                 len(items)),
            )
            conn.executemany(
                """INSERT INTO cleanup_plan_items
                   (plan_id, job_kind, job_id, status, planned_files_json, seq,
                    terminal_status, needs_review)
                   VALUES (?,?,?, 'pending', ?, ?, ?, ?)""",
                [
                    (plan_id, job_kind, job_id, files_json, seq,
                     terminal_status, int(needs_review))
                    for seq, (job_kind, job_id, files_json,
                              terminal_status, needs_review) in enumerate(items)
                ],
            )

    def get_cleanup_plan_row(self, plan_id: str) -> sqlite3.Row | None:
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM cleanup_plans WHERE id=?", (plan_id,)
            ).fetchone()

    def get_cleanup_plan_by_idempotency(self, key: str) -> sqlite3.Row | None:
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM cleanup_plans WHERE idempotency_key=?", (key,)
            ).fetchone()

    def find_cleanup_plan_by_fingerprint(self, target_fingerprint: str) -> sqlite3.Row | None:
        """找同目标指纹的最近计划（无幂等键时的重复执行幂等回放）。"""
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM cleanup_plans WHERE target_fingerprint=? "
                "ORDER BY created_at DESC, id DESC LIMIT 1",
                (target_fingerprint,),
            ).fetchone()

    def cleanup_plan_items(self, plan_id: str) -> list[sqlite3.Row]:
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM cleanup_plan_items WHERE plan_id=? ORDER BY seq ASC",
                (plan_id,),
            ).fetchall()

    def list_cleanup_plans(self, *, status: str | None, limit: int, offset: int,
                           ) -> tuple[list[sqlite3.Row], int]:
        where = "WHERE status=?" if status is not None else ""
        params: tuple[Any, ...] = (status,) if status is not None else ()
        with self._conn() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM cleanup_plans {where}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"SELECT * FROM cleanup_plans {where} "
                "ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                params + (limit, offset),
            ).fetchall()
        return list(rows), total

    def resumable_cleanup_plans(self) -> list[sqlite3.Row]:
        """服务重启后继续的清理计划：未全部完成（含运行中被中断）。"""
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM cleanup_plans WHERE status IN ('pending','running') "
                "ORDER BY created_at ASC"
            ).fetchall()

    def mark_cleanup_plan_running(self, plan_id: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE cleanup_plans SET status='running', updated_at=?, "
                "started_at=COALESCE(started_at, ?) WHERE id=? AND status IN "
                "('pending','running')",
                (utcnow_iso(), utcnow_iso(), plan_id),
            )

    def mark_cleanup_plan_finished(
        self, plan_id: str, *, status: str, jobs_failed: int,
        files_processed: int, bytes_deleted: int, error: str | None
    ) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE cleanup_plans SET status=?, updated_at=?, finished_at=?,
                   jobs_failed=?, files_processed=?, bytes_deleted=?, error=?
                   WHERE id=?""",
                (status, utcnow_iso(), utcnow_iso(), jobs_failed,
                 files_processed, bytes_deleted, error, plan_id),
            )

    def update_cleanup_progress(
        self, plan_id: str, *, jobs_done: int, jobs_failed: int,
        files_processed: int, bytes_deleted: int
    ) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE cleanup_plans SET updated_at=?, jobs_done=?, jobs_failed=?,
                   files_processed=?, bytes_deleted=? WHERE id=?""",
                (utcnow_iso(), jobs_done, jobs_failed, files_processed,
                 bytes_deleted, plan_id),
            )

    def mark_plan_item(
        self, item_id: int, *, status: str, processed: int,
        deleted_bytes: int, outcomes: list[dict[str, Any]]
    ) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE cleanup_plan_items SET status=?, processed=?,
                   deleted_bytes=?, outcomes_json=? WHERE id=?""",
                (status, processed, deleted_bytes,
                 json.dumps(outcomes, ensure_ascii=False), item_id),
            )

    def reset_failed_plan_items(self, plan_id: str) -> int:
        """重试：把失败作业项复位为 pending，返回复位条数。"""
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "UPDATE cleanup_plan_items SET status='pending' "
                "WHERE plan_id=? AND status='failed'",
                (plan_id,),
            )
            return cur.rowcount

    # ---------- 保留/清理审计 ----------

    def add_retention_audit(
        self, action: str, *, job_kind: str | None = None, job_id: str | None = None,
        plan_id: str | None = None, detail: dict[str, Any] | None = None
    ) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT INTO retention_audit (ts, action, job_kind, job_id, "
                "plan_id, detail_json) VALUES (?,?,?,?,?,?)",
                (utcnow_iso(), action, job_kind, job_id, plan_id,
                 json.dumps(detail or {}, ensure_ascii=False)),
            )

    def list_retention_audit(
        self, *, plan_id: str | None, job_kind: str | None, job_id: str | None,
        action: str | None, limit: int, offset: int
    ) -> tuple[list[sqlite3.Row], int]:
        where: list[str] = []
        params: list[Any] = []
        for col, val in (("plan_id", plan_id), ("job_kind", job_kind),
                         ("job_id", job_id), ("action", action)):
            if val is not None:
                where.append(f"{col}=?")
                params.append(val)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self._conn() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM retention_audit {clause}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"SELECT * FROM retention_audit {clause} "
                "ORDER BY id DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
        return list(rows), total

    # ---------- 清理删除：文件先删、记录随后（限定本服务数据目录） ----------

    def delete_job_records(self, job_kind: str, job_id: str) -> None:
        """删除指定作业的全部数据库记录（审计/风险/作业行/保留锁）。

        仅在该作业的文件删除成功后调用；按 审计→风险→作业行→锁 的顺序，
        避免外键/悬挂锁残留。
        """
        if job_kind == "batch":
            tables = ("audit", "risks", "decode_issues", "jobs")
        elif job_kind == "stream":
            tables = ("stream_audit", "stream_risks", "stream_decode_issues",
                      "stream_jobs")
        elif job_kind == "bundle":
            tables = ("bundle_audit", "bundle_risks", "bundle_decode_issues",
                      "bundle_files", "bundle_jobs")
        else:  # 防御：未知类型不动数据库
            return
        job_tables = {"jobs", "stream_jobs", "bundle_jobs"}
        with self._lock, self._conn() as conn:
            for table in tables:
                col = "id" if table in job_tables else "job_id"
                conn.execute(f"DELETE FROM {table} WHERE {col}=?", (job_id,))
            conn.execute(
                "UPDATE retention_locks SET released_at=?, release_reason='expired' "
                "WHERE job_kind=? AND job_id=? AND released_at=''",
                (utcnow_iso(), job_kind, job_id),
            )

    # ---------- 断点续传上传会话 ----------

    def create_upload_session(
        self,
        *,
        session_id: str,
        idempotency_key: str | None,
        kind: str,
        source_filename: str,
        bytes_total: int,
        content_sha256: str,
        strategy_json: str,
        strategy_sha256: str,
        domain_id: str | None,
        key_fingerprint: str,
        expires_at: str,
    ) -> sqlite3.Row:
        now = utcnow_iso()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO upload_sessions
                   (id, idempotency_key, created_at, updated_at, status, kind,
                    source_filename, bytes_total, content_sha256, strategy_json,
                    strategy_sha256, domain_id, key_fingerprint, expires_at)
                   VALUES (?,?,?,?, 'uploading', ?,?,?,?,?,?,?,?,?)""",
                (
                    session_id, idempotency_key, now, now, kind, source_filename,
                    bytes_total, content_sha256, strategy_json, strategy_sha256,
                    domain_id, key_fingerprint, expires_at,
                ),
            )
            return conn.execute(
                "SELECT * FROM upload_sessions WHERE id=?", (session_id,)
            ).fetchone()

    def get_upload_session(self, session_id: str) -> sqlite3.Row | None:
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM upload_sessions WHERE id=?", (session_id,)
            ).fetchone()

    def get_upload_session_by_idempotency(self, key: str) -> sqlite3.Row | None:
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM upload_sessions WHERE idempotency_key=?", (key,)
            ).fetchone()

    def update_upload_session_status(
        self,
        session_id: str,
        status: str,
        *,
        job_id: str | None = None,
        error_message: str | None = None,
    ) -> sqlite3.Row | None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """UPDATE upload_sessions SET status=?, updated_at=?,
                   job_id=COALESCE(?, job_id), error_message=? WHERE id=?""",
                (status, utcnow_iso(), job_id, error_message, session_id),
            )
            return conn.execute(
                "SELECT * FROM upload_sessions WHERE id=?", (session_id,)
            ).fetchone()

    def touch_upload_session(self, session_id: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE upload_sessions SET updated_at=? WHERE id=?",
                (utcnow_iso(), session_id),
            )

    def expire_due_upload_sessions(self, now_iso: str | None = None) -> list[str]:
        """把已过期的 uploading 会话置为 expired，返回本次置期的会话 id。"""
        stamp = now_iso or utcnow_iso()
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT id FROM upload_sessions WHERE status='uploading' "
                "AND expires_at<=?",
                (stamp,),
            ).fetchall()
            ids = [r["id"] for r in rows]
            if ids:
                conn.execute(
                    "UPDATE upload_sessions SET status='expired', updated_at=? "
                    "WHERE status='uploading' AND expires_at<=?",
                    (stamp, stamp),
                )
        return ids

    def resumable_upload_sessions(self) -> list[sqlite3.Row]:
        """重启后需要核对暂存状态的会话（仍在接收分片的）。"""
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM upload_sessions WHERE status='uploading' "
                "ORDER BY created_at ASC"
            ).fetchall()

    # ---------- 上传分片索引 ----------

    def add_upload_chunk(
        self, session_id: str, start: int, end: int, sha256: str
    ) -> None:
        """登记一个已落盘分片（end 为开区间）；重复区间由唯一约束拦截。"""
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO upload_chunks (session_id, start, end, sha256,
                   created_at) VALUES (?,?,?,?,?)""",
                (session_id, start, end, sha256, utcnow_iso()),
            )
            conn.execute(
                "UPDATE upload_sessions SET updated_at=? WHERE id=?",
                (utcnow_iso(), session_id),
            )

    def upload_chunks(self, session_id: str) -> list[sqlite3.Row]:
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM upload_chunks WHERE session_id=? ORDER BY start ASC",
                (session_id,),
            ).fetchall()

    def find_overlapping_chunks(
        self, session_id: str, start: int, end: int
    ) -> list[sqlite3.Row]:
        """与 [start, end) 相交（含相邻边界不算相交）的已登记分片。"""
        with self._conn() as conn:
            return conn.execute(
                "SELECT * FROM upload_chunks WHERE session_id=? "
                "AND start < ? AND end > ? ORDER BY start ASC",
                (session_id, end, start),
            ).fetchall()

    def upload_chunk_stats(self, session_id: str) -> tuple[int, int]:
        """返回 (已覆盖字节数, 最大已登记终点)；无分片时为 (0, 0)。"""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(end - start), 0) AS covered, "
                "COALESCE(MAX(end), 0) AS max_end FROM upload_chunks "
                "WHERE session_id=?",
                (session_id,),
            ).fetchone()
        return int(row["covered"]), int(row["max_end"])

    def delete_upload_chunks(self, session_id: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "DELETE FROM upload_chunks WHERE session_id=?", (session_id,)
            )
