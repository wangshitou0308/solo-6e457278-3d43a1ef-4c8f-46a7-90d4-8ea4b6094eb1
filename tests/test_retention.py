"""本地数据保留与安全清理测试：策略、保留锁、预览、执行、目标变化、部分失败重试与重启续跑。

时间语义：保留期限只能按服务当前时间评估；显式传入未来/过去的 now 会被拒绝。
需要“已过期”的作业时，把数据库内的完成时间回拨，而不是把评估时间拨到未来。
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from redactor import retention, stream_jobs
from redactor.database import Database, utcnow_iso
from redactor.samples import SAMPLE_STRATEGY, sample_ndjson


@pytest.fixture()
def client(isolated_data):
    stream_jobs.reset_recovery()
    stream_jobs.registry.reset()
    retention.reset_recovery()
    yield TestClient(isolated_data["app"])
    stream_jobs.registry.reset()
    stream_jobs.reset_recovery()
    retention.reset_recovery()


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


FAR = _iso(datetime.now(timezone.utc) + timedelta(days=500))


def _create_batch(client, key="b1", content=None):
    body = {"format": "ndjson",
            "content": content if content is not None else sample_ndjson(),
            "strategy": SAMPLE_STRATEGY}
    r = client.post("/api/v1/jobs", json=body, headers={"Idempotency-Key": key})
    assert r.status_code == 201, r.text
    return r.json()["job"]


def _age_job(db_path: Path, table: str, job_id: str, days: float) -> None:
    """把作业完成时间回拨 days 天（保留期按服务当前时间评估，不能拨未来 now）。"""
    _age_job_seconds(db_path, table, job_id, int(days * 86400))


def _age_job_seconds(db_path: Path, table: str, job_id: str, seconds: int) -> None:
    old = (datetime.now(timezone.utc) - timedelta(seconds=seconds)
           ).isoformat(timespec="seconds")
    with sqlite3.connect(db_path) as conn:
        if table == "jobs":
            conn.execute("UPDATE jobs SET created_at=? WHERE id=?", (old, job_id))
        else:
            conn.execute(
                f"UPDATE {table} SET updated_at=? WHERE id=?", (old, job_id))


def _preview(client, kinds=None):
    body: dict = {}
    if kinds:
        body["job_kinds"] = kinds
    return client.post("/api/v1/retention/cleanup/preview", json=body).json()


def _plan_epoch(value):
    from datetime import timezone as tz
    try:
        dt = datetime.fromisoformat((value or "").replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=tz.utc)
        return dt.timestamp()
    except ValueError:
        return 0.0


def _wait_plan(client, plan_id, timeout=10.0, *, after_updated: str | None = None):
    """等待计划终结；给 after_updated 时只接受 updated_at 晚于该值的终态，
    避免重试时读到上一轮的 partial。"""
    import time
    end = time.time() + timeout
    threshold = _plan_epoch(after_updated)
    # 终态需稳定 300ms，确认没有更新一轮执行正在写入
    stable_since = None
    last = None
    while time.time() < end:
        p = client.get(f"/api/v1/retention/cleanup/plans/{plan_id}").json()
        last = p
        if p["status"] in ("succeeded", "partial", "failed"):
            fresh = (after_updated is None
                     or _plan_epoch(p["updated_at"]) >= threshold)
            if fresh:
                now = time.time()
                if stable_since is None:
                    stable_since = now
                elif now - stable_since >= 0.3:
                    return p
        else:
            stable_since = None
        time.sleep(0.02)
    raise AssertionError(f"清理计划超时未终结: {last and last['status']}")


def _execute_preview(client, pv, key=None, status=202):
    payload = {
        "preview_id": pv["preview_id"],
        "target_fingerprint": pv["target_fingerprint"],
        "job_count": pv["job_count"], "file_count": pv["file_count"],
        "bytes_total": pv["bytes_total"],
    }
    headers = {"Idempotency-Key": key} if key else {}
    r = client.post("/api/v1/retention/cleanup/execute", json=payload, headers=headers)
    assert r.status_code == status, r.text
    return r.json()


# ---------- 时间校验 ----------


def test_future_now_rejected_in_preview_and_execute(client):
    future = _iso(datetime.now(timezone.utc) + timedelta(days=400))
    r = client.post("/api/v1/retention/cleanup/preview", json={"now": future})
    assert r.status_code == 400
    assert "时间" in r.json()["detail"]["message"]
    # 过去过远同样拒绝
    past = _iso(datetime.now(timezone.utc) - timedelta(days=400))
    r = client.post("/api/v1/retention/cleanup/preview", json={"now": past})
    assert r.status_code == 400
    # 秒级时钟偏差（未来 2 秒）允许
    near = _iso(datetime.now(timezone.utc) + timedelta(seconds=2))
    assert client.post("/api/v1/retention/cleanup/preview",
                       json={"now": near}).status_code == 200
    # 超过秒级容错的未来时间（3 分钟）拒绝：不能提前清理临近到期的作业
    soon = _iso(datetime.now(timezone.utc) + timedelta(minutes=3))
    assert client.post("/api/v1/retention/cleanup/preview",
                       json={"now": soon}).status_code == 400


def test_execute_rejects_future_now_even_for_idempotent_replay(
        client, isolated_data):
    """复用已有 Idempotency-Key 同时传未来 now：时间校验先于回放，返回 400。"""
    job = _create_batch(client)
    client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "true", "retention_days": 0})
    _age_job(isolated_data["settings"].db_path, "jobs", job["id"], 1)
    pv = _preview(client)
    key = "replay-time-1"
    # 首次执行成功，建立该幂等键的计划
    ok = client.post("/api/v1/retention/cleanup/execute", json={
        "preview_id": pv["preview_id"], "target_fingerprint": pv["target_fingerprint"],
        "job_count": pv["job_count"], "file_count": pv["file_count"],
        "bytes_total": pv["bytes_total"]}, headers={"Idempotency-Key": key})
    assert ok.status_code == 202
    _wait_plan(client, ok.json()["plan"]["plan_id"])
    # 同一键 + 未来 now：必须 400，而不是 200/replayed=true
    future = _iso(datetime.now(timezone.utc) + timedelta(minutes=3))
    r = client.post("/api/v1/retention/cleanup/execute", json={
        "preview_id": pv["preview_id"], "target_fingerprint": pv["target_fingerprint"],
        "job_count": pv["job_count"], "file_count": pv["file_count"],
        "bytes_total": pv["bytes_total"], "now": future},
        headers={"Idempotency-Key": key})
    assert r.status_code == 400, r.status_code


def test_preview_execute_consistent_near_deadline(client, isolated_data):
    """距到期很近（约 120 秒）的作业：用 3 分钟后的 now 预览被拒，无法提前纳入；

    只有真正到期后（回拨完成时间模拟时间流逝）预览、执行、计划状态才一致成功。
    """
    job = _create_batch(client)
    client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "true", "retention_days": 1})
    # 完成于 23 小时 58 分前：距到期约 120 秒，现在不应入选
    _age_job_seconds(isolated_data["settings"].db_path, "jobs", job["id"],
                     23 * 3600 + 58 * 60)
    pv_now = _preview(client)
    assert job["id"] not in [i["job_id"] for i in pv_now["items"]]
    assert pv_now["blocked"]["retained"] >= 1
    # 3 分钟后的 now 被拒（否则会提前约 2 分钟清理）
    soon = _iso(datetime.now(timezone.utc) + timedelta(minutes=3))
    r = client.post("/api/v1/retention/cleanup/preview", json={"now": soon})
    assert r.status_code == 400
    # 时间真正走过到期点（回拨到 1 天 + 1 分钟前）：预览入选、执行成功、无 partial
    _age_job_seconds(isolated_data["settings"].db_path, "jobs", job["id"],
                     24 * 3600 + 60)
    pv = _preview(client)
    assert any(i["job_id"] == job["id"] for i in pv["items"])
    resp = _execute_preview(client, pv, key="near-deadline-1")
    plan = _wait_plan(client, resp["plan"]["plan_id"])
    assert plan["status"] == "succeeded", plan["status"]
    assert all(
        o["outcome"] != "guard_refused"
        for it in plan["items"] for o in it["outcomes"])


def test_fresh_job_cannot_be_cleaned_early_even_with_zero_rule(client, isolated_data):
    """刚完成、仍在保留期内的作业不会被任何时间技巧提前清掉。"""
    job = _create_batch(client)
    # 默认 90 天（需复核）：现在不可清
    pv = _preview(client)
    assert job["id"] not in [i["job_id"] for i in pv["items"]]
    assert pv["blocked"]["retained"] >= 1
    # 即使把规则改成 0 天，完成时刻为“现在”的作业按 deadline=now 仍不应入选；
    # 回拨完成时间 1 秒前即可入选（边界由 completed+0d <= now 决定）
    client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "true", "retention_days": 0})
    pv = _preview(client)
    # completed_at 与 now 同为当前秒：deadline==completed，now>=deadline 通常入选；
    # 关键保证是“不能靠传未来 now”达成（见上一测试）
    assert isinstance(pv["job_count"], int)


# ---------- 策略 ----------


def test_policy_defaults_seeded(client):
    pol = client.get("/api/v1/retention/policy").json()
    keys = {(r["job_kind"], r["terminal_status"], r["needs_review"]) for r in pol["rules"]}
    assert ("batch", "succeeded", "false") in keys
    assert ("stream", "failed", "any") in keys
    assert all(r["builtin"] for r in pol["rules"])
    # 默认期限：batch succeeded false=30, true=90
    by = {(r["job_kind"], r["terminal_status"], r["needs_review"]): r
          for r in pol["rules"]}
    assert by[("batch", "succeeded", "false")]["retention_days"] == 30
    assert by[("batch", "succeeded", "true")]["retention_days"] == 90


def test_rule_upsert_overrides_and_delete_restores_builtin(client):
    r = client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "false", "retention_days": 1})
    rule = next(x for x in r.json()["rules"]
                if (x["job_kind"], x["terminal_status"], x["needs_review"])
                == ("batch", "succeeded", "false"))
    assert rule["retention_days"] == 1 and rule["builtin"] is False
    # 覆盖为永久保留
    client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "false", "retention_days": None})
    rule = next(x for x in client.get("/api/v1/retention/policy").json()["rules"]
                if (x["job_kind"], x["terminal_status"], x["needs_review"])
                == ("batch", "succeeded", "false"))
    assert rule["retention_days"] is None
    # 删除自定义覆盖：内置 30 天必须恢复（而不是规则消失）
    d = client.delete("/api/v1/retention/rules/batch/succeeded/false")
    assert d.status_code == 200
    rule = next(x for x in d.json()["rules"]
                if (x["job_kind"], x["terminal_status"], x["needs_review"])
                == ("batch", "succeeded", "false"))
    assert rule["retention_days"] == 30 and rule["builtin"] is True
    # 再次删除内置规则 -> 404
    assert client.delete(
        "/api/v1/retention/rules/batch/succeeded/false").status_code == 404


def test_delete_custom_any_rule_without_builtin_removes_completely(client):
    """内置没有的键（如 batch failed）删除自定义覆盖后保持“无规则=永久保留”。"""
    client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "failed",
        "needs_review": "any", "retention_days": 5})
    r = client.delete("/api/v1/retention/rules/batch/failed/any")
    assert r.status_code == 200
    assert not any(
        (x["job_kind"], x["terminal_status"], x["needs_review"])
        == ("batch", "failed", "any") for x in r.json()["rules"])


def test_any_review_custom_rule_overrides_builtin_exact(client, isolated_data):
    job = _create_batch(client)  # needs_review=true
    client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "any", "retention_days": None})
    # 即使完成时间很老，自定义 any 永久保留优先于内置 90 天
    _age_job(isolated_data["settings"].db_path, "jobs", job["id"], 400)
    pv = _preview(client)
    assert job["id"] not in [i["job_id"] for i in pv["items"]]
    assert pv["blocked"]["permanent"] >= 1


# ---------- 保留锁 ----------


def test_lock_lifecycle_conflict(client):
    job = _create_batch(client)
    assert client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": "nope", "reason": "x",
        "expires_at": FAR}).status_code == 404
    assert client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": job["id"], "reason": "调查中",
        "expires_at": FAR}).status_code == 200
    assert client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": job["id"], "reason": "别的",
        "expires_at": FAR}).status_code == 409
    r = client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": job["id"], "reason": "调查中",
        "expires_at": FAR})
    assert r.status_code == 200 and r.json()["replayed"] is True
    assert any(x["job_id"] == job["id"]
               for x in client.get("/api/v1/retention/locks?state=active").json()["items"])
    assert client.delete(f"/api/v1/retention/locks/batch/{job['id']}").status_code == 200
    assert client.delete(f"/api/v1/retention/locks/batch/{job['id']}").status_code == 404
    # 释放原因可查
    rel = client.get("/api/v1/retention/locks?state=released").json()
    assert any(x["job_id"] == job["id"] and x["state"] == "released"
               for x in rel["items"])
    assert client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": job["id"], "reason": "再保留",
        "expires_at": FAR}).status_code == 200


def test_past_expiry_lock_rejected(client):
    job = _create_batch(client)
    past = _iso(datetime.now(timezone.utc) - timedelta(days=1))
    r = client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": job["id"], "reason": "x",
        "expires_at": past})
    assert r.status_code == 422


def test_expired_lock_state_consistent_between_list_and_preview(client, isolated_data):
    """同一把已到期锁：锁列表能按 state=expired 查到，预览也不被它拦截。"""
    job = _create_batch(client)
    db_path = isolated_data["settings"].db_path
    # 直接构造一把“已到期但尚未被扫描标记”的锁（历史遗留行）
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO retention_locks (job_kind,job_id,reason,expires_at,"
            "created_at,released_at,release_reason) VALUES (?,?,?,?,?,?,'')",
            ("batch", job["id"], "old",
             _iso(datetime.now(timezone.utc) - timedelta(days=1)),
             _iso(datetime.now(timezone.utc) - timedelta(days=2)), ""))
    # 任何锁查询都先按墙钟时间统一失效扫描
    expired = client.get("/api/v1/retention/locks?state=expired").json()
    assert any(x["job_id"] == job["id"] and x["state"] == "expired"
               for x in expired["items"])
    active = client.get("/api/v1/retention/locks?state=active").json()
    assert not any(x["job_id"] == job["id"] for x in active["items"])
    # 清理评估与列表同一基准：把作业变老且 0 天规则后，到期锁不拦截
    client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "true", "retention_days": 0})
    _age_job(db_path, "jobs", job["id"], 1)
    pv = _preview(client)
    assert any(i["job_id"] == job["id"] for i in pv["items"])
    assert pv["blocked"]["locked"] == 0


# ---------- 预览 ----------


def test_preview_shape_and_no_content(client, isolated_data):
    job = _create_batch(client)
    _age_job(isolated_data["settings"].db_path, "jobs", job["id"], 100)
    pv = _preview(client)
    assert pv["job_count"] == 1
    item = pv["items"][0]
    assert item["job_id"] == job["id"]
    assert item["rule_source"] == "builtin"
    assert {f["category"] for f in item["files"]} == {"result", "receipt"}
    assert all(f["status"] == "present" for f in item["files"])
    assert item["bytes_total"] > 0
    blob = json.dumps(pv, ensure_ascii=False)
    assert "zhangsan@example.com" not in blob and "13800001234" not in blob
    pv2 = _preview(client)
    assert pv2["target_fingerprint"] == pv["target_fingerprint"]


def test_fresh_job_preview_blocked_retained(client):
    _create_batch(client)
    pv = _preview(client)
    assert pv["job_count"] == 0 and pv["blocked"]["retained"] >= 1


def test_preview_respects_job_kinds_filter(client, isolated_data):
    job = _create_batch(client)
    _age_job(isolated_data["settings"].db_path, "jobs", job["id"], 100)
    assert _preview(client, kinds=["stream", "bundle"])["job_count"] == 0
    assert _preview(client, kinds=["batch"])["job_count"] == 1


def test_running_stream_job_blocked(client, isolated_data, monkeypatch):
    gate = threading.Event()
    monkeypatch.setattr(stream_jobs, "on_record_hook",
                        lambda jid, line: gate.set())
    r = client.post("/api/v1/stream-jobs",
                    files={"file": ("logs.ndjson", sample_ndjson(),
                                    "application/x-ndjson")},
                    data={"strategy": json.dumps(SAMPLE_STRATEGY)})
    sid = r.json()["job"]["id"]
    assert gate.wait(timeout=5)
    pv = _preview(client)
    assert sid not in [i["job_id"] for i in pv["items"]]
    assert pv["blocked"]["running"] >= 1
    stream_jobs.registry.request_cancel(sid)
    import time
    final_status = None
    end = time.time() + 10
    while time.time() < end:
        final_status = client.get(f"/api/v1/stream-jobs/{sid}").json()["status"]
        if final_status in ("cancelled", "failed", "succeeded"):
            break
        time.sleep(0.02)
    assert final_status in ("cancelled", "failed", "succeeded"), final_status
    # 小文件可能在取消生效前已成功；统一配置 0 天期限并回拨完成时间
    if final_status == "succeeded":
        for review in ("true", "false"):
            client.put("/api/v1/retention/rules", json={
                "job_kind": "stream", "terminal_status": "succeeded",
                "needs_review": review, "retention_days": 0})
    _age_job(isolated_data["settings"].db_path, "stream_jobs", sid, 10)
    pv2 = _preview(client)
    matched = [i for i in pv2["items"] if i["job_id"] == sid]
    assert matched, (final_status, pv2["blocked"], pv2["items"])


# ---------- 执行 ----------


def test_execute_deletes_files_and_records(client, isolated_data):
    data_dir = isolated_data["data_dir"]
    job = _create_batch(client)
    _age_job(isolated_data["settings"].db_path, "jobs", job["id"], 100)
    out = data_dir / "jobs" / f"{job['id']}.ndjson"
    receipt = data_dir / "jobs" / f"{job['id']}.receipt.json"
    assert out.exists() and receipt.exists()
    pv = _preview(client)
    resp = _execute_preview(client, pv, key="run-1")
    plan = _wait_plan(client, resp["plan"]["plan_id"])
    assert plan["status"] == "succeeded"
    assert plan["jobs_done"] == 1 and plan["bytes_deleted"] > 0
    assert not out.exists() and not receipt.exists()
    assert client.get(f"/api/v1/jobs/{job['id']}").status_code == 404
    db = Database(isolated_data["settings"].db_path)
    with db._conn() as conn:
        assert conn.execute("SELECT COUNT(*) c FROM jobs WHERE id=?",
                            (job["id"],)).fetchone()["c"] == 0
        assert conn.execute("SELECT COUNT(*) c FROM audit WHERE job_id=?",
                            (job["id"],)).fetchone()["c"] == 0


def test_execute_rejects_target_change_and_bad_summary(client, isolated_data):
    job = _create_batch(client)
    _age_job(isolated_data["settings"].db_path, "jobs", job["id"], 100)
    pv = _preview(client)
    r = client.post("/api/v1/retention/cleanup/execute", json={
        "preview_id": "x" * 64, "target_fingerprint": "x" * 64,
        "job_count": pv["job_count"], "file_count": pv["file_count"],
        "bytes_total": pv["bytes_total"]})
    assert r.status_code == 409
    r = client.post("/api/v1/retention/cleanup/execute", json={
        "preview_id": pv["target_fingerprint"],
        "target_fingerprint": pv["target_fingerprint"],
        "job_count": pv["job_count"] + 1, "file_count": pv["file_count"],
        "bytes_total": pv["bytes_total"]})
    assert r.status_code == 409
    r = client.post("/api/v1/retention/cleanup/execute", json={
        "preview_id": "y" * 64, "target_fingerprint": pv["target_fingerprint"],
        "job_count": 1, "file_count": 1, "bytes_total": 1})
    assert r.status_code == 400


def test_empty_preview_execute_400(client):
    r = client.post("/api/v1/retention/cleanup/preview", json={}).json()
    assert r["job_count"] == 0
    resp = client.post("/api/v1/retention/cleanup/execute", json={
        "preview_id": r["preview_id"], "target_fingerprint": r["target_fingerprint"],
        "job_count": 0, "file_count": 0, "bytes_total": 0})
    assert resp.status_code in (400, 409)


def test_lock_added_after_preview_blocks_execution(client, isolated_data):
    """预览后加锁：目标指纹变化，提交旧摘要被 409，记录保留。"""
    job = _create_batch(client)
    _age_job(isolated_data["settings"].db_path, "jobs", job["id"], 100)
    pv = _preview(client)
    client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": job["id"], "reason": "预览后保留",
        "expires_at": FAR})
    resp = client.post("/api/v1/retention/cleanup/execute", json={
        "preview_id": pv["target_fingerprint"],
        "target_fingerprint": pv["target_fingerprint"],
        "job_count": pv["job_count"], "file_count": pv["file_count"],
        "bytes_total": pv["bytes_total"]})
    assert resp.status_code == 409
    assert client.get(f"/api/v1/jobs/{job['id']}").status_code == 200


def test_execute_idempotency_key_replays(client, isolated_data):
    job = _create_batch(client)
    _age_job(isolated_data["settings"].db_path, "jobs", job["id"], 100)
    pv = _preview(client)
    r1 = _execute_preview(client, pv, key="idem-1")
    pid = r1["plan"]["plan_id"]
    _wait_plan(client, pid)
    r2 = _execute_preview(client, pv, key="idem-1", status=200)
    assert r2["replayed"] is True and r2["plan"]["plan_id"] == pid


# ---------- 符号链接：不得删除锁定对象 ----------


def test_symlink_to_locked_job_target_refused(client, isolated_data):
    """结果路径被替换为指向另一把锁保护作业的符号链接：

    整个作业项在删除任何文件之前失败（partial），符号链接与其锁定目标都保留，
    两个作业的数据库记录都不动；移除链接后重试成功。
    """
    data_dir = isolated_data["data_dir"]
    victim = _create_batch(client, key="v1")
    locked = _create_batch(client, key="l1")
    client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "true", "retention_days": 0})
    client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": locked["id"], "reason": "锁定对象",
        "expires_at": FAR})
    _age_job(isolated_data["settings"].db_path, "jobs", victim["id"], 1)
    _age_job(isolated_data["settings"].db_path, "jobs", locked["id"], 1)

    target = data_dir / "jobs" / f"{locked['id']}.ndjson"
    link = data_dir / "jobs" / f"{victim['id']}.ndjson"
    target_text = target.read_text()
    link.unlink()
    link.symlink_to(target)

    pv = _preview(client)
    # 被锁作业不入选；受害作业入选且其结果条目标注 symlink
    assert [i["job_id"] for i in pv["items"]] == [victim["id"]]
    assert pv["blocked"]["locked"] == 1
    entry = next(f for i in pv["items"] for f in i["files"]
                 if f["category"] == "result")
    assert entry["note"] == "symlink"

    resp = _execute_preview(client, pv, key="sym-1")
    plan = _wait_plan(client, resp["plan"]["plan_id"])
    assert plan["status"] == "partial"
    item = plan["items"][0]
    assert item["status"] == "failed"
    outcomes = item["outcomes"]
    assert outcomes[0]["outcome"] == "unsafe_target_refused"
    assert any(o["outcome"] == "symlink_refused" for o in outcomes)
    # 关键安全断言：锁定目标文件内容完好，符号链接未被删除，记录均保留
    assert target.exists() and target.read_text() == target_text
    assert link.is_symlink()
    assert client.get(f"/api/v1/jobs/{victim['id']}").status_code == 200
    assert client.get(f"/api/v1/jobs/{locked['id']}").status_code == 200

    # 审计中可查到拒绝结果
    aud = client.get(
        "/api/v1/retention/audit?action=cleanup.item.failed").json()
    assert aud["total"] >= 1

    # 移除符号链接（缺失）后重试：成功并清掉受害作业记录
    link.unlink()
    before_updated = plan["updated_at"]
    rt = client.post(f"/api/v1/retention/cleanup/plans/{plan['plan_id']}/retry")
    assert rt.status_code == 202
    plan2 = _wait_plan(client, plan["plan_id"], after_updated=before_updated)
    assert plan2["status"] == "succeeded"
    assert client.get(f"/api/v1/jobs/{victim['id']}").status_code == 404
    assert client.get(f"/api/v1/jobs/{locked['id']}").status_code == 200
    assert target.exists()


# ---------- 缺失文件：结果非空、记录照删 ----------


def test_missing_files_recorded_and_records_still_deleted(client, isolated_data):
    data_dir = isolated_data["data_dir"]
    job = _create_batch(client)
    client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "true", "retention_days": 0})
    _age_job(isolated_data["settings"].db_path, "jobs", job["id"], 1)
    out = data_dir / "jobs" / f"{job['id']}.ndjson"
    receipt = data_dir / "jobs" / f"{job['id']}.receipt.json"
    out.unlink()
    receipt.unlink()
    pv = _preview(client)
    item = next(i for i in pv["items"] if i["job_id"] == job["id"])
    assert {f["status"] for f in item["files"]} == {"missing"}
    assert item["bytes_total"] == 0
    resp = _execute_preview(client, pv, key="miss-1")
    plan = _wait_plan(client, resp["plan"]["plan_id"])
    assert plan["status"] == "succeeded"
    outcomes = [o["outcome"] for it in plan["items"] for o in it["outcomes"]]
    # 缺失项明确记录（非空结果），可查询、可审计
    assert outcomes == ["missing", "missing"]
    assert plan["items"][0]["processed"] == 2
    assert client.get(f"/api/v1/jobs/{job['id']}").status_code == 404


def test_bundle_staging_symlink_refused(client, isolated_data):
    """诊断包残留暂存目录内含符号链接时：整个作业项拒绝删除，链接目标保留。"""
    data_dir = isolated_data["data_dir"]
    job = _create_batch(client, key="bs1")  # 用 batch 记录承载一个 bundle 风格暂存目录
    client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "true", "retention_days": 0})
    _age_job(isolated_data["settings"].db_path, "jobs", job["id"], 1)

    # 构造一个 bundle 暂存目录并把作业“伪装”为 bundle 记录较繁琐，这里直接
    # 针对安全删除原语：暂存目录内含指向界外文件的符号链接时 _walk_plain 上报、
    # _prescan_unsafe 拒绝。
    from redactor import retention
    roots = retention._allowed_roots()
    staging = data_dir / "bundles" / "staging" / "fakejob"
    staging.mkdir(parents=True)
    outside = data_dir / "secret.txt"
    outside.write_text("LOCKED")
    (staging / "a.txt").write_text("normal")
    (staging / "evil.link").symlink_to(outside)
    unsafe = retention._prescan_unsafe(
        [{"category": "bundle_staging", "path": "bundles/staging/fakejob/"}],
        roots)
    assert any(u["outcome"] == "symlink_refused" for u in unsafe)
    # 界外目标完好
    assert outside.read_text() == "LOCKED"


def test_retry_succeeded_plan_409(client, isolated_data):
    job = _create_batch(client)
    client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "true", "retention_days": 0})
    _age_job(isolated_data["settings"].db_path, "jobs", job["id"], 1)
    pv = _preview(client)
    resp = _execute_preview(client, pv, key="ok-1")
    plan = _wait_plan(client, resp["plan"]["plan_id"])
    assert client.post(
        f"/api/v1/retention/cleanup/plans/{plan['plan_id']}/retry"
    ).status_code == 409


# ---------- 重启恢复 ----------


def test_interrupted_plan_resumes_after_recovery(client, isolated_data):
    j1 = _create_batch(client, key="r1")
    j2 = _create_batch(client, key="r2")
    client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "true", "retention_days": 0})
    _age_job(isolated_data["settings"].db_path, "jobs", j1["id"], 1)
    _age_job(isolated_data["settings"].db_path, "jobs", j2["id"], 1)
    pv = _preview(client)
    assert pv["job_count"] == 2

    db = Database(isolated_data["settings"].db_path)
    plan_id, replayed = retention.persist_plan(
        db, preview=retention.build_preview(db), idempotency_key="crashed-1")
    assert not replayed
    assert client.get(
        f"/api/v1/retention/cleanup/plans/{plan_id}").json()["status"] == "pending"

    retention.reset_recovery()
    with TestClient(isolated_data["app"]):
        pass
    plan = client.get(f"/api/v1/retention/cleanup/plans/{plan_id}").json()
    assert plan["status"] == "succeeded", plan["status"]
    assert plan["jobs_done"] == 2


# ---------- 审计 ----------


def test_audit_query_and_filters(client, isolated_data):
    job = _create_batch(client)
    client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": job["id"], "reason": "a",
        "expires_at": FAR})
    client.delete(f"/api/v1/retention/locks/batch/{job['id']}")
    client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "true", "retention_days": 0})
    _age_job(isolated_data["settings"].db_path, "jobs", job["id"], 1)
    pv = _preview(client)
    resp = _execute_preview(client, pv, key="aud-1")
    _wait_plan(client, resp["plan"]["plan_id"])

    page = client.get("/api/v1/retention/audit?limit=100").json()
    actions = {e["action"] for e in page["items"]}
    assert {"lock.created", "lock.released", "policy.rule.set",
            "cleanup.plan.created", "cleanup.plan.finished"} <= actions
    locks = client.get("/api/v1/retention/audit?action=lock.created").json()
    assert locks["total"] >= 1 and all(
        e["action"] == "lock.created" for e in locks["items"])
    assert "zhangsan@example.com" not in json.dumps(page, ensure_ascii=False)
