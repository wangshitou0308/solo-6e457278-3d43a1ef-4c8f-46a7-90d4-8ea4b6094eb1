"""本地数据保留与安全清理测试：策略、保留锁、预览、执行、目标变化、部分失败重试与重启续跑。"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from redactor import retention, stream_jobs, config as config_mod
from redactor.database import Database
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


FUTURE = _iso(datetime.now(timezone.utc) + timedelta(days=400))
SOON = _iso(datetime.now(timezone.utc) + timedelta(hours=1))
FAR = _iso(datetime.now(timezone.utc) + timedelta(days=500))


def _create_batch(client, key="b1", content=None):
    body = {"format": "ndjson",
            "content": content if content is not None else sample_ndjson(),
            "strategy": SAMPLE_STRATEGY}
    r = client.post("/api/v1/jobs", json=body, headers={"Idempotency-Key": key})
    assert r.status_code == 201, r.text
    return r.json()["job"]


def _preview(client, now=FUTURE, kinds=None):
    body: dict = {"now": now}
    if kinds:
        body["job_kinds"] = kinds
    return client.post("/api/v1/retention/cleanup/preview", json=body).json()


def _wait_plan(client, plan_id, timeout=10.0):
    deadline = threading.get_native_id() and (
        datetime.now(timezone.utc).timestamp() + timeout)
    import time
    end = time.time() + timeout
    while time.time() < end:
        p = client.get(f"/api/v1/retention/cleanup/plans/{plan_id}").json()
        if p["status"] in ("succeeded", "partial", "failed"):
            return p
        time.sleep(0.02)
    raise AssertionError("清理计划超时未终结")


def _execute_preview(client, pv, now=FUTURE, key=None, status=202):
    payload = {
        "preview_id": pv["preview_id"],
        "target_fingerprint": pv["target_fingerprint"],
        "job_count": pv["job_count"], "file_count": pv["file_count"],
        "bytes_total": pv["bytes_total"], "now": now,
    }
    headers = {"Idempotency-Key": key} if key else {}
    r = client.post("/api/v1/retention/cleanup/execute", json=payload, headers=headers)
    assert r.status_code == status, r.text
    return r.json()


# ---------- 策略 ----------


def test_policy_defaults_seeded(client):
    pol = client.get("/api/v1/retention/policy").json()
    keys = {(r["job_kind"], r["terminal_status"], r["needs_review"]) for r in pol["rules"]}
    assert ("batch", "succeeded", "false") in keys
    assert ("stream", "failed", "any") in keys
    assert all(r["builtin"] for r in pol["rules"])


def test_rule_upsert_overrides_and_delete_falls_back(client):
    r = client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "false", "retention_days": 1})
    assert r.status_code == 200
    rule = next(x for x in r.json()["rules"]
                if (x["job_kind"], x["terminal_status"], x["needs_review"])
                == ("batch", "succeeded", "false"))
    assert rule["retention_days"] == 1 and rule["builtin"] is False
    # 重复提交幂等（覆盖为永久保留）
    client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "false", "retention_days": None})
    rule = next(x for x in client.get("/api/v1/retention/policy").json()["rules"]
                if (x["job_kind"], x["terminal_status"], x["needs_review"])
                == ("batch", "succeeded", "false"))
    assert rule["retention_days"] is None
    # 删除自定义覆盖回退内置 30 天
    d = client.delete("/api/v1/retention/rules/batch/succeeded/false")
    assert d.status_code == 200
    rule = next(x for x in d.json()["rules"]
                if (x["job_kind"], x["terminal_status"], x["needs_review"])
                == ("batch", "succeeded", "false"))
    assert rule["retention_days"] == 30 and rule["builtin"] is True
    # 内置规则不可删
    assert client.delete("/api/v1/retention/rules/stream/failed/any").status_code == 404


def test_any_review_custom_rule_overrides_builtin_exact(client):
    """自定义 any 永久保留优先于内置精确键（90 天）。"""
    job = _create_batch(client)  # needs_review=true
    client.put("/api/v1/retention/rules", json={
        "job_kind": "batch", "terminal_status": "succeeded",
        "needs_review": "any", "retention_days": None})
    pv = _preview(client)
    assert job["id"] not in [i["job_id"] for i in pv["items"]]
    assert pv["blocked"]["permanent"] >= 1


# ---------- 保留锁 ----------


def test_lock_lifecycle_conflict_and_expiry(client, isolated_data):
    job = _create_batch(client)
    # 锁未知作业 404
    r = client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": "nope", "reason": "x", "expires_at": FAR})
    assert r.status_code == 404
    # 加锁
    r = client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": job["id"], "reason": "调查中", "expires_at": FAR})
    assert r.status_code == 200 and r.json()["lock"]["state"] == "active"
    # 不同原因 -> 409
    r = client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": job["id"], "reason": "别的", "expires_at": FAR})
    assert r.status_code == 409
    # 相同请求 -> 幂等 200
    r = client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": job["id"], "reason": "调查中", "expires_at": FAR})
    assert r.status_code == 200 and r.json()["replayed"] is True
    # 列表过滤
    lst = client.get("/api/v1/retention/locks?state=active").json()
    assert any(x["job_id"] == job["id"] for x in lst["items"])
    # 释放
    assert client.delete(f"/api/v1/retention/locks/batch/{job['id']}").status_code == 200
    assert client.delete(f"/api/v1/retention/locks/batch/{job['id']}").status_code == 404
    # 释放后可重新加锁
    assert client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": job["id"], "reason": "再保留",
        "expires_at": FAR}).status_code == 200


def test_expired_lock_does_not_block(client):
    job = _create_batch(client)
    # 已过期的时间点加锁 -> 422
    past = _iso(datetime.now(timezone.utc) - timedelta(days=1))
    r = client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": job["id"], "reason": "x", "expires_at": past})
    assert r.status_code == 422
    # 加一把只到“未来 1 天”的锁；在 +400 天评估点已过期，不拦截清理
    soon_lock = _iso(datetime.now(timezone.utc) + timedelta(days=1))
    client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": job["id"], "reason": "临时",
        "expires_at": soon_lock})
    pv = _preview(client)
    assert job["id"] in [i["job_id"] for i in pv["items"]]
    # 过期锁状态展示为 expired
    lst = client.get("/api/v1/retention/locks?state=expired").json()
    assert any(x["job_id"] == job["id"] and x["state"] == "expired"
               for x in lst["items"])


# ---------- 预览：不含内容 ----------


def test_preview_shape_and_no_content(client, isolated_data):
    job = _create_batch(client)
    pv = _preview(client)
    assert pv["job_count"] == 1
    item = pv["items"][0]
    assert item["job_id"] == job["id"]
    assert item["rule_source"] == "builtin"
    assert {f["category"] for f in item["files"]} == {"result", "receipt"}
    assert item["bytes_total"] > 0
    # 预览与返回中绝不含日志原文/敏感值
    blob = json.dumps(pv, ensure_ascii=False)
    assert "zhangsan@example.com" not in blob
    assert "13800001234" not in blob
    # 重复预览幂等：同状态指纹一致
    pv2 = _preview(client)
    assert pv2["target_fingerprint"] == pv["target_fingerprint"]
    # 当前时间不满足期限 -> 不入选
    now_pv = client.post("/api/v1/retention/cleanup/preview", json={}).json()
    assert now_pv["job_count"] == 0
    assert now_pv["blocked"]["retained"] >= 1


def test_preview_respects_job_kinds_filter(client):
    _create_batch(client)
    pv = _preview(client, kinds=["stream", "bundle"])
    assert pv["job_count"] == 0
    pv_all = _preview(client, kinds=["batch"])
    assert pv_all["job_count"] == 1


def test_running_stream_job_blocked_from_preview(client, isolated_data, monkeypatch):
    gate = threading.Event()

    def hook(job_id, line_no):
        gate.set()

    monkeypatch.setattr(stream_jobs, "on_record_hook", hook)
    files = {"file": ("logs.ndjson", sample_ndjson(), "application/x-ndjson")}
    data = {"strategy": json.dumps(SAMPLE_STRATEGY)}
    r = client.post("/api/v1/stream-jobs", files=files, data=data)
    assert r.status_code == 202
    sid = r.json()["job"]["id"]
    assert gate.wait(timeout=5)
    # 运行中：既不入选清理，也计入 blocked.running
    pv = _preview(client)
    assert sid not in [i["job_id"] for i in pv["items"]]
    assert pv["blocked"]["running"] >= 1
    stream_jobs.registry.request_cancel(sid)
    # 等终态后（cancelled 3 天期限），+400 天可清理
    import time
    end = time.time() + 10
    while time.time() < end:
        st = client.get(f"/api/v1/stream-jobs/{sid}").json()["status"]
        if st in ("cancelled", "failed", "succeeded"):
            break
        time.sleep(0.02)
    pv2 = _preview(client)
    assert any(i["job_id"] == sid for i in pv2["items"])


# ---------- 执行 ----------


def test_execute_deletes_files_and_records(client, isolated_data):
    data_dir = isolated_data["data_dir"]
    job = _create_batch(client)
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
    # 审计/风险记录一并删除
    db = Database(isolated_data["settings"].db_path)
    with db._conn() as conn:  # noqa: SLF001
        assert conn.execute("SELECT COUNT(*) c FROM jobs WHERE id=?",
                            (job["id"],)).fetchone()["c"] == 0
        assert conn.execute("SELECT COUNT(*) c FROM audit WHERE job_id=?",
                            (job["id"],)).fetchone()["c"] == 0


def test_execute_rejects_target_change_and_bad_summary(client):
    job = _create_batch(client)
    pv = _preview(client)
    # 篡改指纹 -> 409
    r = client.post("/api/v1/retention/cleanup/execute", json={
        "preview_id": "x" * 64, "target_fingerprint": "x" * 64,
        "job_count": pv["job_count"], "file_count": pv["file_count"],
        "bytes_total": pv["bytes_total"], "now": FUTURE})
    assert r.status_code == 409
    # 指纹一致但计数不符 -> 409
    r = client.post("/api/v1/retention/cleanup/execute", json={
        "preview_id": pv["target_fingerprint"],
        "target_fingerprint": pv["target_fingerprint"],
        "job_count": pv["job_count"] + 1, "file_count": pv["file_count"],
        "bytes_total": pv["bytes_total"], "now": FUTURE})
    assert r.status_code == 409
    # preview_id 与指纹不一致 -> 400
    r = client.post("/api/v1/retention/cleanup/execute", json={
        "preview_id": "y" * 64, "target_fingerprint": pv["target_fingerprint"],
        "job_count": 1, "file_count": 1, "bytes_total": 1, "now": FUTURE})
    assert r.status_code == 400


def test_execute_empty_preview_400(client):
    r = client.post("/api/v1/retention/cleanup/preview", json={}).json()
    resp = client.post("/api/v1/retention/cleanup/execute", json={
        "preview_id": r["preview_id"], "target_fingerprint": r["target_fingerprint"],
        "job_count": 0, "file_count": 0, "bytes_total": 0})
    assert resp.status_code == 400


def test_lock_added_after_preview_blocks_execution(client):
    """预览后、执行前加锁：执行守卫复核失败，计划项 failed，记录保留。"""
    job = _create_batch(client)
    pv = _preview(client)
    client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": job["id"], "reason": "预览后决定保留",
        "expires_at": FAR})
    # 提交的是旧指纹（加锁改变了目标）-> 直接 409
    resp = client.post("/api/v1/retention/cleanup/execute", json={
        "preview_id": pv["target_fingerprint"],
        "target_fingerprint": pv["target_fingerprint"],
        "job_count": pv["job_count"], "file_count": pv["file_count"],
        "bytes_total": pv["bytes_total"], "now": FUTURE})
    assert resp.status_code == 409
    assert client.get(f"/api/v1/jobs/{job['id']}").status_code == 200


def test_execute_idempotency_key_replays(client):
    _create_batch(client)
    pv = _preview(client)
    r1 = _execute_preview(client, pv, key="idem-1", status=202)
    pid = r1["plan"]["plan_id"]
    _wait_plan(client, pid)
    # 同键重复提交 -> 200 回放同一计划（即使目标已被删空）
    r2 = _execute_preview(client, pv, now=FUTURE, key="idem-1", status=200)
    assert r2["replayed"] is True and r2["plan"]["plan_id"] == pid


# ---------- 部分失败与重试 ----------


def test_missing_files_are_idempotent_and_still_delete_records(client, isolated_data):
    """文件已被外部删除（缺失）时，执行按已删处理，数据库记录仍清理。"""
    job = _create_batch(client)
    out = isolated_data["data_dir"] / "jobs" / f"{job['id']}.ndjson"
    receipt = isolated_data["data_dir"] / "jobs" / f"{job['id']}.receipt.json"
    pv = _preview(client)
    # 预览后、执行前把文件手工删掉
    out.unlink()
    receipt.unlink()
    # 目标已变化（文件缺失）-> 409，需要重新预览
    stale = client.post("/api/v1/retention/cleanup/execute", json={
        "preview_id": pv["target_fingerprint"],
        "target_fingerprint": pv["target_fingerprint"],
        "job_count": pv["job_count"], "file_count": pv["file_count"],
        "bytes_total": pv["bytes_total"], "now": FUTURE})
    assert stale.status_code == 409
    # 重新预览：作业仍入选（文件缺失按大小 0 计），执行成功并清掉记录
    pv2 = _preview(client)
    item = pv2["items"][0]
    assert item["bytes_total"] == 0
    resp = _execute_preview(client, pv2, key="missing-1")
    plan = _wait_plan(client, resp["plan"]["plan_id"])
    assert plan["status"] == "succeeded"
    outcomes = [o["outcome"] for it in plan["items"] for o in it["outcomes"]]
    assert set(outcomes) == {"missing"}
    assert client.get(f"/api/v1/jobs/{job['id']}").status_code == 404


def test_symlink_refused_recorded_and_retryable(client, isolated_data, monkeypatch):
    """结果文件被替换为符号链接：拒绝跟随、记 failed；移除后重试成功。"""
    data_dir = isolated_data["data_dir"]
    job = _create_batch(client)
    out = data_dir / "jobs" / f"{job['id']}.ndjson"
    outside = data_dir / "outside-secret.ndjson"
    outside.write_text("SECRET\n")
    pv = _preview(client)
    # 预览中已标注 symlink
    note = next(f.get("note") for i in pv["items"] for f in i["files"]
                if f["category"] == "result")
    # 先构造普通预览（未替换前 note 为 None）
    assert note is None
    out.unlink()
    out.symlink_to(outside)
    # 替换改变指纹 -> 先重新预览（预览不跟随链接，标注 symlink）
    pv2 = _preview(client)
    entry = next(f for i in pv2["items"] for f in i["files"]
                 if f["category"] == "result")
    assert entry["note"] == "symlink"
    resp = _execute_preview(client, pv2, key="sym-1")
    plan = _wait_plan(client, resp["plan"]["plan_id"])
    assert plan["status"] == "partial"
    item = plan["items"][0]
    assert item["status"] == "failed"
    assert any(o["outcome"] == "symlink_refused" for o in item["outcomes"])
    # 外部文件安然无恙，数据库记录仍在
    assert outside.read_text() == "SECRET\n"
    assert client.get(f"/api/v1/jobs/{job['id']}").status_code == 200
    # 移除符号链接后重试：文件缺失按已删处理，计划成功
    out.unlink()
    rt = client.post(f"/api/v1/retention/cleanup/plans/{plan['plan_id']}/retry")
    assert rt.status_code == 202
    plan2 = _wait_plan(client, plan["plan_id"])
    assert plan2["status"] == "succeeded"
    assert client.get(f"/api/v1/jobs/{job['id']}").status_code == 404
    assert outside.exists()


def test_retry_endpoint_on_succeeded_409(client):
    _create_batch(client)
    pv = _preview(client)
    resp = _execute_preview(client, pv, key="ok-1")
    plan = _wait_plan(client, resp["plan"]["plan_id"])
    r = client.post(f"/api/v1/retention/cleanup/plans/{plan['plan_id']}/retry")
    assert r.status_code == 409


# ---------- 重启恢复 ----------


def test_interrupted_plan_resumes_after_recovery(client, isolated_data, monkeypatch):
    """模拟计划持久化后、worker 完成前进程重启：启动恢复扫描继续执行。"""
    _create_batch(client, key="r1")
    _create_batch(client, key="r2")
    pv = _preview(client)
    assert pv["job_count"] == 2

    db = isolated_data and _db(isolated_data)
    # 直接持久化计划但不启动 worker（模拟“先落计划后崩溃”）
    from redactor import retention as ret
    plan_id, replayed = ret.persist_plan(
        db, preview=ret.build_preview(db, now=datetime.fromisoformat(FUTURE)),
        idempotency_key="crashed-1")
    assert not replayed
    plan = client.get(f"/api/v1/retention/cleanup/plans/{plan_id}").json()
    assert plan["status"] == "pending"

    # 重置恢复标志并触发 lifespan 恢复（TestClient 重入即执行 startup）
    ret.reset_recovery()
    with TestClient(isolated_data["app"]) as c2:
        pass
    plan = client.get(f"/api/v1/retention/cleanup/plans/{plan_id}").json()
    assert plan["status"] == "succeeded", plan["status"]
    assert plan["jobs_done"] == 2


def _db(isolated_data) -> Database:
    return Database(isolated_data["settings"].db_path)


# ---------- 审计 ----------


def test_audit_query_and_filters(client):
    job = _create_batch(client)
    client.put("/api/v1/retention/locks", json={
        "job_kind": "batch", "job_id": job["id"], "reason": "a", "expires_at": FAR})
    client.delete(f"/api/v1/retention/locks/batch/{job['id']}")
    pv = _preview(client)
    resp = _execute_preview(client, pv, key="aud-1")
    _wait_plan(client, resp["plan"]["plan_id"])

    page = client.get("/api/v1/retention/audit?limit=100").json()
    actions = {e["action"] for e in page["items"]}
    assert "lock.created" in actions
    assert "lock.released" in actions
    assert "cleanup.plan.created" in actions
    assert "cleanup.plan.finished" in actions
    # 按动作过滤
    locks = client.get("/api/v1/retention/audit?action=lock.created").json()
    assert locks["total"] >= 1 and all(e["action"] == "lock.created"
                                       for e in locks["items"])
    # 审计内容不含敏感值
    blob = json.dumps(page, ensure_ascii=False)
    assert "zhangsan@example.com" not in blob
