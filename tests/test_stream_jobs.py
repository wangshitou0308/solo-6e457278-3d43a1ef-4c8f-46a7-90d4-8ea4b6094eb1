"""大批量 NDJSON 流式作业测试：上传、进度、幂等冲突、取消、检查点恢复、分页、下载。"""
from __future__ import annotations

import json
import os
import stat
import threading

import pytest
from fastapi.testclient import TestClient

from redactor import stream_jobs
from redactor.samples import SAMPLE_STRATEGY, sample_ndjson


@pytest.fixture()
def client(isolated_data):
    stream_jobs.reset_recovery()
    stream_jobs.registry.reset()
    stream_jobs.on_record_hook = None
    stream_jobs.on_publish_hook = None
    yield TestClient(isolated_data["app"])
    stream_jobs.on_record_hook = None
    stream_jobs.on_publish_hook = None
    stream_jobs.registry.reset()
    stream_jobs.reset_recovery()


def _upload(client, content, key=None, filename="logs.ndjson", strategy=None):
    files = {"file": (filename, content, "application/x-ndjson")}
    data = {"strategy": json.dumps(strategy or SAMPLE_STRATEGY)}
    headers = {"Idempotency-Key": key} if key else {}
    return client.post("/api/v1/stream-jobs", files=files, data=data, headers=headers)


def _wait(client, job_id, timeout=10.0):
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/v1/stream-jobs/{job_id}").json()
        if job["status"] in ("succeeded", "failed", "cancelled"):
            return job
        time.sleep(0.01)
    raise AssertionError("作业超时未终结")


# ---------- 基本流程 ----------


def test_upload_creates_running_then_succeeds(client, isolated_data):
    r = _upload(client, sample_ndjson())
    assert r.status_code == 202
    job = r.json()["job"]
    assert job["status"] in ("queued", "running")
    assert job["bytes_total"] == len(sample_ndjson().encode())
    assert job["progress_pct"] == 0.0

    final = _wait(client, job["id"])
    assert final["status"] == "succeeded"
    assert final["progress_pct"] == 100.0
    assert final["records_processed"] == 3
    assert final["audit_count"] > 0
    assert final["risk_count"] >= 1
    assert final["download_url"].endswith("/download")

    # 原始文件已删，结果文件 0600 发布
    raw = isolated_data["data_dir"] / "streams/raw" / f"{job['id']}.ndjson"
    out = isolated_data["data_dir"] / "streams/out" / f"{job['id']}.ndjson"
    assert not raw.exists()
    assert out.exists()
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_download_matches_small_batch_redaction(client):
    r = _upload(client, sample_ndjson())
    job = _wait(client, r.json()["job"]["id"])
    dl = client.get(f"/api/v1/stream-jobs/{job['id']}/download")
    assert dl.status_code == 200
    assert "application/x-ndjson" in dl.headers["content-type"]
    assert "attachment" in dl.headers["content-disposition"]
    lines = [json.loads(l) for l in dl.text.splitlines() if l.strip()]
    assert len(lines) == 3
    assert "zhangsan@example.com" not in dl.text
    assert "13800001234" not in dl.text
    # 跨记录确定性：同一手机号同令牌
    t1 = lines[0]["user"]["phone"]
    t2 = lines[2]["user"]["phone"]
    assert t1 == t2 and t1.startswith("T-")


def test_raw_file_is_0600_while_processing(client, isolated_data, monkeypatch):
    seen = {}
    gate = threading.Event()

    def hook(job_id, line_no):
        raw = isolated_data["data_dir"] / "streams/raw" / f"{job_id}.ndjson"
        if raw.exists():
            seen["mode"] = stat.S_IMODE(raw.stat().st_mode)
        gate.set()

    monkeypatch.setattr(stream_jobs, "on_record_hook", hook)
    r = _upload(client, sample_ndjson())
    job_id = r.json()["job"]["id"]
    assert gate.wait(timeout=5)
    assert seen.get("mode") == 0o600
    _wait(client, job_id)


def test_empty_upload_422_and_no_job(client, isolated_data):
    r = _upload(client, b"")
    assert r.status_code == 422
    assert client.get("/api/v1/stream-jobs").json()["total"] == 0
    # 临时文件已清理
    assert not list((isolated_data["data_dir"] / "streams/raw").glob("*"))


def test_blank_lines_only_job_failed_and_cleaned(client, isolated_data):
    r = _upload(client, b"\n  \n\t\n")
    job = _wait(client, r.json()["job"]["id"])
    assert job["status"] == "failed"
    assert "空" in job["error_message"]
    assert not list((isolated_data["data_dir"] / "streams/raw").glob("*"))
    assert not list((isolated_data["data_dir"] / "streams/partial").glob("*"))


def test_invalid_strategy_form_422(client):
    files = {"file": ("a.ndjson", sample_ndjson(), "application/x-ndjson")}
    bad_strategy = {"name": "bad", "rules": [
        {"id": "BAD ID", "name": "x", "match": {}, "action": "delete"}]}
    data = {"strategy": json.dumps(bad_strategy)}
    r = client.post("/api/v1/stream-jobs", files=files, data=data)
    assert r.status_code == 422


# ---------- 幂等与冲突 ----------


def test_idempotent_key_replays_same_content(client):
    r1 = _upload(client, sample_ndjson(), key="batch-001")
    j1 = r1.json()["job"]["id"]
    _wait(client, j1)
    r2 = _upload(client, sample_ndjson(), key="batch-001")
    assert r2.status_code == 200
    assert r2.json()["replayed"] is True
    assert r2.json()["job"]["id"] == j1
    assert client.get("/api/v1/stream-jobs").json()["total"] == 1


def test_same_key_different_content_is_409(client, isolated_data):
    r1 = _upload(client, sample_ndjson(), key="batch-002")
    j1 = r1.json()["job"]["id"]
    _wait(client, j1)
    other = sample_ndjson() + json.dumps({"extra": 1}) + "\n"
    r2 = _upload(client, other, key="batch-002")
    assert r2.status_code == 409
    body = r2.json()["detail"]
    assert body["existing_job_id"] == j1
    # 冲突上传不产生作业，也不残留临时文件
    assert client.get("/api/v1/stream-jobs").json()["total"] == 1
    raws = list((isolated_data["data_dir"] / "streams/raw").glob("*.ndjson"))
    assert raws == []


def test_conflict_while_first_still_running(client):
    # 不同内容、同键，即使首个还在跑也必须冲突
    gate = threading.Event()
    release = threading.Event()

    def hook(job_id, line_no):
        gate.set()
        release.wait(timeout=10)

    stream_jobs.on_record_hook = hook
    r1 = _upload(client, sample_ndjson(), key="batch-003")
    j1 = r1.json()["job"]["id"]
    assert gate.wait(timeout=5)
    stream_jobs.on_record_hook = None
    try:
        r2 = _upload(client, sample_ndjson() + '{"z":1}\n', key="batch-003")
        assert r2.status_code == 409
        assert r2.json()["detail"]["existing_job_id"] == j1
    finally:
        release.set()
    _wait(client, j1)


# ---------- 取消 ----------


def test_cancel_stops_job_and_cleans_files(client, isolated_data, monkeypatch):
    gate = threading.Event()
    release = threading.Event()

    def hook(job_id, line_no):
        if line_no == 1:
            gate.set()
            release.wait(timeout=10)

    monkeypatch.setattr(stream_jobs, "on_record_hook", hook)
    content = "".join(
        json.dumps({"i": i, "email": f"user{i}@example.com", "phone": "13800001234"}) + "\n"
        for i in range(200)
    )
    r = _upload(client, content)
    job_id = r.json()["job"]["id"]
    assert gate.wait(timeout=5)

    cr = client.post(f"/api/v1/stream-jobs/{job_id}/cancel")
    assert cr.status_code == 200 and cr.json()["cancelling"] is True
    release.set()

    final = _wait(client, job_id)
    assert final["status"] == "cancelled"
    assert final["records_processed"] == 0  # 停在第一行之前
    assert not (isolated_data["data_dir"] / "streams/raw" / f"{job_id}.ndjson").exists()
    assert not (isolated_data["data_dir"] / "streams/partial" / f"{job_id}.ndjson").exists()
    dl = client.get(f"/api/v1/stream-jobs/{job_id}/download")
    assert dl.status_code == 409


def test_cancel_after_checkpoint_keeps_progress_then_cleans(client, monkeypatch):
    monkeypatch.setenv("REDACTOR_CHECKPOINT_RECORDS", "10")
    # checkpoint_records() 在 worker 线程内被调用时读取环境变量
    seen = threading.Event()

    def hook(job_id, line_no):
        if line_no == 51:
            seen.set()
            client.post(f"/api/v1/stream-jobs/{job_id}/cancel")

    stream_jobs.on_record_hook = hook
    content = "".join(
        json.dumps({"i": i, "email": f"user{i}@example.com"}) + "\n"
        for i in range(200)
    )
    r = _upload(client, content)
    job_id = r.json()["job"]["id"]
    assert seen.wait(timeout=10)
    final = _wait(client, job_id)
    assert final["status"] == "cancelled"
    # 取消生效于 50 条记录的检查点之后
    assert final["records_processed"] == 50
    assert final["audit_count"] > 0


def test_cancel_terminal_job_is_409(client):
    r = _upload(client, sample_ndjson())
    job = _wait(client, r.json()["job"]["id"])
    cr = client.post(f"/api/v1/stream-jobs/{job['id']}/cancel")
    assert cr.status_code == 409


# ---------- 格式错误 ----------


def test_malformed_line_records_line_no_and_terminates(client):
    bad = '{"ok": 1}\n{"also": 2}\n{not json}\n{"never": 3}\n'
    r = _upload(client, bad)
    job = _wait(client, r.json()["job"]["id"])
    assert job["status"] == "failed"
    assert job["error_line"] == 3
    assert "第 3 行" in job["error_message"]
    # 未完成输出不可下载
    assert client.get(f"/api/v1/stream-jobs/{job['id']}/download").status_code == 409


def test_blank_and_bad_line_numbering(client):
    # 空行占物理行号但不占记录序号；错误行号按物理行报告
    bad = '{"a": 1}\n\n{"b": 2}\n   \n{x}\n'
    r = _upload(client, bad)
    job = _wait(client, r.json()["job"]["id"])
    assert job["status"] == "failed"
    assert job["error_line"] == 5
    assert job["records_processed"] == 2
    risks = client.get(f"/api/v1/stream-jobs/{job['id']}/risks").json()
    assert risks["total"] == 0


# ---------- 进度与分页 ----------


def test_progress_and_pagination(client):
    content = "".join(
        json.dumps({"i": i, "email": f"user{i}@example.com"}) + "\n"
        for i in range(30)
    )
    r = _upload(client, content)
    job = _wait(client, r.json()["job"]["id"])
    jid = job["id"]

    audit = client.get(f"/api/v1/stream-jobs/{jid}/audit",
                       params={"limit": 10, "offset": 0}).json()
    assert audit["total"] == job["audit_count"]
    assert len(audit["items"]) == 10
    # 行号按物理行（=记录行，这里没有空行）
    assert audit["items"][0]["line_no"] == 1
    page2 = client.get(f"/api/v1/stream-jobs/{jid}/audit",
                       params={"limit": 10, "offset": 10}).json()
    assert len(page2["items"]) == 10
    ids1 = [id(a) for a in audit["items"]]
    ids2 = [id(a) for a in page2["items"]]
    assert not set(ids1) & set(ids2)

    risks = client.get(f"/api/v1/stream-jobs/{jid}/risks",
                       params={"limit": 5, "offset": 0}).json()
    assert risks["total"] == job["risk_count"]

    listing = client.get("/api/v1/stream-jobs",
                         params={"status": "succeeded", "limit": 1}).json()
    assert listing["total"] == 1
    assert listing["items"][0]["id"] == jid


def test_unknown_job_404(client):
    assert client.get("/api/v1/stream-jobs/deadbeef").status_code == 404
    assert client.get("/api/v1/stream-jobs/deadbeef/audit").status_code == 404
    assert client.post("/api/v1/stream-jobs/deadbeef/cancel").status_code == 404


# ---------- 大文件豁免 10 MiB 小批量限制 ----------


def test_stream_upload_exempt_from_body_size_limit(client, monkeypatch):
    monkeypatch.setenv("REDACTOR_CHECKPOINT_RECORDS", "5000")
    big_record = {"i": 0, "note": "x" * 200}
    # 约 11 MiB（超过小批量接口的 10 MiB 上限）
    line = (json.dumps(big_record) + "\n").encode()
    n = (11 * 1024 * 1024) // len(line) + 1
    content = line * n
    assert len(content) > 10 * 1024 * 1024
    r = _upload(client, content)
    assert r.status_code == 202
    job = _wait(client, r.json()["job"]["id"], timeout=60)
    assert job["status"] == "succeeded"
    assert job["records_processed"] == n
    assert job["bytes_processed"] == len(content)
    dl = client.get(f"/api/v1/stream-jobs/{job['id']}/download")
    assert dl.status_code == 200
    assert len([l for l in dl.iter_lines() if l.strip()]) == n


# ---------- 服务重启：检查点恢复 / 崩溃后续跑 / 持久化取消 ----------


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_resume_from_checkpoint_after_hard_crash(client, isolated_data, monkeypatch):
    """worker 在检查点后、作业完成前“崩溃”，重启后从检查点继续。"""
    monkeypatch.setenv("REDACTOR_CHECKPOINT_RECORDS", "10")
    content = "".join(
        json.dumps({"i": i, "email": f"user{i}@example.com", "phone": "13800001234"}) + "\n"
        for i in range(45)
    )

    import redactor.stream_jobs as sj

    crash_jobs = set()

    class _Crash(BaseException):
        pass

    def hook(job_id, line_no):
        # 在第 31 条记录处理前崩溃：10/20/30 已检查点
        if line_no == 31 and job_id not in crash_jobs:
            crash_jobs.add(job_id)
            raise _Crash("simulated hard crash")

    monkeypatch.setattr(sj, "on_record_hook", hook)
    r = _upload(client, content)
    job_id = r.json()["job"]["id"]
    thread = sj.registry._threads[job_id]
    thread.join(timeout=10)
    assert not thread.is_alive()

    # 崩溃后状态仍为 running，进度停在 30 条；raw 与 partial 保留
    crashed = client.get(f"/api/v1/stream-jobs/{job_id}").json()
    assert crashed["status"] == "running"
    assert crashed["records_processed"] == 30
    assert (isolated_data["data_dir"] / "streams/raw" / f"{job_id}.ndjson").exists()
    partial = isolated_data["data_dir"] / "streams/partial" / f"{job_id}.ndjson"
    assert partial.exists()
    partial_bytes_at_crash = partial.stat().st_size

    # “重启”：注册表清空、恢复标记重置；通过状态查询惰性触发恢复
    sj.registry.reset()
    sj.reset_recovery()
    monkeypatch.setattr(sj, "on_record_hook", None)
    recovered = _wait(client, job_id)
    assert recovered["status"] == "succeeded"
    assert recovered["records_processed"] == 45
    assert recovered["audit_count"] > 0

    dl = client.get(f"/api/v1/stream-jobs/{job_id}/download")
    lines = [json.loads(l) for l in dl.text.splitlines() if l.strip()]
    assert len(lines) == 45
    # 检查点之前的记录不重复（恢复时严格截断了未提交输出）
    assert [row["i"] for row in lines] == list(range(45))
    # 确定性：恢复前后同一手机号仍同令牌
    tokens = {row["phone"] for row in lines}
    assert len(tokens) == 1 and next(iter(tokens)).startswith("T-")


def test_cancel_persists_across_restart(client, isolated_data, monkeypatch):
    monkeypatch.setenv("REDACTOR_CHECKPOINT_RECORDS", "10")
    gate = threading.Event()
    release = threading.Event()

    def hook(job_id, line_no):
        if line_no == 1:
            gate.set()
            release.wait(timeout=10)

    stream_jobs.on_record_hook = hook
    content = "".join(
        json.dumps({"i": i, "email": f"user{i}@example.com"}) + "\n"
        for i in range(40)
    )
    r = _upload(client, content)
    job_id = r.json()["job"]["id"]
    assert gate.wait(timeout=5)

    # 重启前请求取消（持久化），随后模拟进程退出：线程被释放但未跑完
    client.post(f"/api/v1/stream-jobs/{job_id}/cancel")
    release.set()
    stream_jobs.registry._threads[job_id].join(timeout=10)

    stream_jobs.registry.reset()
    stream_jobs.reset_recovery()
    stream_jobs.on_record_hook = None
    # 触发恢复扫描
    client.get("/api/v1/stream-jobs")
    final = _wait(client, job_id)
    assert final["status"] == "cancelled"
    assert not (isolated_data["data_dir"] / "streams/raw" / f"{job_id}.ndjson").exists()


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_resume_with_missing_raw_marks_failed(client, isolated_data, monkeypatch):
    monkeypatch.setenv("REDACTOR_CHECKPOINT_RECORDS", "10")
    crashed = threading.Event()

    class _Crash(BaseException):
        pass

    def hook(job_id, line_no):
        if line_no == 15:
            crashed.set()
            raise _Crash("simulated hard crash")

    stream_jobs.on_record_hook = hook
    r = _upload(client, sample_ndjson() * 20)
    job_id = r.json()["job"]["id"]
    assert crashed.wait(timeout=10)
    stream_jobs.registry._threads[job_id].join(timeout=10)

    # 硬崩溃后原始文件“丢失”（手工删除）
    raw = isolated_data["data_dir"] / "streams/raw" / f"{job_id}.ndjson"
    assert raw.exists()  # 崩溃路径不应清理文件
    raw.unlink()

    stream_jobs.registry.reset()
    stream_jobs.reset_recovery()
    stream_jobs.on_record_hook = None
    client.get("/api/v1/stream-jobs")
    final = _wait(client, job_id)
    assert final["status"] == "failed"
    assert "原始上传文件" in final["error_message"]


# ---------- 回归：发布/状态之间的崩溃窗口 ----------


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_crash_between_publish_and_mark_reconciles_on_restart(client, isolated_data):
    """成品已 rename 发布、succeeded 事务未提交时硬崩溃：重启必须补登状态且可下载。"""
    crashed_jobs = set()

    class _Crash(BaseException):
        pass

    def publish_hook(job_id):
        if job_id not in crashed_jobs:
            crashed_jobs.add(job_id)
            raise _Crash("crash after publish, before mark succeeded")

    stream_jobs.on_publish_hook = publish_hook
    r = _upload(client, sample_ndjson(), key="publish-window")
    job_id = r.json()["job"]["id"]
    stream_jobs.registry._threads[job_id].join(timeout=10)

    # 崩溃后的现场：状态仍 running，但成品已发布、partial 已被 rename、raw 还在
    stuck = client.get(f"/api/v1/stream-jobs/{job_id}").json()
    assert stuck["status"] == "running"
    out = isolated_data["data_dir"] / "streams/out" / f"{job_id}.ndjson"
    partial = isolated_data["data_dir"] / "streams/partial" / f"{job_id}.ndjson"
    raw = isolated_data["data_dir"] / "streams/raw" / f"{job_id}.ndjson"
    assert out.exists() and not partial.exists() and raw.exists()
    published_bytes = out.read_bytes()

    # “重启”：触发恢复扫描。对账应补登 succeeded，不得重跑 worker
    stream_jobs.registry.reset()
    stream_jobs.reset_recovery()
    stream_jobs.on_publish_hook = None
    client.get("/api/v1/stream-jobs")
    final = _wait(client, job_id)
    assert final["status"] == "succeeded"
    assert final["records_processed"] == 3

    # 成品字节级未被改动（没有被新建的 NUL partial 覆盖/重写）
    assert out.read_bytes() == published_bytes
    assert not partial.exists()  # 恢复对账路径绝不新建 partial
    assert not raw.exists()      # 原始文件随对账清理

    dl = client.get(f"/api/v1/stream-jobs/{job_id}/download")
    assert dl.status_code == 200
    lines = [json.loads(l) for l in dl.text.splitlines() if l.strip()]
    assert len(lines) == 3
    assert "zhangsan@example.com" not in dl.text


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_published_file_revalidated_against_checkpoint_records(client, isolated_data):
    """成品存在但记录数与检查点不一致（不可信）时不能误判成功，也不能提供损坏下载。"""
    from redactor.app import get_db

    crashed_jobs = set()

    class _Crash(BaseException):
        pass

    def publish_hook(job_id):
        if job_id not in crashed_jobs:
            crashed_jobs.add(job_id)
            out = isolated_data["data_dir"] / "streams/out" / f"{job_id}.ndjson"
            out.write_bytes(b'{"tampered": true}\n')  # 1 条，检查点是 3 条
            raise _Crash("crash with bogus published file")

    stream_jobs.on_publish_hook = publish_hook
    r = _upload(client, sample_ndjson())
    job_id = r.json()["job"]["id"]
    stream_jobs.registry._threads[job_id].join(timeout=10)

    # 对账不认可伪造成品：删除它并返回 False，状态保持 running
    stream_jobs.registry.reset()
    stream_jobs.reset_recovery()
    stream_jobs.on_publish_hook = None
    assert stream_jobs.reconcile_published_job(get_db(), job_id) is False
    out = isolated_data["data_dir"] / "streams/out" / f"{job_id}.ndjson"
    assert not out.exists()

    # 触发恢复：partial 已在发布时被 rename 走、检查点 output_bytes>0，
    # 安全守卫把作业判失败，而不是 NUL 填充或把损坏文件标成功
    client.get("/api/v1/stream-jobs")
    final = _wait(client, job_id)
    assert final["status"] == "failed"
    assert client.get(f"/api/v1/stream-jobs/{job_id}/download").status_code == 409
    assert not out.exists()


def test_missing_or_short_partial_checkpoint_fails_safely(isolated_data):
    """partial 缺失/短于检查点字节时严禁 NUL 填充续跑，必须判失败并清理。"""
    import redactor.stream_jobs as sj
    from redactor.app import get_db, get_master_key
    from redactor.database import Database

    db: Database = get_db()
    content = sample_ndjson().encode()
    (isolated_data["data_dir"] / "streams/raw").mkdir(parents=True, exist_ok=True)

    # 情形 A：partial 缺失
    job_id = "partialmissing0000000000000000000001"
    raw = sj.raw_path(job_id)
    raw.write_bytes(content)
    os.chmod(raw, 0o600)
    db.create_stream_job(
        job_id=job_id, idempotency_key=None,
        strategy_json=json.dumps(SAMPLE_STRATEGY), strategy_sha256="x",
        source_filename="a.ndjson", content_sha256="c1",
        bytes_total=len(content), key_fingerprint="sha256:test",
    )
    db.checkpoint_stream_job(
        job_id, bytes_processed=10, records_processed=1, audit_count=0,
        risk_count=0, fields_scanned=1, by_action={}, by_rule={},
        last_line_no=1, output_bytes=42, audit=[], risks=[],
    )
    sj.run_stream_job(job_id, get_db, get_master_key)
    job = db.get_stream_job(job_id)
    assert job.status == "failed"
    assert "未完成输出文件丢失" in (job.error_message or "")
    assert not raw.exists()
    assert not sj.partial_output_path(job_id).exists()

    # 情形 B：partial 短于检查点字节（旧的实现会 NUL 填充覆盖）
    job_id2 = "partialshort0000000000000000000000002"
    raw2 = sj.raw_path(job_id2)
    raw2.write_bytes(content)
    os.chmod(raw2, 0o600)
    db.create_stream_job(
        job_id=job_id2, idempotency_key=None,
        strategy_json=json.dumps(SAMPLE_STRATEGY), strategy_sha256="x",
        source_filename="a.ndjson", content_sha256="c2",
        bytes_total=len(content), key_fingerprint="sha256:test",
    )
    db.checkpoint_stream_job(
        job_id2, bytes_processed=10, records_processed=1, audit_count=0,
        risk_count=0, fields_scanned=1, by_action={}, by_rule={},
        last_line_no=1, output_bytes=100, audit=[], risks=[],
    )
    partial = sj.partial_output_path(job_id2)
    partial.parent.mkdir(parents=True, exist_ok=True)
    partial.write_bytes(b'{"a":1}\n')  # 远少于 100
    sj.run_stream_job(job_id2, get_db, get_master_key)
    job2 = db.get_stream_job(job_id2)
    assert job2.status == "failed"
    assert "损坏" in (job2.error_message or "")
    assert not partial.exists() and not raw2.exists()


# ---------- 回归：策略参与幂等一致性 ----------


def test_same_key_same_file_different_strategy_is_409(client):
    import copy

    r1 = _upload(client, sample_ndjson(), key="strategy-key")
    j1 = r1.json()["job"]["id"]
    _wait(client, j1)

    other = copy.deepcopy(SAMPLE_STRATEGY)
    other["rules"][1]["keep_prefix"] = 3  # 改变脱敏语义
    files = {"file": ("logs.ndjson", sample_ndjson(), "application/x-ndjson")}
    r2 = client.post(
        "/api/v1/stream-jobs",
        files=files,
        data={"strategy": json.dumps(other)},
        headers={"Idempotency-Key": "strategy-key"},
    )
    assert r2.status_code == 409
    assert "策略" in r2.json()["detail"]["message"]
    assert r2.json()["detail"]["existing_job_id"] == j1
    assert client.get("/api/v1/stream-jobs").json()["total"] == 1

    # 同策略、仅 JSON 排版/键序不同：规范化后摘要一致，应回放而非冲突
    r3 = client.post(
        "/api/v1/stream-jobs",
        files=files,
        data={"strategy": json.dumps(other, indent=4, sort_keys=True)},
        headers={"Idempotency-Key": "strategy-key-2"},
    )
    # 新键首次上传：202（不同排版在单次上传内不构成冲突）
    assert r3.status_code == 202
    j3 = _wait(client, r3.json()["job"]["id"])
    # 用同一策略的另一种排版 + 同一键重放：必须 200 回放
    r4 = client.post(
        "/api/v1/stream-jobs",
        files={"file": ("logs.ndjson", sample_ndjson(), "application/x-ndjson")},
        data={"strategy": json.dumps(other, separators=(",", ":"))},
        headers={"Idempotency-Key": "strategy-key-2"},
    )
    assert r4.status_code == 200
    assert r4.json()["job"]["id"] == j3["id"]


def test_openapi_documents_stream_routes(client):
    spec = client.get("/openapi.json").json()
    paths = spec["paths"]
    for p in [
        "/api/v1/stream-jobs",
        "/api/v1/stream-jobs/{job_id}",
        "/api/v1/stream-jobs/{job_id}/cancel",
        "/api/v1/stream-jobs/{job_id}/audit",
        "/api/v1/stream-jobs/{job_id}/risks",
        "/api/v1/stream-jobs/{job_id}/download",
    ]:
        assert p in paths, p
    # 409 冲突与未完成不可下载都写进了契约
    create_responses = paths["/api/v1/stream-jobs"]["post"]["responses"]
    assert "409" in create_responses
    dl_responses = paths["/api/v1/stream-jobs/{job_id}/download"]["get"]["responses"]
    assert "409" in dl_responses
