"""断点续传上传会话测试：声明式创建、Content-Range 乱序分片、幂等回放、
重叠/越界/摘要冲突、进度与缺失区间、终止与过期清理、完成转入流式/诊断包作业、
重启恢复与幂等键语义。"""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import zipfile

import pytest
from fastapi.testclient import TestClient

from redactor import stream_jobs, bundle_jobs, upload_sessions
from redactor.samples import SAMPLE_STRATEGY, sample_ndjson


@pytest.fixture()
def client(isolated_data):
    stream_jobs.reset_recovery()
    stream_jobs.registry.reset()
    bundle_jobs.reset_bundle_recovery()
    bundle_jobs.bundle_registry.reset()
    upload_sessions.reset_upload_recovery()
    upload_sessions.reset_session_locks()
    yield TestClient(isolated_data["app"])
    stream_jobs.registry.reset()
    stream_jobs.reset_recovery()
    bundle_jobs.bundle_registry.reset()
    bundle_jobs.reset_bundle_recovery()
    upload_sessions.reset_session_locks()
    upload_sessions.reset_upload_recovery()


# ---------- 构造辅助 ----------


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _create(client, content: bytes, *, kind="ndjson", key=None, strategy=None,
            token_context=None, filename=None, expires_in=None):
    body = {
        "kind": kind,
        "bytes_total": len(content),
        "content_sha256": _sha(content),
        "strategy": strategy or SAMPLE_STRATEGY,
    }
    if token_context is not None:
        body["token_context"] = token_context
    if filename is not None:
        body["source_filename"] = filename
    if expires_in is not None:
        body["expires_in_seconds"] = expires_in
    headers = {"Idempotency-Key": key} if key else {}
    return client.post("/api/v1/upload-sessions", json=body, headers=headers)


def _put(client, sid, data: bytes, start: int, total: int | None = None,
         chunk_sha: str | None = None):
    total = len(data) + start if total is None else total
    headers = {"Content-Range": f"bytes {start}-{start + len(data) - 1}/{total}"}
    if chunk_sha is not None:
        headers["X-Chunk-SHA256"] = chunk_sha
    return client.put(f"/api/v1/upload-sessions/{sid}/chunks",
                      content=data, headers=headers)


def _upload_all(client, sid, content: bytes, parts: int = 3):
    """把内容切成 parts 片、乱序提交。"""
    n = len(content)
    bounds = [round(i * n / parts) for i in range(parts + 1)]
    ranges = [(bounds[i], bounds[i + 1]) for i in range(parts)]
    for start, end in reversed(ranges):
        if end > start:
            r = _put(client, sid, content[start:end], start, total=n)
            assert r.status_code == 200, r.text
    return ranges


def _wait_job(client, kind, job_id, timeout=10.0):
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/v1/{kind}/{job_id}").json()
        if job["status"] in ("succeeded", "failed", "cancelled"):
            return job
        time.sleep(0.01)
    raise AssertionError("作业超时未终结")


def make_zip(files: dict[str, bytes | str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            if isinstance(data, str):
                data = data.encode("utf-8")
            zf.writestr(name, data)
    return buf.getvalue()


# ---------- 创建会话 ----------


def test_create_session_declares_metadata(client):
    content = sample_ndjson().encode()
    r = _create(client, content, token_context="incident-7", filename="a.ndjson")
    assert r.status_code == 201
    s = r.json()["session"]
    assert r.json()["replayed"] is False
    assert s["status"] == "uploading"
    assert s["kind"] == "ndjson"
    assert s["bytes_total"] == len(content)
    assert s["bytes_received"] == 0
    assert s["content_sha256"] == _sha(content)
    assert s["source_filename"] == "a.ndjson"
    assert s["domain_fingerprint"].startswith("dom:")
    assert s["progress_pct"] == 0.0
    assert s["received_ranges"] == []
    assert s["missing_ranges"] == [
        {"start": 0, "end": len(content), "bytes": len(content)}
    ]
    assert s["expires_at"]


def test_create_session_validation(client):
    content = b'{"a": 1}\n'
    # 摘要格式非法
    r = client.post("/api/v1/upload-sessions", json={
        "kind": "ndjson", "bytes_total": 10, "content_sha256": "not-a-sha",
        "strategy": SAMPLE_STRATEGY})
    assert r.status_code == 422
    # 总字节数非法
    r = client.post("/api/v1/upload-sessions", json={
        "kind": "ndjson", "bytes_total": 0, "content_sha256": _sha(content),
        "strategy": SAMPLE_STRATEGY})
    assert r.status_code == 422
    # 策略非法（未知识别器）
    r = client.post("/api/v1/upload-sessions", json={
        "kind": "ndjson", "bytes_total": 10, "content_sha256": _sha(content),
        "strategy": {"name": "x", "rules": [
            {"id": "r1", "name": "n", "match": {"detectors": ["nope"]},
             "action": "mask"}]}})
    assert r.status_code == 422
    # token_context 超长
    r = client.post("/api/v1/upload-sessions", json={
        "kind": "ndjson", "bytes_total": 10, "content_sha256": _sha(content),
        "strategy": SAMPLE_STRATEGY, "token_context": "x" * 129})
    assert r.status_code == 422
    # kind 非法
    r = client.post("/api/v1/upload-sessions", json={
        "kind": "txt", "bytes_total": 10, "content_sha256": _sha(content),
        "strategy": SAMPLE_STRATEGY})
    assert r.status_code == 422
    # Idempotency-Key 超长
    r = _create(client, content, key="k" * 129)
    assert r.status_code == 400


def test_create_zip_session_over_cap_rejected(client, monkeypatch):
    monkeypatch.setenv("REDACTOR_BUNDLE_MAX_TOTAL_BYTES", "1024")
    r = client.post("/api/v1/upload-sessions", json={
        "kind": "zip", "bytes_total": 2048, "content_sha256": _sha(b"x" * 2048),
        "strategy": SAMPLE_STRATEGY})
    assert r.status_code == 413


def test_session_idempotency_replay_and_conflict(client):
    content = sample_ndjson().encode()
    r1 = _create(client, content, key="sess-1")
    assert r1.status_code == 201
    # 同键同声明：回放既有会话（同一 id）
    r2 = _create(client, content, key="sess-1")
    assert r2.status_code == 200
    assert r2.json()["replayed"] is True
    assert r2.json()["session"]["id"] == r1.json()["session"]["id"]
    # 同键不同内容：409
    other = content + b"\n"
    r3 = _create(client, other, key="sess-1")
    assert r3.status_code == 409
    # 同键不同策略：409
    changed = dict(SAMPLE_STRATEGY, name="other-name")
    r4 = _create(client, content, key="sess-1", strategy=changed)
    assert r4.status_code == 409
    # 同键不同关联域：409
    r5 = _create(client, content, key="sess-1", token_context="other-domain")
    assert r5.status_code == 409


def test_create_conflicts_with_existing_job_key(client):
    """键已被既有流式作业占用且内容不同：创建会话即 409（快速失败）。"""
    content = sample_ndjson().encode()
    files = {"file": ("logs.ndjson", content, "application/x-ndjson")}
    data = {"strategy": json.dumps(SAMPLE_STRATEGY)}
    r = client.post("/api/v1/stream-jobs", files=files, data=data,
                    headers={"Idempotency-Key": "job-key-1"})
    assert r.status_code == 202
    # 同键不同内容 → 409
    r = _create(client, content + b"\n", key="job-key-1")
    assert r.status_code == 409
    # 同键同内容同策略 → 允许创建（完成时回放到既有作业）
    r = _create(client, content, key="job-key-1")
    assert r.status_code == 201


# ---------- 分片上传 ----------


def test_out_of_order_chunks_and_progress(client, isolated_data):
    content = sample_ndjson().encode()
    sid = _create(client, content).json()["session"]["id"]
    n = len(content)
    b1, b2 = n // 3, 2 * n // 3

    r = _put(client, sid, content[b2:], b2, total=n)
    assert r.status_code == 200
    assert r.json()["replayed"] is False
    prog = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert prog["received_ranges"] == [
        {"start": b2, "end": n, "bytes": n - b2}
    ]
    assert prog["missing_ranges"] == [
        {"start": 0, "end": b2, "bytes": b2}
    ]
    assert 0 < prog["progress_pct"] < 100

    _put(client, sid, content[:b1], 0, total=n)
    prog = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert prog["missing_ranges"] == [
        {"start": b1, "end": b2, "bytes": b2 - b1}
    ]

    _put(client, sid, content[b1:b2], b1, total=n)
    prog = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert prog["received_ranges"] == [{"start": 0, "end": n, "bytes": n}]
    assert prog["missing_ranges"] == []
    assert prog["progress_pct"] == 100.0

    # 暂存文件权限 0600
    staged = isolated_data["data_dir"] / "uploads" / f"{sid}.part"
    assert staged.exists()
    assert stat.S_IMODE(staged.stat().st_mode) == 0o600


def test_chunk_replay_same_content_is_idempotent(client):
    content = sample_ndjson().encode()
    sid = _create(client, content).json()["session"]["id"]
    n = len(content)
    half = n // 2
    r1 = _put(client, sid, content[:half], 0, total=n)
    assert r1.status_code == 200 and r1.json()["replayed"] is False
    # 相同区间相同内容：幂等回放，不产生第二片
    r2 = _put(client, sid, content[:half], 0, total=n)
    assert r2.status_code == 200 and r2.json()["replayed"] is True
    prog = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert prog["bytes_received"] == half


def test_chunk_conflict_same_range_different_content(client):
    content = sample_ndjson().encode()
    sid = _create(client, content).json()["session"]["id"]
    n = len(content)
    half = n // 2
    _put(client, sid, content[:half], 0, total=n)
    # 相同区间、内容不同：409，已有分片保留
    r = _put(client, sid, b"X" * half, 0, total=n)
    assert r.status_code == 409
    prog = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert prog["received_ranges"] == [{"start": 0, "end": half, "bytes": half}]


def test_chunk_partial_overlap_rejected(client):
    content = sample_ndjson().encode()
    sid = _create(client, content).json()["session"]["id"]
    n = len(content)
    half = n // 2
    _put(client, sid, content[:half], 0, total=n)
    # 部分重叠（跨已登记边界）：409
    r = _put(client, sid, content[half - 10:half + 10], half - 10, total=n)
    assert r.status_code == 409
    assert "conflicting_ranges" in r.json()["detail"]
    prog = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert prog["bytes_received"] == half
    # 相邻不重叠（end == start）允许
    r = _put(client, sid, content[half:], half, total=n)
    assert r.status_code == 200


def test_chunk_out_of_bounds_and_total_mismatch(client):
    content = b"0123456789"
    sid = _create(client, content).json()["session"]["id"]
    # 越界（end 超出声明总长）
    r = client.put(f"/api/v1/upload-sessions/{sid}/chunks", content=b"01234567890",
                   headers={"Content-Range": "bytes 0-10/10"})
    assert r.status_code == 409
    # 总长声明与会话不符
    r = client.put(f"/api/v1/upload-sessions/{sid}/chunks", content=b"01",
                   headers={"Content-Range": "bytes 0-1/999"})
    assert r.status_code == 409
    # 头部缺失/格式非法/空区间
    r = client.put(f"/api/v1/upload-sessions/{sid}/chunks", content=b"01")
    assert r.status_code == 400
    r = client.put(f"/api/v1/upload-sessions/{sid}/chunks", content=b"01",
                   headers={"Content-Range": "items 0-1/10"})
    assert r.status_code == 400
    r = client.put(f"/api/v1/upload-sessions/{sid}/chunks", content=b"",
                   headers={"Content-Range": "bytes 5-4/10"})
    assert r.status_code == 400
    # 请求体长度与声明区间不符
    r = client.put(f"/api/v1/upload-sessions/{sid}/chunks", content=b"0",
                   headers={"Content-Range": "bytes 0-1/10"})
    assert r.status_code == 400
    # 会话未受任何影响
    prog = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert prog["bytes_received"] == 0


def test_chunk_declared_digest_mismatch(client):
    content = b"0123456789"
    sid = _create(client, content).json()["session"]["id"]
    # 声明摘要与实际内容不符：422，分片不登记
    r = _put(client, sid, content[:5], 0, total=10, chunk_sha="0" * 64)
    assert r.status_code == 422
    prog = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert prog["bytes_received"] == 0
    # 摘要格式非法：400
    r = _put(client, sid, content[:5], 0, total=10, chunk_sha="xyz")
    assert r.status_code == 400
    # 摘要相符：正常登记
    r = _put(client, sid, content[:5], 0, total=10, chunk_sha=_sha(content[:5]))
    assert r.status_code == 200


def test_chunk_unknown_session_404(client):
    r = client.put("/api/v1/upload-sessions/nope/chunks", content=b"1",
                   headers={"Content-Range": "bytes 0-0/1"})
    assert r.status_code == 404
    assert client.get("/api/v1/upload-sessions/nope").status_code == 404
    assert client.post("/api/v1/upload-sessions/nope/abort").status_code == 404
    assert client.post("/api/v1/upload-sessions/nope/complete").status_code == 404


# ---------- 完成：NDJSON 转入流式作业 ----------


def test_complete_ndjson_hands_off_to_stream_job(client, isolated_data):
    content = sample_ndjson().encode()
    sid = _create(client, content, token_context="incident-ndjson",
                  key="ndjson-complete-1").json()["session"]["id"]
    _upload_all(client, sid, content, parts=4)

    r = client.post(f"/api/v1/upload-sessions/{sid}/complete")
    assert r.status_code == 201
    assert r.json()["replayed"] is False
    job = r.json()["job"]
    assert job["bytes_total"] == len(content)
    assert job["content_sha256"] == _sha(content)
    assert job["domain_fingerprint"].startswith("dom:")
    assert job["idempotency_key"] == "ndjson-complete-1"

    final = _wait_job(client, "stream-jobs", job["id"])
    assert final["status"] == "succeeded"
    assert final["records_processed"] == 3

    # 会话进入 completed，暂存文件已清理
    s = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert s["status"] == "completed"
    assert s["job_id"] == job["id"]
    assert s["job_url"].endswith(f"/stream-jobs/{job['id']}")
    assert s["progress_pct"] == 100.0
    staged = isolated_data["data_dir"] / "uploads" / f"{sid}.part"
    assert not staged.exists()

    # 结果与直接上传一致：脱敏生效
    dl = client.get(f"/api/v1/stream-jobs/{job['id']}/download")
    assert dl.status_code == 200
    assert "zhangsan@example.com" not in dl.text

    # 完成后禁止继续写入
    r = _put(client, sid, content[:4], 0, total=len(content))
    assert r.status_code == 409
    # 重复完成：幂等回放同一作业
    r = client.post(f"/api/v1/upload-sessions/{sid}/complete")
    assert r.status_code == 200
    assert r.json()["replayed"] is True
    assert r.json()["job"]["id"] == job["id"]


def test_complete_requires_full_coverage(client):
    content = sample_ndjson().encode()
    sid = _create(client, content).json()["session"]["id"]
    n = len(content)
    _put(client, sid, content[: n // 2], 0, total=n)
    r = client.post(f"/api/v1/upload-sessions/{sid}/complete")
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["missing_ranges"] == [
        {"start": n // 2, "end": n, "bytes": n - n // 2}
    ]
    # 会话保持 uploading，分片保留
    s = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert s["status"] == "uploading"
    assert s["bytes_received"] == n // 2


def test_complete_overall_digest_mismatch_keeps_chunks(client):
    content = sample_ndjson().encode()
    body = {
        "kind": "ndjson",
        "bytes_total": len(content),
        "content_sha256": _sha(b"different-content"),
        "strategy": SAMPLE_STRATEGY,
    }
    sid = client.post("/api/v1/upload-sessions", json=body).json()["session"]["id"]
    _put(client, sid, content, 0, total=len(content))
    r = client.post(f"/api/v1/upload-sessions/{sid}/complete")
    assert r.status_code == 409
    assert "SHA-256" in r.json()["detail"]["message"]
    # 分片保留、会话仍可操作（客户端可终止后重传）
    s = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert s["status"] == "uploading"
    assert s["bytes_received"] == len(content)


def test_complete_replays_to_existing_job_with_same_key(client):
    """同键作业已存在且声明一致：完成不新建作业，会话指向既有作业。"""
    content = sample_ndjson().encode()
    files = {"file": ("logs.ndjson", content, "application/x-ndjson")}
    data = {"strategy": json.dumps(SAMPLE_STRATEGY)}
    r = client.post("/api/v1/stream-jobs", files=files, data=data,
                    headers={"Idempotency-Key": "shared-key"})
    assert r.status_code == 202
    existing_job = r.json()["job"]
    _wait_job(client, "stream-jobs", existing_job["id"])

    sid = _create(client, content, key="shared-key").json()["session"]["id"]
    _upload_all(client, sid, content)
    r = client.post(f"/api/v1/upload-sessions/{sid}/complete")
    assert r.status_code == 200
    assert r.json()["replayed"] is True
    assert r.json()["job"]["id"] == existing_job["id"]
    s = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert s["status"] == "completed"
    assert s["job_id"] == existing_job["id"]


# ---------- 完成：ZIP 转入诊断包作业 ----------


def test_complete_zip_hands_off_to_bundle_job(client, isolated_data):
    zcontent = make_zip({
        "logs/app.ndjson": json.dumps(
            {"email": "zhangsan@example.com", "phone": "13800001234"}) + "\n",
        "notes.txt": "contact 13800001234 from 10.0.0.1\n",
        "skip.bin": b"\x00\x01\x02",
    })
    sid = _create(client, zcontent, kind="zip", filename="diag.zip",
                  token_context="incident-zip").json()["session"]["id"]
    _upload_all(client, sid, zcontent, parts=3)

    r = client.post(f"/api/v1/upload-sessions/{sid}/complete")
    assert r.status_code == 201
    job = r.json()["job"]
    assert job["source_filename"] == "diag.zip"
    assert job["files_total"] == 3
    assert job["domain_fingerprint"].startswith("dom:")

    final = _wait_job(client, "bundle-jobs", job["id"])
    assert final["status"] == "succeeded"
    assert final["files_processed"] == 3

    manifest = client.get(f"/api/v1/bundle-jobs/{job['id']}/manifest").json()
    statuses = {f["path"]: f["status"] for f in manifest["files"]}
    assert statuses["logs/app.ndjson"] == "redacted"
    assert statuses["notes.txt"] == "redacted"
    assert statuses["skip.bin"] == "skipped"

    s = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert s["status"] == "completed"
    assert s["job_url"].endswith(f"/bundle-jobs/{job['id']}")
    staged = isolated_data["data_dir"] / "uploads" / f"{sid}.part"
    assert not staged.exists()


def test_complete_zip_security_rejection_fails_session(client, isolated_data):
    bad = make_zip({"../escape.txt": "x", "dup.txt": "a", "dup2/../dup.txt": "b"})
    sid = _create(client, bad, kind="zip").json()["session"]["id"]
    _put(client, sid, bad, 0, total=len(bad))
    r = client.post(f"/api/v1/upload-sessions/{sid}/complete")
    assert r.status_code == 422
    assert r.json()["detail"]["reasons"]
    s = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert s["status"] == "failed"
    assert s["error_message"]
    # 暂存文件已清理，会话不可再写
    staged = isolated_data["data_dir"] / "uploads" / f"{sid}.part"
    assert not staged.exists()
    assert _put(client, sid, bad[:2], 0, total=len(bad)).status_code == 409


# ---------- 终止与过期 ----------


def test_abort_cleans_staging_and_blocks_writes(client, isolated_data):
    content = sample_ndjson().encode()
    sid = _create(client, content).json()["session"]["id"]
    _put(client, sid, content[:100], 0, total=len(content))
    staged = isolated_data["data_dir"] / "uploads" / f"{sid}.part"
    assert staged.exists()

    r = client.post(f"/api/v1/upload-sessions/{sid}/abort")
    assert r.status_code == 200
    assert r.json()["session"]["status"] == "aborted"
    assert not staged.exists()
    # 终止后拒绝写入与完成
    assert _put(client, sid, content[:4], 0, total=len(content)).status_code == 409
    assert client.post(f"/api/v1/upload-sessions/{sid}/complete").status_code == 409
    # 重复终止幂等
    r = client.post(f"/api/v1/upload-sessions/{sid}/abort")
    assert r.status_code == 200
    # 进度视图仍可读（终态）
    s = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert s["status"] == "aborted"


def test_abort_completed_session_conflict(client):
    content = sample_ndjson().encode()
    sid = _create(client, content).json()["session"]["id"]
    _upload_all(client, sid, content)
    r = client.post(f"/api/v1/upload-sessions/{sid}/complete")
    assert r.status_code == 201
    _wait_job(client, "stream-jobs", r.json()["job"]["id"])
    r = client.post(f"/api/v1/upload-sessions/{sid}/abort")
    assert r.status_code == 409


def test_expired_session_is_swept(client, isolated_data):
    content = sample_ndjson().encode()
    sid = _create(client, content, expires_in=60).json()["session"]["id"]
    _put(client, sid, content[:50], 0, total=len(content))
    staged = isolated_data["data_dir"] / "uploads" / f"{sid}.part"
    assert staged.exists()

    # 把过期时间拨到过去，模拟到期
    db = isolated_data["app"]
    from redactor import app as app_mod
    app_mod.get_db()._conn().execute(
        "UPDATE upload_sessions SET expires_at='2000-01-01T00:00:00+00:00' "
        "WHERE id=?", (sid,),
    ).connection.commit()

    # 惰性过期：任意访问触发清理
    s = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert s["status"] == "expired"
    assert not staged.exists()
    assert _put(client, sid, content[:4], 0, total=len(content)).status_code == 409
    assert client.post(f"/api/v1/upload-sessions/{sid}/complete").status_code == 409


# ---------- 重启恢复 ----------


def test_session_and_chunk_index_survive_restart(client, isolated_data):
    content = sample_ndjson().encode()
    sid = _create(client, content, token_context="restart-1").json()["session"]["id"]
    n = len(content)
    half = n // 2
    _put(client, sid, content[:half], 0, total=n)

    # 模拟服务重启：重置恢复标记后重新触发恢复扫描
    upload_sessions.reset_upload_recovery()
    upload_sessions.ensure_upload_dirs()
    upload_sessions.recover_upload_sessions(app_get_db(client))

    prog = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert prog["status"] == "uploading"
    assert prog["received_ranges"] == [{"start": 0, "end": half, "bytes": half}]
    assert prog["domain_fingerprint"].startswith("dom:")

    # 续传剩余分片并完成
    _put(client, sid, content[half:], half, total=n)
    r = client.post(f"/api/v1/upload-sessions/{sid}/complete")
    assert r.status_code == 201
    final = _wait_job(client, "stream-jobs", r.json()["job"]["id"])
    assert final["status"] == "succeeded"


def app_get_db(client):
    from redactor import app as app_mod

    return app_mod.get_db


def test_recovery_resets_index_when_staged_file_missing(client, isolated_data):
    content = sample_ndjson().encode()
    sid = _create(client, content).json()["session"]["id"]
    n = len(content)
    _put(client, sid, content[:100], 0, total=n)
    # 暂存文件被外部删除：索引不可信，恢复时重置让客户端重传
    staged = isolated_data["data_dir"] / "uploads" / f"{sid}.part"
    staged.unlink()
    upload_sessions.reset_upload_recovery()
    upload_sessions.recover_upload_sessions(app_get_db(client))
    prog = client.get(f"/api/v1/upload-sessions/{sid}").json()
    assert prog["bytes_received"] == 0
    assert prog["missing_ranges"] == [{"start": 0, "end": n, "bytes": n}]
    # 重传可继续（暂存文件由分片写入按需重建）
    r = _put(client, sid, content, 0, total=n)
    assert r.status_code == 200


def test_recovery_sweeps_orphan_files(client, isolated_data):
    content = sample_ndjson().encode()
    sid = _create(client, content).json()["session"]["id"]
    uploads = isolated_data["data_dir"] / "uploads"
    orphan = uploads / "deadbeef.part"
    orphan.write_bytes(b"orphan")
    tmp = uploads / ".tmp-stale"
    tmp.write_bytes(b"stale")
    upload_sessions.reset_upload_recovery()
    upload_sessions.recover_upload_sessions(app_get_db(client))
    assert not orphan.exists()
    assert not tmp.exists()
    # 正常会话的暂存文件不受影响
    assert (uploads / f"{sid}.part").exists()


# ---------- 幂等键贯穿 ----------


def test_completed_session_key_blocks_conflicting_job_upload(client):
    """会话完成后，同键不同内容的直接 multipart 上传返回 409。"""
    content = sample_ndjson().encode()
    sid = _create(client, content, key="cross-check-1").json()["session"]["id"]
    _upload_all(client, sid, content)
    r = client.post(f"/api/v1/upload-sessions/{sid}/complete")
    assert r.status_code == 201
    _wait_job(client, "stream-jobs", r.json()["job"]["id"])

    files = {"file": ("logs.ndjson", content + b"\n", "application/x-ndjson")}
    data = {"strategy": json.dumps(SAMPLE_STRATEGY)}
    r = client.post("/api/v1/stream-jobs", files=files, data=data,
                    headers={"Idempotency-Key": "cross-check-1"})
    assert r.status_code == 409
    # 同键同内容同策略：回放既有作业
    files = {"file": ("logs.ndjson", content, "application/x-ndjson")}
    r = client.post("/api/v1/stream-jobs", files=files, data=data,
                    headers={"Idempotency-Key": "cross-check-1"})
    assert r.status_code == 200
    assert r.json()["replayed"] is True


def test_domain_isolation_preserved_through_session(client):
    """会话声明的关联域贯穿到作业：同内容不同域替身不同。"""
    content = sample_ndjson().encode()
    job_ids = {}
    for ctx in ("tenant-a", "tenant-b"):
        sid = _create(client, content, token_context=ctx).json()["session"]["id"]
        _upload_all(client, sid, content)
        r = client.post(f"/api/v1/upload-sessions/{sid}/complete")
        assert r.status_code == 201
        job_ids[ctx] = r.json()["job"]["id"]
    outs = {}
    for ctx, jid in job_ids.items():
        final = _wait_job(client, "stream-jobs", jid)
        assert final["status"] == "succeeded"
        dl = client.get(f"/api/v1/stream-jobs/{jid}/download")
        outs[ctx] = dl.text
    # 不同域：脱敏输出中的令牌替身不同
    assert outs["tenant-a"] != outs["tenant-b"]
