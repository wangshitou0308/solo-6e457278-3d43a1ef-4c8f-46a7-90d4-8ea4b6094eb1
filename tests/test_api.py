"""API 集成测试：试运行、作业、幂等、下载、错误处理。"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from redactor.samples import SAMPLE_STRATEGY, sample_ndjson


@pytest.fixture()
def client(isolated_data):
    return TestClient(isolated_data["app"])


def _payload(fmt="ndjson", content=None, strategy=None):
    return {
        "format": fmt,
        "content": content if content is not None else sample_ndjson(),
        "strategy": strategy or SAMPLE_STRATEGY,
    }


# ---------- 基础 ----------


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["key_fingerprint"].startswith("sha256:")


def test_openapi_available(client):
    r = client.get("/openapi.json")
    assert r.status_code == 200
    assert r.json()["info"]["title"] == "本地日志脱敏 API"
    paths = r.json()["paths"]
    for p in ["/api/v1/jobs", "/api/v1/strategies/validate",
              "/api/v1/jobs/{job_id}/download"]:
        assert p in paths


def test_sample_endpoints(client):
    s = client.get("/api/v1/sample/strategy").json()
    assert s["rules"]
    logs = client.get("/api/v1/sample/logs.ndjson")
    assert logs.status_code == 200
    assert "application/x-ndjson" in logs.headers["content-type"]
    lines = [l for l in logs.text.splitlines() if l.strip()]
    assert all(json.loads(l) for l in lines)


# ---------- 试运行 ----------


def test_dry_run_does_not_persist(client):
    r = client.post("/api/v1/strategies/validate", json=_payload())
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "dry-run"
    assert body["needs_review"] is True
    assert any(a["action"] == "tokenize" for a in body["audit"])
    # dry-run 不产生作业
    assert client.get("/api/v1/jobs").json()["total"] == 0
    # 审计中不应出现原始邮箱/手机号
    raw_blob = json.dumps(body["audit"], ensure_ascii=False)
    assert "zhangsan@example.com" not in raw_blob
    assert "13800001234" not in raw_blob


def test_dry_run_json_object_payload(client):
    content = json.dumps({"user": {"email": "a@b.com"}, "msg": "ip 10.0.0.9"})
    r = client.post("/api/v1/strategies/validate", json=_payload(fmt="json", content=content))
    assert r.status_code == 200
    rec = r.json()["records"][0]
    assert "@" not in rec["user"]["email"]


def test_json_array_payload(client):
    content = json.dumps([{"email": "a@b.com"}, {"email": "c@d.com"}])
    r = client.post("/api/v1/strategies/validate", json=_payload(fmt="json", content=content))
    assert len(r.json()["records"]) == 2


def test_invalid_ndjson_line_reports_line_no(client):
    r = client.post("/api/v1/strategies/validate",
                    json=_payload(content='{"a": 1}\n{broken}\n'))
    assert r.status_code == 422
    assert r.json()["detail"]["line"] == 2


def test_invalid_strategy_422(client):
    payload = _payload(strategy={"name": "bad", "rules": [
        {"id": "BAD ID", "name": "x", "match": {}, "action": "delete"}]})
    r = client.post("/api/v1/strategies/validate", json=payload)
    assert r.status_code == 422


def test_strategy_check_endpoint(client):
    r = client.post("/api/v1/strategies/check", json=SAMPLE_STRATEGY)
    assert r.status_code == 200 and r.json()["valid"] is True


# ---------- 正式作业 ----------


def _create_job(client, key=None, payload=None):
    headers = {"Idempotency-Key": key} if key else {}
    return client.post("/api/v1/jobs", json=payload or _payload(), headers=headers)


def test_create_job_persists_and_downloads_ndjson(client, isolated_data):
    r = _create_job(client)
    assert r.status_code == 201
    job = r.json()["job"]
    job_id = job["id"]
    assert job["needs_review"] is True
    assert job["stats"]["audit_entries"] > 0
    assert job["download_url"].endswith("/download")

    detail = client.get(f"/api/v1/jobs/{job_id}").json()
    assert detail["id"] == job_id
    assert detail["risks"]

    records = client.get(f"/api/v1/jobs/{job_id}/records").json()
    assert len(records["records"]) == 3
    # 确定性：同一手机号跨记录同令牌
    t1 = records["records"][0]["user"]["phone"]
    t2 = records["records"][2]["user"]["phone"]
    assert t1 == t2 and t1.startswith("T-")

    dl = client.get(f"/api/v1/jobs/{job_id}/download")
    assert dl.status_code == 200
    assert "attachment" in dl.headers["content-disposition"]
    assert "application/x-ndjson" in dl.headers["content-type"]
    lines = [l for l in dl.text.splitlines() if l.strip()]
    assert len(lines) == 3
    # 下载文件中不含原始敏感值
    assert "zhangsan@example.com" not in dl.text
    assert "13800001234" not in dl.text

    audit = client.get(f"/api/v1/jobs/{job_id}/audit").json()
    assert audit["count"] == detail["stats"]["audit_entries"]

    # 输出文件确实写到了本地 jobs 目录
    assert (isolated_data["data_dir"] / "jobs" / f"{job_id}.ndjson").exists()


def test_download_json_format_for_json_job(client):
    payload = _payload(fmt="json", content=json.dumps({"email": "a@b.com",
                                                       "msg": "ip 1.2.3.4"}))
    r = _create_job(client, payload=payload)
    job_id = r.json()["job"]["id"]
    dl = client.get(f"/api/v1/jobs/{job_id}/download")
    assert "application/json" in dl.headers["content-type"]
    assert json.loads(dl.text)  # 合法 JSON


def test_idempotency_key_replays_same_job(client):
    r1 = _create_job(client, key="inc-20260910-001")
    r2 = _create_job(client, key="inc-20260910-001")
    assert r1.status_code == 201
    assert r2.status_code == 200
    assert r2.json()["replayed"] is True
    assert r2.json()["job"]["id"] == r1.json()["job"]["id"]
    assert client.get("/api/v1/jobs").json()["total"] == 1


def test_different_idempotency_keys_create_distinct_jobs(client):
    r1 = _create_job(client, key="k-1")
    r2 = _create_job(client, key="k-2")
    assert r1.json()["job"]["id"] != r2.json()["job"]["id"]


def test_list_jobs_filter_needs_review(client):
    # 示例含未处理银行卡 → 需复核
    _create_job(client, key="a")
    clean = {
        "name": "clean",
        "rules": [
            {"id": "all", "name": "all", "match": {"detectors": ["email", "phone",
             "ipv4", "access_token", "id_card", "bank_card"]}, "action": "tokenize"}
        ],
        "risk_detectors": ["email", "phone", "ipv4", "access_token", "id_card", "bank_card"],
    }
    r2 = _create_job(client, key="b", payload=_payload(strategy=clean))
    assert r2.json()["job"]["needs_review"] is False
    todo = client.get("/api/v1/jobs", params={"needs_review": True}).json()
    ok = client.get("/api/v1/jobs", params={"needs_review": False}).json()
    assert todo["total"] == 1 and ok["total"] == 1


def test_404_for_unknown_job(client):
    assert client.get("/api/v1/jobs/deadbeef").status_code == 404
    assert client.get("/api/v1/jobs/deadbeef/download").status_code == 404


def test_body_size_limit(client):
    huge = '{"a": "' + "x" * (10 * 1024 * 1024 + 10) + '"}'
    r = client.post("/api/v1/strategies/validate",
                    json=_payload(fmt="json", content=huge))
    assert r.status_code == 413
