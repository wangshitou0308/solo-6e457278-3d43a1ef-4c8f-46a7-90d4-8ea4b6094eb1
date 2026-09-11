"""令牌关联域（token_context）测试。

覆盖：
* 域标识/子密钥密码学性质：不可逆、相同上下文稳定、不同上下文隔离、全局向后兼容；
* 小批量 dry-run / 正式作业：同域稳定、异域不同、mask/delete 不受影响、域指纹返回；
* 幂等键绑定内容+策略+关联域（同键换内容/换策略/换域均 409）；
* 非法 token_context 不创建文件或数据库记录；
* 流式作业与诊断包：域隔离、重启续跑沿用原域、状态/清单返回域指纹；
* 策略对照：基线与候选共用一个关联域。
"""
from __future__ import annotations

import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from redactor import bundle_jobs, stream_jobs
from redactor.crypto import (
    GLOBAL_DOMAIN_FINGERPRINT,
    MAX_TOKEN_CONTEXT,
    MasterKey,
    deterministic_number_token,
    deterministic_token,
    domain_fingerprint,
    domain_id_hex,
    domain_identifier,
    resolve_token_domain,
    validate_token_context,
)
from redactor.engine import RedactionEngine, run_strategy
from redactor.models import Strategy
from redactor.samples import SAMPLE_STRATEGY, sample_ndjson


# ---------- 密码学性质（单元） ----------


def test_global_domain_uses_master_key_directly():
    key = MasterKey(b"k" * 32)
    token_key, fp, domain_id = resolve_token_domain(key)
    assert token_key is key
    assert fp == GLOBAL_DOMAIN_FINGERPRINT == "global"
    assert domain_id is None
    # 全局替身与历史行为逐字节一致
    assert deterministic_token(token_key, "v") == deterministic_token(key, "v")
    assert deterministic_number_token(token_key, 13800001234) == (
        deterministic_number_token(key, 13800001234)
    )


def test_same_context_same_domain_and_surrogate():
    key = MasterKey(b"k" * 32)
    k1, fp1, id1 = resolve_token_domain(key, "incident-1")
    k2, fp2, id2 = resolve_token_domain(key, "incident-1")
    assert id1 == id2 and fp1 == fp2
    assert fp1.startswith("dom:") and len(fp1) == len("dom:") + 16
    assert deterministic_token(k1, "13800001234") == deterministic_token(k2, "13800001234")
    assert deterministic_number_token(k1, 13800001234) == (
        deterministic_number_token(k2, 13800001234)
    )


def test_different_contexts_different_domains_and_surrogates():
    key = MasterKey(b"k" * 32)
    k1, fp1, id1 = resolve_token_domain(key, "incident-1")
    k2, fp2, id2 = resolve_token_domain(key, "incident-2")
    assert id1 != id2 and fp1 != fp2 and k1._raw != k2._raw
    assert deterministic_token(k1, "13800001234") != deterministic_token(k2, "13800001234")
    assert deterministic_number_token(k1, 13800001234) != (
        deterministic_number_token(k2, 13800001234)
    )


def test_isolated_surrogate_differs_from_global():
    key = MasterKey(b"k" * 32)
    sub, _fp, _id = resolve_token_domain(key, "incident-1")
    assert deterministic_token(sub, "13800001234") != deterministic_token(key, "13800001234")


def test_domain_identifier_is_irreversible_and_unique_per_master_key():
    key_a = MasterKey(b"a" * 32)
    key_b = MasterKey(b"b" * 32)
    # 域标识是 HMAC 摘要：不含上下文原文，且不同主密钥下同一上下文标识不同
    assert domain_identifier(key_a, "incident-1") != domain_identifier(key_b, "incident-1")
    tag = domain_id_hex(key_a, "incident-1")
    assert "incident-1" not in tag
    assert domain_fingerprint(tag) == "dom:" + tag[:16]


def test_domain_resumes_from_persisted_identifier():
    """重启续跑：只有域标识（hex）也能恢复同一域子密钥。"""
    key = MasterKey(b"k" * 32)
    k1, fp1, id1 = resolve_token_domain(key, "incident-1")
    k2, fp2, _ = resolve_token_domain(key, domain_id=id1.hex())
    assert fp1 == fp2
    assert deterministic_token(k1, "13800001234") == deterministic_token(k2, "13800001234")


def test_validate_token_context_rules():
    assert validate_token_context(None) is None
    assert validate_token_context("   ") is None
    assert validate_token_context("  ctx  ") == "ctx"
    assert validate_token_context("好" * MAX_TOKEN_CONTEXT) == "好" * MAX_TOKEN_CONTEXT
    with pytest.raises(ValueError):
        validate_token_context("x" * (MAX_TOKEN_CONTEXT + 1))


# ---------- 引擎层 ----------


_TOKEN_STRATEGY = Strategy.model_validate({
    "name": "t",
    "rules": [
        {"id": "tok", "name": "令牌化", "match": {"key_names": ["phone"]},
         "action": "tokenize"},
        {"id": "del", "name": "删除", "match": {"key_names": ["password"]},
         "action": "delete"},
        {"id": "msk", "name": "掩码", "match": {"key_names": ["email"]},
         "action": "mask", "keep_prefix": 1},
    ],
})


def test_engine_mask_and_delete_unaffected_by_domain():
    key = MasterKey(b"k" * 32)
    sub, _fp, _id = resolve_token_domain(key, "ctx")
    record = {"phone": "13800001234", "password": "p@ss", "email": "a@b.com"}
    g = run_strategy(_TOKEN_STRATEGY, [record], key).records[0]
    s = run_strategy(_TOKEN_STRATEGY, [record], sub).records[0]
    # delete/mask 与域无关，输出一致；只有 tokenize 替身不同
    assert g["password"] is None and s["password"] is None
    assert g["email"] == s["email"]
    assert g["phone"] != s["phone"]


def test_run_strategy_reports_domain_fingerprint():
    key = MasterKey(b"k" * 32)
    sub, fp, _id = resolve_token_domain(key, "ctx")
    result = run_strategy(_TOKEN_STRATEGY, [{"phone": "13800001234"}], sub,
                          domain_fingerprint=fp)
    assert result.domain_fingerprint == fp
    # key_fingerprint 是子密钥指纹（调用方负责报告主密钥指纹）
    sub_engine = RedactionEngine(_TOKEN_STRATEGY, sub, domain_fingerprint=fp)
    assert sub_engine.domain_fingerprint == fp


# ---------- API fixtures ----------


@pytest.fixture()
def client(isolated_data):
    return TestClient(isolated_data["app"])


def _payload(ctx=None, content=None, strategy=None):
    p = {
        "format": "ndjson",
        "content": content if content is not None else sample_ndjson(),
        "strategy": strategy or SAMPLE_STRATEGY,
    }
    if ctx is not None:
        p["token_context"] = ctx
    return p


def _phone_token(body):
    return body["records"][0]["user"]["phone"]


# ---------- 小批量 dry-run / 作业 ----------


def test_dry_run_global_domain_default(client):
    r = client.post("/api/v1/strategies/validate", json=_payload())
    assert r.status_code == 200
    assert r.json()["domain_fingerprint"] == "global"


def test_dry_run_isolated_domain_stable_and_distinct(client):
    r1 = client.post("/api/v1/strategies/validate", json=_payload("incident-A"))
    r2 = client.post("/api/v1/strategies/validate", json=_payload("incident-A"))
    rb = client.post("/api/v1/strategies/validate", json=_payload("incident-B"))
    rg = client.post("/api/v1/strategies/validate", json=_payload())
    fp = r1.json()["domain_fingerprint"]
    assert fp.startswith("dom:") and fp == r2.json()["domain_fingerprint"]
    assert fp != rb.json()["domain_fingerprint"]
    assert _phone_token(r1.json()) == _phone_token(r2.json())
    assert _phone_token(r1.json()) != _phone_token(rb.json())
    assert _phone_token(r1.json()) != _phone_token(rg.json())


def test_blank_context_normalized_to_global(client):
    r = client.post("/api/v1/strategies/validate", json=_payload("   "))
    assert r.status_code == 200
    assert r.json()["domain_fingerprint"] == "global"


def test_context_too_long_is_422_and_creates_nothing(client, isolated_data):
    r = client.post(
        "/api/v1/strategies/validate", json=_payload("x" * (MAX_TOKEN_CONTEXT + 1))
    )
    assert r.status_code == 422
    r2 = client.post(
        "/api/v1/jobs", json=_payload("x" * (MAX_TOKEN_CONTEXT + 1)),
        headers={"Idempotency-Key": "k1"},
    )
    assert r2.status_code == 422
    assert client.get("/api/v1/jobs").json()["total"] == 0
    # 非法请求不落任何输出文件
    assert not list((isolated_data["data_dir"] / "jobs").glob("*")) if (
        isolated_data["data_dir"] / "jobs").exists() else True


def test_job_persists_domain_fingerprint_and_isolated_token(client):
    r = client.post("/api/v1/jobs", json=_payload("incident-A"))
    assert r.status_code == 201
    job = r.json()["job"]
    fp = job["domain_fingerprint"]
    assert fp.startswith("dom:")
    assert r.json()["result"]["domain_fingerprint"] == fp
    detail = client.get(f"/api/v1/jobs/{job['id']}").json()
    assert detail["domain_fingerprint"] == fp
    isolated_tok = _phone_token(r.json()["result"])

    # 全局域作业的同值替身不同
    rg = client.post("/api/v1/jobs", json=_payload())
    assert rg.json()["job"]["domain_fingerprint"] == "global"
    assert _phone_token(rg.json()["result"]) != isolated_tok

    # 相同上下文的第二个作业替身一致
    r2 = client.post("/api/v1/jobs", json=_payload("incident-A"))
    assert _phone_token(r2.json()["result"]) == isolated_tok


def test_context_plaintext_never_stored(client, isolated_data):
    ctx = "super-secret-context-42"
    client.post("/api/v1/jobs", json=_payload(ctx))
    db_bytes = (isolated_data["settings"].db_path).read_bytes()
    assert ctx.encode() not in db_bytes
    # 数据目录任何文件都不含上下文原文
    for path in isolated_data["data_dir"].rglob("*"):
        if path.is_file() and path.suffix in (".ndjson", ".json", ".db", ".key"):
            assert ctx.encode() not in path.read_bytes()


# ---------- 幂等键绑定内容/策略/域 ----------


def test_job_same_key_replays_when_triplet_identical(client):
    h = {"Idempotency-Key": "job-k"}
    r1 = client.post("/api/v1/jobs", json=_payload("incident-A"), headers=h)
    r2 = client.post("/api/v1/jobs", json=_payload("incident-A"), headers=h)
    assert r1.status_code == 201 and r2.status_code == 200
    assert r2.json()["job"]["id"] == r1.json()["job"]["id"]


def test_job_same_key_different_domain_is_409(client):
    h = {"Idempotency-Key": "job-k"}
    r1 = client.post("/api/v1/jobs", json=_payload("incident-A"), headers=h)
    r2 = client.post("/api/v1/jobs", json=_payload("incident-B"), headers=h)
    assert r1.status_code == 201 and r2.status_code == 409
    assert r2.json()["detail"]["existing_job_id"] == r1.json()["job"]["id"]
    assert client.get("/api/v1/jobs").json()["total"] == 1


def test_job_same_key_global_vs_isolated_is_409(client):
    h = {"Idempotency-Key": "job-k"}
    r1 = client.post("/api/v1/jobs", json=_payload(), headers=h)
    r2 = client.post("/api/v1/jobs", json=_payload("incident-A"), headers=h)
    assert r1.status_code == 201 and r2.status_code == 409


def test_job_same_key_different_content_is_409(client):
    h = {"Idempotency-Key": "job-k"}
    r1 = client.post("/api/v1/jobs", json=_payload("incident-A"), headers=h)
    other = _payload("incident-A",
                     content='{"phone": "13900000000"}\n')
    r2 = client.post("/api/v1/jobs", json=other, headers=h)
    assert r1.status_code == 201 and r2.status_code == 409


def test_job_same_key_different_strategy_is_409(client):
    h = {"Idempotency-Key": "job-k"}
    r1 = client.post("/api/v1/jobs", json=_payload("incident-A"), headers=h)
    changed = json.loads(json.dumps(SAMPLE_STRATEGY))
    # 改 action 必然改变规范化策略（同键不同策略 -> 409）
    changed["rules"][0]["action"] = (
        "mask" if changed["rules"][0]["action"] != "mask" else "delete"
    )
    r2 = client.post("/api/v1/jobs", json=_payload("incident-A", strategy=changed),
                     headers=h)
    assert r1.status_code == 201 and r2.status_code == 409


# ---------- 流式作业 ----------


@pytest.fixture()
def stream_client(isolated_data):
    stream_jobs.reset_recovery()
    stream_jobs.registry.reset()
    stream_jobs.on_record_hook = None
    stream_jobs.on_publish_hook = None
    yield TestClient(isolated_data["app"])
    stream_jobs.on_record_hook = None
    stream_jobs.on_publish_hook = None
    stream_jobs.registry.reset()
    stream_jobs.reset_recovery()


def _upload_stream(client, content, key=None, ctx=None):
    data = {"strategy": json.dumps(SAMPLE_STRATEGY)}
    if ctx is not None:
        data["token_context"] = ctx
    headers = {"Idempotency-Key": key} if key else {}
    return client.post(
        "/api/v1/stream-jobs",
        files={"file": ("logs.ndjson", content, "application/x-ndjson")},
        data=data, headers=headers,
    )


def _wait(client, job_id, timeout=10.0):
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/v1/stream-jobs/{job_id}").json()
        if job["status"] in ("succeeded", "failed", "cancelled"):
            return job
        time.sleep(0.01)
    raise AssertionError("作业超时未终结")


def _stream_content(n=20):
    return "".join(
        json.dumps({"i": i, "phone": "13800001234", "email": f"u{i}@e.com"}) + "\n"
        for i in range(n)
    )


def test_stream_job_isolated_domain_and_fingerprint(stream_client, isolated_data):
    r = _upload_stream(stream_client, _stream_content(), ctx="incident-S")
    assert r.status_code == 202
    job_id = r.json()["job"]["id"]
    fp = r.json()["job"]["domain_fingerprint"]
    assert fp.startswith("dom:")
    job = _wait(stream_client, job_id)
    assert job["status"] == "succeeded"
    assert job["domain_fingerprint"] == fp

    dl = stream_client.get(f"/api/v1/stream-jobs/{job_id}/download")
    first = json.loads(dl.text.splitlines()[0])
    # 与小批量同域替身一致
    small = stream_client.post(
        "/api/v1/strategies/validate",
        json=_payload("incident-S",
                      content=json.dumps({"i": 0, "phone": "13800001234",
                                          "email": "u0@e.com"})),
    ).json()
    assert first["phone"] == small["records"][0]["phone"]

    # 上下文原文既不入库也不入原始/成品文件
    db_bytes = (isolated_data["settings"].db_path).read_bytes()
    assert b"incident-S" not in db_bytes
    assert b"incident-S" not in dl.content


def test_stream_job_context_too_long_422_and_no_leftover(stream_client, isolated_data):
    r = _upload_stream(stream_client, _stream_content(2), ctx="x" * 129)
    assert r.status_code == 422
    # 没有作业、没有暂存文件
    assert stream_client.get("/api/v1/stream-jobs").json()["total"] == 0
    raw_dir = isolated_data["data_dir"] / "streams" / "raw"
    assert not any(raw_dir.glob("*.ndjson"))


def test_stream_same_key_different_domain_is_409(stream_client):
    r1 = _upload_stream(stream_client, _stream_content(), key="sk", ctx="incident-S")
    _wait(stream_client, r1.json()["job"]["id"])
    r2 = _upload_stream(stream_client, _stream_content(), key="sk", ctx="incident-T")
    assert r2.status_code == 409
    r3 = _upload_stream(stream_client, _stream_content(), key="sk", ctx="incident-S")
    assert r3.status_code == 200 and r3.json()["replayed"] is True


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_stream_resume_keeps_domain_after_restart(stream_client, isolated_data,
                                                  monkeypatch):
    """worker 在检查点后“硬崩溃”，重启续跑必须沿用原关联域，替身前后一致。"""
    monkeypatch.setenv("REDACTOR_CHECKPOINT_RECORDS", "5")
    content = _stream_content(20)

    import redactor.stream_jobs as sj

    crash_jobs: set[str] = set()

    class _Crash(BaseException):
        pass

    def hook(job_id, line_no):
        if line_no == 11 and job_id not in crash_jobs:
            crash_jobs.add(job_id)
            raise _Crash("simulated hard crash")

    monkeypatch.setattr(sj, "on_record_hook", hook)
    r = _upload_stream(stream_client, content, ctx="incident-resume")
    job_id = r.json()["job"]["id"]
    fp = r.json()["job"]["domain_fingerprint"]
    sj.registry._threads[job_id].join(timeout=10)

    crashed = stream_client.get(f"/api/v1/stream-jobs/{job_id}").json()
    assert crashed["status"] == "running"
    assert crashed["records_processed"] == 10

    # “重启”：清空注册表后通过状态查询惰性恢复
    sj.registry.reset()
    sj.reset_recovery()
    monkeypatch.setattr(sj, "on_record_hook", None)
    recovered = _wait(stream_client, job_id)
    assert recovered["status"] == "succeeded"
    assert recovered["domain_fingerprint"] == fp
    assert recovered["records_processed"] == 20

    # 全量 20 行替身必须与同域小批量结果一致（域在续跑后保持不变）
    dl = stream_client.get(f"/api/v1/stream-jobs/{job_id}/download")
    lines = [json.loads(l) for l in dl.text.splitlines() if l.strip()]
    expected = stream_client.post(
        "/api/v1/strategies/validate",
        json={"format": "ndjson", "content": content,
              "strategy": SAMPLE_STRATEGY, "token_context": "incident-resume"},
    ).json()
    assert [row["phone"] for row in lines] == [
        row["phone"] for row in expected["records"]
    ]


# ---------- 诊断包作业 ----------


def _make_bundle() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "logs/api.ndjson",
            "".join(
                json.dumps({"i": i, "phone": "13800001234"}) + "\n"
                for i in range(5)
            ),
        )
        zf.writestr("logs/app.log", "call 13800001234 now\n")
    return buf.getvalue()


def _upload_bundle(client, content, key=None, ctx=None):
    data = {"strategy": json.dumps(SAMPLE_STRATEGY)}
    if ctx is not None:
        data["token_context"] = ctx
    headers = {"Idempotency-Key": key} if key else {}
    return client.post(
        "/api/v1/bundle-jobs",
        files={"file": ("diag.zip", content, "application/zip")},
        data=data, headers=headers,
    )


@pytest.fixture()
def bundle_client(isolated_data):
    bundle_jobs.reset_bundle_recovery()
    bundle_jobs.bundle_registry.reset()
    bundle_jobs.on_file_hook = None
    bundle_jobs.on_publish_hook = None
    yield TestClient(isolated_data["app"])
    bundle_jobs.on_file_hook = None
    bundle_jobs.on_publish_hook = None
    bundle_jobs.bundle_registry.reset()
    bundle_jobs.reset_bundle_recovery()


def _wait_bundle(client, job_id, timeout=10.0):
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/v1/bundle-jobs/{job_id}").json()
        if job["status"] in ("succeeded", "failed", "cancelled"):
            return job
        time.sleep(0.01)
    raise AssertionError("诊断包作业超时未终结")


def test_bundle_isolated_domain_status_and_manifest(bundle_client, isolated_data):
    r = _upload_bundle(bundle_client, _make_bundle(), ctx="incident-Z")
    assert r.status_code == 202
    job_id = r.json()["job"]["id"]
    fp = r.json()["job"]["domain_fingerprint"]
    assert fp.startswith("dom:")
    job = _wait_bundle(bundle_client, job_id)
    assert job["status"] == "succeeded" and job["domain_fingerprint"] == fp

    # 清单接口与结果 ZIP 内的 manifest 都返回域指纹
    manifest = bundle_client.get(
        f"/api/v1/bundle-jobs/{job_id}/manifest"
    ).json()
    assert manifest["domain_fingerprint"] == fp

    dl = bundle_client.get(f"/api/v1/bundle-jobs/{job_id}/download")
    with zipfile.ZipFile(io.BytesIO(dl.content)) as zf:
        packaged = json.loads(
            zf.read("redaction-manifest.json").decode("utf-8")
        )
        ndjson = zf.read("logs/api.ndjson").decode("utf-8")
    assert packaged["domain_fingerprint"] == fp

    # 替身与同域小批量一致
    first_phone = json.loads(ndjson.splitlines()[0])["phone"]
    same_ctx = bundle_client.post(
        "/api/v1/strategies/validate",
        json={"format": "ndjson",
              "content": json.dumps({"i": 0, "phone": "13800001234"}) + "\n",
              "strategy": SAMPLE_STRATEGY, "token_context": "incident-Z"},
    ).json()
    assert first_phone == same_ctx["records"][0]["phone"]

    # 上下文原文不落库、不入结果
    assert b"incident-Z" not in isolated_data["settings"].db_path.read_bytes()
    assert b"incident-Z" not in dl.content


def test_bundle_context_too_long_422_and_no_leftover(bundle_client, isolated_data):
    r = _upload_bundle(bundle_client, _make_bundle(), ctx="x" * 129)
    assert r.status_code == 422
    assert bundle_client.get("/api/v1/bundle-jobs").json()["total"] == 0
    raw_dir = isolated_data["data_dir"] / "bundles" / "raw"
    assert not any(raw_dir.glob("*.zip"))


def test_bundle_same_key_different_domain_is_409(bundle_client):
    r1 = _upload_bundle(bundle_client, _make_bundle(), key="bk", ctx="incident-Z")
    _wait_bundle(bundle_client, r1.json()["job"]["id"])
    r2 = _upload_bundle(bundle_client, _make_bundle(), key="bk", ctx="incident-Y")
    assert r2.status_code == 409
    r3 = _upload_bundle(bundle_client, _make_bundle(), key="bk", ctx="incident-Z")
    assert r3.status_code == 200 and r3.json()["replayed"] is True


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_bundle_resume_keeps_domain_after_restart(bundle_client, monkeypatch):
    """文件级检查点后续跑：已完成文件与未完成文件的替身必须在同一关联域内。"""
    import redactor.bundle_jobs as bj

    crashed: set[str] = set()

    class _Crash(BaseException):
        pass

    def hook(job_id, path):
        if path == "logs/second.ndjson" and job_id not in crashed:
            crashed.add(job_id)
            raise _Crash("simulated hard crash")

    monkeypatch.setattr(bj, "on_file_hook", hook)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("logs/first.ndjson",
                    json.dumps({"phone": "13800001234"}) + "\n")
        zf.writestr("logs/second.ndjson",
                    json.dumps({"phone": "13800001234"}) + "\n")
    r = _upload_bundle(bundle_client, buf.getvalue(), ctx="incident-resume-b")
    job_id = r.json()["job"]["id"]
    fp = r.json()["job"]["domain_fingerprint"]
    bj.bundle_registry._threads[job_id].join(timeout=10)

    stuck = bundle_client.get(f"/api/v1/bundle-jobs/{job_id}").json()
    assert stuck["status"] == "running" and stuck["files_processed"] == 1

    # “重启”：恢复扫描从未完成的 second.ndjson 继续
    bundle_jobs.bundle_registry.reset()
    bundle_jobs.reset_bundle_recovery()
    monkeypatch.setattr(bj, "on_file_hook", None)
    bundle_client.get("/api/v1/bundle-jobs")  # 触发惰性恢复
    job = _wait_bundle(bundle_client, job_id)
    assert job["status"] == "succeeded"
    assert job["domain_fingerprint"] == fp

    dl = bundle_client.get(f"/api/v1/bundle-jobs/{job_id}/download")
    with zipfile.ZipFile(io.BytesIO(dl.content)) as zf:
        first = json.loads(zf.read("logs/first.ndjson").decode().strip())
        second = json.loads(zf.read("logs/second.ndjson").decode().strip())
    # 两个文件（续跑前后）同值替身一致
    assert first["phone"] == second["phone"] and first["phone"].startswith("T-")


# ---------- 策略对照 ----------


def _diff_payload(ctx=None):
    baseline = {
        "name": "base", "rules": [
            {"id": "tok-phone", "name": "令牌化手机号",
             "match": {"key_names": ["phone"]}, "action": "tokenize"},
        ],
    }
    candidate = {
        "name": "cand", "rules": [
            {"id": "tok-phone", "name": "令牌化手机号",
             "match": {"key_names": ["phone"]}, "action": "tokenize"},
            {"id": "mask-email", "name": "掩码邮箱",
             "match": {"key_names": ["email"]}, "action": "mask"},
        ],
    }
    p = {
        "format": "ndjson",
        "content": '{"phone": "13800001234", "email": "a@b.com"}\n',
        "baseline": baseline,
        "candidate": candidate,
    }
    if ctx is not None:
        p["token_context"] = ctx
    return p


def test_diff_uses_shared_domain_and_reports_fingerprint(client):
    r = client.post("/api/v1/strategies/diff", json=_diff_payload("incident-D"))
    assert r.status_code == 200
    body = r.json()
    assert body["domain_fingerprint"].startswith("dom:")
    # 两侧同域：共同覆盖的 phone 不会因域隔离产生动作/覆盖差异，
    # 差异只来自候选新增的 email 掩码
    assert body["summary"]["coverage_gained"] >= 1
    assert body["summary"]["action_changes"] == 0
    assert body["key_fingerprint"].startswith("sha256:")


def test_diff_without_context_is_global(client):
    r = client.post("/api/v1/strategies/diff", json=_diff_payload())
    assert r.status_code == 200
    assert r.json()["domain_fingerprint"] == "global"


def test_diff_context_too_long_is_422(client):
    r = client.post("/api/v1/strategies/diff",
                    json=_diff_payload("x" * (MAX_TOKEN_CONTEXT + 1)))
    assert r.status_code == 422
    assert client.get("/api/v1/jobs").json()["total"] == 0
