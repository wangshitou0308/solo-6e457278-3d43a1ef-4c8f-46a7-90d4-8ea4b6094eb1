"""诊断包（ZIP）作业测试：上传校验、混合文件脱敏、清单、幂等、取消、
重启续跑、原子发布、分页与下载。"""
from __future__ import annotations

import io
import json
import os
import stat
import threading
import zipfile

import pytest
from fastapi.testclient import TestClient

from redactor import bundle_jobs, bundle_zip
from redactor.bundle_zip import BundleRejection, validate_bundle
from redactor.samples import SAMPLE_STRATEGY


@pytest.fixture()
def client(isolated_data):
    bundle_jobs.reset_bundle_recovery()
    bundle_jobs.bundle_registry.reset()
    bundle_jobs.on_file_hook = None
    bundle_jobs.on_publish_hook = None
    yield TestClient(isolated_data["app"])
    bundle_jobs.on_file_hook = None
    bundle_jobs.on_publish_hook = None
    bundle_jobs.bundle_registry.reset()
    bundle_jobs.reset_bundle_recovery()


# ---------- 构造辅助 ----------


def make_zip(files: dict[str, bytes | str]) -> bytes:
    """用 zipfile.writestr 构造测试压缩包（external_attr 仅权限位）。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            if isinstance(data, str):
                data = data.encode("utf-8")
            zf.writestr(name, data)
    return buf.getvalue()


def _upload(client, content, key=None, filename="diag.zip", strategy=None):
    files = {"file": (filename, content, "application/zip")}
    data = {"strategy": json.dumps(strategy or SAMPLE_STRATEGY)}
    headers = {"Idempotency-Key": key} if key else {}
    return client.post("/api/v1/bundle-jobs", files=files, data=data, headers=headers)


def _wait(client, job_id, timeout=10.0):
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/v1/bundle-jobs/{job_id}").json()
        if job["status"] in ("succeeded", "failed", "cancelled"):
            return job
        time.sleep(0.01)
    raise AssertionError("作业超时未终结")


def _download_zip(client, job_id) -> zipfile.ZipFile:
    r = client.get(f"/api/v1/bundle-jobs/{job_id}/download")
    assert r.status_code == 200
    assert "application/zip" in r.headers["content-type"]
    return zipfile.ZipFile(io.BytesIO(r.content))


def sample_bundle() -> bytes:
    """混合诊断包：结构化 + 文本 + 二进制 + 不支持类型。"""
    return make_zip({
        "logs/app.log": "user zhangsan@example.com login from 10.23.56.78\r\n"
                        "call 13800001234 for details\r\n",
        "logs/api.ndjson": json.dumps({"user": {"phone": "13800001234"},
                                       "msg": "ip 10.0.0.9"}) + "\n"
                           + json.dumps({"note": "ok"}) + "\n",
        "config/db.json": json.dumps({"password": "Pa$$w0rd!",
                                      "email": "admin@example.com"}),
        "notes.txt": "token=ak_live_9f2a7c4e1b8d46a09f3e5c7d8a1b2e4f\n",
        "logs/dump.log": b"\x00\x01\x02binary",
        "readme.md": "# not supported\n",
    })


# ---------- 安全校验（单元级） ----------


def test_writestr_permission_only_entries_pass_validation(tmp_path):
    """回归：writestr 生成的条目只有权限位（0o600，无类型位），必须按普通文件通过。"""
    path = tmp_path / "ok.zip"
    path.write_bytes(make_zip({"logs/app.log": "hello\n"}))
    entries = validate_bundle(path)
    assert [e.name for e in entries] == ["logs/app.log"]


def test_symlink_and_special_files_rejected(tmp_path):
    """真正的符号链接与特殊文件（fifo/设备）仍必须被拒绝。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        link = zipfile.ZipInfo("etc/passwd-link")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(link, "/etc/passwd")
        fifo = zipfile.ZipInfo("pipes/notify")
        fifo.external_attr = (stat.S_IFIFO | 0o644) << 16
        zf.writestr(fifo, "")
        regular = zipfile.ZipInfo("logs/app.log")
        regular.external_attr = (stat.S_IFREG | 0o644) << 16
        zf.writestr(regular, "ok\n")
    path = tmp_path / "bad.zip"
    path.write_bytes(buf.getvalue())
    with pytest.raises(BundleRejection) as exc_info:
        validate_bundle(path)
    reasons = "；".join(exc_info.value.reasons)
    assert "符号链接或特殊文件" in reasons
    assert "etc/passwd-link" in reasons and "pipes/notify" in reasons

    # 显式带 S_IFREG 类型位的普通文件不受影响
    good = io.BytesIO()
    with zipfile.ZipFile(good, "w") as zf:
        zi = zipfile.ZipInfo("logs/app.log")
        zi.external_attr = (stat.S_IFREG | 0o644) << 16
        zf.writestr(zi, "ok\n")
    good_path = tmp_path / "good.zip"
    good_path.write_bytes(good.getvalue())
    assert [e.name for e in validate_bundle(good_path)] == ["logs/app.log"]


@pytest.mark.parametrize("name", [
    "../evil.txt",
    "a/../../b.txt",
    "/abs/path.txt",
    "C:/windows/system32/x.txt",
    "a\\..\\b.txt",
    "back\\slash.txt",
])
def test_path_traversal_names_rejected(tmp_path, name):
    path = tmp_path / "trav.zip"
    path.write_bytes(make_zip({name: "x"}))
    with pytest.raises(BundleRejection):
        validate_bundle(path)


def test_duplicate_and_encrypted_and_empty_rejected(tmp_path):
    # 重复路径
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            zf.writestr("a.txt", "1")
            zf.writestr("a.txt", "2")
    dup = tmp_path / "dup.zip"
    dup.write_bytes(buf.getvalue())
    with pytest.raises(BundleRejection) as exc_info:
        validate_bundle(dup)
    assert any("重复路径" in r for r in exc_info.value.reasons)

    # 加密条目（手工置 general purpose flag 第 0 位）
    raw = bytearray(make_zip({"secret.txt": "x"}))
    i = raw.find(b"PK\x03\x04")
    raw[i + 6] |= 0x01
    j = raw.find(b"PK\x01\x02")
    raw[j + 8] |= 0x01
    enc = tmp_path / "enc.zip"
    enc.write_bytes(bytes(raw))
    with pytest.raises(BundleRejection) as exc_info:
        validate_bundle(enc)
    assert any("加密条目" in r for r in exc_info.value.reasons)

    # 空包（只有目录）
    empty = tmp_path / "empty.zip"
    empty.write_bytes(make_zip({"only-dir/": ""}))
    with pytest.raises(BundleRejection) as exc_info:
        validate_bundle(empty)
    assert any("空" in r for r in exc_info.value.reasons)

    # 非 ZIP 文件
    notzip = tmp_path / "not.zip"
    notzip.write_bytes(b"this is not a zip file at all")
    with pytest.raises(BundleRejection):
        validate_bundle(notzip)


def test_limits_rejected(tmp_path, monkeypatch):
    # 文件数上限
    monkeypatch.setenv("REDACTOR_BUNDLE_MAX_FILES", "2")
    path = tmp_path / "many.zip"
    path.write_bytes(make_zip({"a.txt": "1", "b.txt": "2", "c.txt": "3"}))
    with pytest.raises(BundleRejection) as exc_info:
        validate_bundle(path)
    assert any("文件数" in r for r in exc_info.value.reasons)

    # 单文件展开上限（下限钳制为 1024）
    monkeypatch.setenv("REDACTOR_BUNDLE_MAX_FILES", "100")
    monkeypatch.setenv("REDACTOR_BUNDLE_MAX_FILE_BYTES", "1024")
    path = tmp_path / "big.zip"
    path.write_bytes(make_zip({"big.txt": "x" * 5000}))
    with pytest.raises(BundleRejection) as exc_info:
        validate_bundle(path)
    assert any("单文件" in r for r in exc_info.value.reasons)

    # 展开总量上限
    monkeypatch.setenv("REDACTOR_BUNDLE_MAX_FILE_BYTES", "10000")
    monkeypatch.setenv("REDACTOR_BUNDLE_MAX_TOTAL_BYTES", "1024")
    path = tmp_path / "total.zip"
    path.write_bytes(make_zip({"a.txt": "x" * 800, "b.txt": "y" * 800}))
    with pytest.raises(BundleRejection) as exc_info:
        validate_bundle(path)
    assert any("展开总量" in r for r in exc_info.value.reasons)

    # 压缩比上限（2 MiB 重复字符 deflate 后比值远超 100:1）
    monkeypatch.setenv("REDACTOR_BUNDLE_MAX_FILE_BYTES", "104857600")
    monkeypatch.setenv("REDACTOR_BUNDLE_MAX_TOTAL_BYTES", "104857600")
    path = tmp_path / "bomb.zip"
    path.write_bytes(make_zip({"zeros.txt": "0" * (2 * 1024 * 1024)}))
    with pytest.raises(BundleRejection) as exc_info:
        validate_bundle(path)
    assert any("压缩比" in r for r in exc_info.value.reasons)


# ---------- 端到端：混合文件脱敏与清单 ----------


def test_mixed_bundle_end_to_end(client, isolated_data):
    r = _upload(client, sample_bundle())
    assert r.status_code == 202
    job = r.json()["job"]
    assert job["files_total"] == 6

    final = _wait(client, job["id"])
    assert final["status"] == "succeeded"
    assert final["progress_pct"] == 100.0
    assert final["files_processed"] == 6
    assert final["records_processed"] == 3  # ndjson 2 条 + json 1 条
    assert final["audit_count"] > 0
    assert final["download_url"].endswith("/download")

    # 原始压缩包与暂存区已清理，结果 ZIP 0600 发布
    data_dir = isolated_data["data_dir"]
    assert not (data_dir / "bundles/raw" / f"{job['id']}.zip").exists()
    assert not (data_dir / "bundles/staging" / job["id"]).exists()
    out = data_dir / "bundles/out" / f"{job['id']}.zip"
    assert out.exists()
    assert stat.S_IMODE(out.stat().st_mode) == 0o600

    zf = _download_zip(client, job["id"])
    names = set(zf.namelist())
    # 结果 ZIP 仅含脱敏文件与清单：二进制/不支持类型不在其中
    assert names == {
        "logs/app.log", "logs/api.ndjson", "config/db.json",
        "notes.txt", "redaction-manifest.json",
    }

    # 文本：内容规则逐行生效，CRLF 换行风格保留
    app_log = zf.read("logs/app.log").decode("utf-8")
    assert "zhangsan@example.com" not in app_log
    assert "10.23.56.78" not in app_log
    assert "13800001234" not in app_log
    assert app_log.endswith("\r\n") and "\r\n" in app_log

    # NDJSON：字段+内容规则生效；跨文件同一手机号同一替身
    ndjson_lines = [json.loads(l) for l in
                    zf.read("logs/api.ndjson").decode("utf-8").splitlines()]
    phone_token = ndjson_lines[0]["user"]["phone"]
    assert phone_token.startswith("T-")
    assert "10.0.0.9" not in ndjson_lines[0]["msg"]
    assert phone_token in zf.read("logs/app.log").decode("utf-8")

    # JSON：delete 动作置空、邮箱掩码，顶层对象结构保留
    db_json = json.loads(zf.read("config/db.json").decode("utf-8"))
    assert db_json["password"] is None
    assert db_json["email"].startswith("a") and "@" not in db_json["email"]

    # 清单：每个文件的状态与原因
    manifest = json.loads(zf.read("redaction-manifest.json").decode("utf-8"))
    assert manifest["job_id"] == job["id"]
    assert manifest["stats"]["files_redacted"] == 4
    assert manifest["stats"]["files_skipped"] == 2
    by_path = {f["path"]: f for f in manifest["files"]}
    assert by_path["logs/dump.log"]["status"] == "skipped"
    assert "二进制" in by_path["logs/dump.log"]["reason"]
    assert by_path["readme.md"]["status"] == "skipped"
    assert "不支持" in by_path["readme.md"]["reason"]
    assert by_path["logs/app.log"]["format"] == "text"
    assert by_path["logs/app.log"]["lines"] == 2
    assert by_path["config/db.json"]["records"] == 1
    # 清单不含原值
    blob = json.dumps(manifest, ensure_ascii=False)
    assert "zhangsan@example.com" not in blob and "13800001234" not in blob

    # 审计带来源路径与行号，且不含原值
    audit = client.get(f"/api/v1/bundle-jobs/{job['id']}/audit").json()
    assert audit["total"] == final["audit_count"]
    paths = {a["source_path"] for a in audit["items"]}
    assert "logs/app.log" in paths and "logs/api.ndjson" in paths
    text_entries = [a for a in audit["items"] if a["source_path"] == "logs/app.log"]
    assert text_entries and all(a["line_no"] in (1, 2) for a in text_entries)
    assert all(a["field_path"] == "$" for a in text_entries)
    ndjson_entries = [a for a in audit["items"]
                      if a["source_path"] == "logs/api.ndjson"]
    assert any(a["line_no"] == 1 for a in ndjson_entries)
    json_entries = [a for a in audit["items"]
                    if a["source_path"] == "config/db.json"]
    assert json_entries and all(a["line_no"] is None for a in json_entries)
    blob = json.dumps(audit, ensure_ascii=False)
    assert "zhangsan@example.com" not in blob and "13800001234" not in blob

    # 残留风险带来源路径（示例策略不处理银行卡，notes.txt 中的令牌已被处理）
    risks = client.get(f"/api/v1/bundle-jobs/{job['id']}/risks").json()
    assert risks["total"] == final["risk_count"]
    for item in risks["items"]:
        assert item["source_path"]


def test_manifest_endpoint_matches_result(client):
    r = _upload(client, sample_bundle())
    job = _wait(client, r.json()["job"]["id"])
    m = client.get(f"/api/v1/bundle-jobs/{job['id']}/manifest").json()
    assert m["job_id"] == job["id"]
    assert m["completed_at"] is not None
    assert len(m["files"]) == 6
    zf = _download_zip(client, job["id"])
    in_zip = json.loads(zf.read("redaction-manifest.json").decode("utf-8"))
    assert {f["path"] for f in in_zip["files"]} == {f["path"] for f in m["files"]}


def test_newline_styles_and_blank_lines_preserved(client):
    content = make_zip({
        "crlf.log": "ip 1.2.3.4\r\nplain line\r\n",
        "lf.log": "ip 1.2.3.4\nplain line\n",
        "blank.ndjson": '{"a": 1}\n\n{"b": "x@y.com"}\n',
        "styled.json": json.dumps({"email": "a@b.com"}, indent=2).replace("\n", "\r\n"),
    })
    job = _wait(client, _upload(client, content).json()["job"]["id"])
    assert job["status"] == "succeeded"
    zf = _download_zip(client, job["id"])

    crlf = zf.read("crlf.log").decode("utf-8")
    assert crlf.count("\r\n") == 2 and "1.2.3.4" not in crlf
    lf = zf.read("lf.log").decode("utf-8")
    assert "\r" not in lf and lf.endswith("\n")

    # 空白行原样保留：物理行号与审计行号对齐
    blank = zf.read("blank.ndjson").decode("utf-8")
    assert blank.split("\n")[1] == ""
    audit = client.get(f"/api/v1/bundle-jobs/{job['id']}/audit").json()
    entry = [a for a in audit["items"] if a["source_path"] == "blank.ndjson"]
    assert entry and entry[0]["line_no"] == 3

    # JSON 重序列化沿用源文件 CRLF 风格
    styled_text = zf.read("styled.json").decode("utf-8")
    assert "\r\n" in styled_text
    assert json.loads(styled_text)["email"].startswith("a")


def test_failed_file_does_not_block_others(client):
    content = make_zip({
        "good.txt": "mail me a@b.com\n",
        "broken.json": "{not valid json",
        "bad.ndjson": '{"ok": 1}\n{bad line}\n',
    })
    job = _wait(client, _upload(client, content).json()["job"]["id"])
    assert job["status"] == "succeeded"  # 单文件失败不拖垮整个作业
    m = client.get(f"/api/v1/bundle-jobs/{job['id']}/manifest").json()
    by_path = {f["path"]: f for f in m["files"]}
    assert by_path["good.txt"]["status"] == "redacted"
    assert by_path["broken.json"]["status"] == "failed"
    assert "JSON 解析失败" in by_path["broken.json"]["reason"]
    assert by_path["bad.ndjson"]["status"] == "failed"
    assert "第 2 行" in by_path["bad.ndjson"]["reason"]
    # 失败文件的半成品审计不落库
    audit = client.get(f"/api/v1/bundle-jobs/{job['id']}/audit").json()
    assert {a["source_path"] for a in audit["items"]} == {"good.txt"}
    zf = _download_zip(client, job["id"])
    assert set(zf.namelist()) == {"good.txt", "redaction-manifest.json"}


def test_reserved_manifest_name_skipped(client):
    content = make_zip({
        "redaction-manifest.json": json.dumps({"fake": True}),
        "real.txt": "ip 9.9.9.9\n",
    })
    job = _wait(client, _upload(client, content).json()["job"]["id"])
    assert job["status"] == "succeeded"
    m = client.get(f"/api/v1/bundle-jobs/{job['id']}/manifest").json()
    by_path = {f["path"]: f for f in m["files"]}
    assert by_path["redaction-manifest.json"]["status"] == "skipped"
    assert "保留名" in by_path["redaction-manifest.json"]["reason"]
    zf = _download_zip(client, job["id"])
    # ZIP 内的清单是服务生成的，不是用户伪造的那份
    manifest = json.loads(zf.read("redaction-manifest.json").decode("utf-8"))
    assert manifest["job_id"] == job["id"]


# ---------- 上传校验（接口级） ----------


def test_upload_rejects_unsafe_zip(client, isolated_data):
    r = _upload(client, make_zip({"../evil.txt": "x", "ok.txt": "y"}))
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["reasons"] and any("穿越" in x or "非法" in x
                                     for x in detail["reasons"])
    # 拒绝不产生作业，也不残留临时文件
    assert client.get("/api/v1/bundle-jobs").json()["total"] == 0
    assert not list((isolated_data["data_dir"] / "bundles/raw").glob("*"))


def test_upload_rejects_not_zip_and_empty(client):
    r = _upload(client, b"definitely not a zip")
    assert r.status_code == 422
    assert "ZIP" in json.dumps(r.json()["detail"], ensure_ascii=False)
    r = _upload(client, b"")
    assert r.status_code == 422


def test_upload_size_cap(client, monkeypatch):
    monkeypatch.setenv("REDACTOR_BUNDLE_MAX_TOTAL_BYTES", "1024")
    # 随机内容不可压缩，压缩态同样超过 1 KiB 上限 → 上传流式拷贝即被拒
    big = make_zip({"big.bin": os.urandom(4096)})
    r = _upload(client, big)
    assert r.status_code == 413


def test_invalid_strategy_422(client):
    files = {"file": ("d.zip", sample_bundle(), "application/zip")}
    bad = {"name": "bad", "rules": [
        {"id": "BAD ID", "name": "x", "match": {}, "action": "delete"}]}
    r = client.post("/api/v1/bundle-jobs", files=files,
                    data={"strategy": json.dumps(bad)})
    assert r.status_code == 422


# ---------- 幂等与冲突 ----------


def test_idempotent_replay_and_conflicts(client):
    bundle = sample_bundle()
    r1 = _upload(client, bundle, key="bundle-001")
    j1 = r1.json()["job"]["id"]
    _wait(client, j1)

    # 同键同包同策略：回放
    r2 = _upload(client, bundle, key="bundle-001")
    assert r2.status_code == 200
    assert r2.json()["replayed"] is True
    assert r2.json()["job"]["id"] == j1
    assert client.get("/api/v1/bundle-jobs").json()["total"] == 1

    # 同键不同压缩包：409
    other = make_zip({"other.txt": "ip 1.1.1.1\n"})
    r3 = _upload(client, other, key="bundle-001")
    assert r3.status_code == 409
    assert r3.json()["detail"]["existing_job_id"] == j1

    # 同键同包不同策略：409
    import copy
    other_strategy = copy.deepcopy(SAMPLE_STRATEGY)
    other_strategy["rules"][1]["keep_prefix"] = 3
    r4 = _upload(client, bundle, key="bundle-001", strategy=other_strategy)
    assert r4.status_code == 409
    assert "策略" in r4.json()["detail"]["message"]
    assert client.get("/api/v1/bundle-jobs").json()["total"] == 1


# ---------- 取消 ----------


def test_cancel_stops_job_and_cleans_files(client, isolated_data):
    gate = threading.Event()
    release = threading.Event()
    seen = []

    def hook(job_id, path):
        seen.append(path)
        if len(seen) == 1:
            gate.set()
            release.wait(timeout=10)

    bundle_jobs.on_file_hook = hook
    content = make_zip({
        "a.txt": "ip 1.2.3.4\n",
        "b.txt": "ip 5.6.7.8\n",
        "c.txt": "ip 9.9.9.9\n",
    })
    r = _upload(client, content)
    job_id = r.json()["job"]["id"]
    assert gate.wait(timeout=5)

    cr = client.post(f"/api/v1/bundle-jobs/{job_id}/cancel")
    assert cr.status_code == 200 and cr.json()["cancelling"] is True
    release.set()

    final = _wait(client, job_id)
    assert final["status"] == "cancelled"
    assert final["files_processed"] <= 1  # 停在文件边界
    data_dir = isolated_data["data_dir"]
    assert not (data_dir / "bundles/raw" / f"{job_id}.zip").exists()
    assert not (data_dir / "bundles/staging" / job_id).exists()
    assert client.get(f"/api/v1/bundle-jobs/{job_id}/download").status_code == 409


def test_cancel_terminal_job_is_409(client):
    job = _wait(client, _upload(client, sample_bundle()).json()["job"]["id"])
    cr = client.post(f"/api/v1/bundle-jobs/{job['id']}/cancel")
    assert cr.status_code == 409


def test_cancel_persists_across_restart(client, isolated_data):
    gate = threading.Event()
    release = threading.Event()

    def hook(job_id, path):
        gate.set()
        release.wait(timeout=10)

    bundle_jobs.on_file_hook = hook
    content = make_zip({"a.txt": "ip 1.2.3.4\n", "b.txt": "x\n"})
    r = _upload(client, content)
    job_id = r.json()["job"]["id"]
    assert gate.wait(timeout=5)

    # 重启前请求取消（持久化），随后模拟进程退出
    client.post(f"/api/v1/bundle-jobs/{job_id}/cancel")
    release.set()
    bundle_jobs.bundle_registry._threads[job_id].join(timeout=10)

    bundle_jobs.bundle_registry.reset()
    bundle_jobs.reset_bundle_recovery()
    bundle_jobs.on_file_hook = None
    client.get("/api/v1/bundle-jobs")  # 触发恢复扫描
    final = _wait(client, job_id)
    assert final["status"] == "cancelled"
    assert not (isolated_data["data_dir"] / "bundles/raw" / f"{job_id}.zip").exists()


# ---------- 重启续跑与原子发布 ----------


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_resume_from_file_checkpoint_after_crash(client, isolated_data):
    """worker 在第二个文件前“崩溃”，重启后跳过已完成文件续跑。"""
    crashed = set()

    class _Crash(BaseException):
        pass

    def hook(job_id, path):
        if path == "b.ndjson" and job_id not in crashed:
            crashed.add(job_id)
            raise _Crash("simulated hard crash")

    bundle_jobs.on_file_hook = hook
    content = make_zip({
        "a.log": "mail a@b.com\n",
        "b.ndjson": json.dumps({"phone": "13800001234"}) + "\n",
        "c.txt": "ip 8.8.8.8\n",
    })
    r = _upload(client, content)
    job_id = r.json()["job"]["id"]
    thread = bundle_jobs.bundle_registry._threads[job_id]
    thread.join(timeout=10)
    assert not thread.is_alive()

    # 崩溃后：状态仍 running，a.log 已检查点，原始包与暂存区保留
    stuck = client.get(f"/api/v1/bundle-jobs/{job_id}").json()
    assert stuck["status"] == "running"
    assert stuck["files_processed"] == 1
    data_dir = isolated_data["data_dir"]
    assert (data_dir / "bundles/raw" / f"{job_id}.zip").exists()
    assert (data_dir / "bundles/staging" / job_id / "a.log").exists()

    # “重启”：恢复扫描从未完成的 b.ndjson 继续
    bundle_jobs.bundle_registry.reset()
    bundle_jobs.reset_bundle_recovery()
    bundle_jobs.on_file_hook = None
    client.get("/api/v1/bundle-jobs")
    final = _wait(client, job_id)
    assert final["status"] == "succeeded"
    assert final["files_processed"] == 3

    # a.log 的审计只落库一次（恢复没有重复处理已完成文件）
    audit = client.get(f"/api/v1/bundle-jobs/{job_id}/audit",
                       params={"limit": 1000}).json()
    a_entries = [x for x in audit["items"] if x["source_path"] == "a.log"]
    assert len(a_entries) == audit["total"] - len(
        [x for x in audit["items"] if x["source_path"] != "a.log"])
    assert len(a_entries) == 1  # a.log 只有一处邮箱命中

    zf = _download_zip(client, job_id)
    assert set(zf.namelist()) == {
        "a.log", "b.ndjson", "c.txt", "redaction-manifest.json"}


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_crash_between_publish_and_mark_reconciles_on_restart(client, isolated_data):
    """成品 ZIP 已发布、succeeded 事务未提交时硬崩溃：重启补登状态且可下载。"""
    crashed = set()

    class _Crash(BaseException):
        pass

    def publish_hook(job_id):
        if job_id not in crashed:
            crashed.add(job_id)
            raise _Crash("crash after publish, before mark succeeded")

    bundle_jobs.on_publish_hook = publish_hook
    r = _upload(client, sample_bundle())
    job_id = r.json()["job"]["id"]
    bundle_jobs.bundle_registry._threads[job_id].join(timeout=10)

    stuck = client.get(f"/api/v1/bundle-jobs/{job_id}").json()
    assert stuck["status"] == "running"
    out = isolated_data["data_dir"] / "bundles/out" / f"{job_id}.zip"
    assert out.exists()
    published_bytes = out.read_bytes()

    bundle_jobs.bundle_registry.reset()
    bundle_jobs.reset_bundle_recovery()
    bundle_jobs.on_publish_hook = None
    client.get("/api/v1/bundle-jobs")
    final = _wait(client, job_id)
    assert final["status"] == "succeeded"
    # 成品字节级未被改动，原始包随对账清理
    assert out.read_bytes() == published_bytes
    assert not (isolated_data["data_dir"] / "bundles/raw" / f"{job_id}.zip").exists()
    zf = _download_zip(client, job_id)
    assert "redaction-manifest.json" in zf.namelist()


# ---------- 进度、分页、列表、下载约束 ----------


def test_progress_listing_and_pagination(client):
    content = make_zip({
        f"dir/f{i}.log": f"mail user{i}@example.com\n" for i in range(6)
    })
    job = _wait(client, _upload(client, content).json()["job"]["id"])
    assert job["files_total"] == 6 and job["files_processed"] == 6

    listing = client.get("/api/v1/bundle-jobs",
                         params={"status": "succeeded"}).json()
    assert listing["total"] == 1
    assert listing["items"][0]["id"] == job["id"]
    bad = client.get("/api/v1/bundle-jobs", params={"status": "nope"})
    assert bad.status_code == 400

    audit = client.get(f"/api/v1/bundle-jobs/{job['id']}/audit",
                       params={"limit": 2, "offset": 0}).json()
    assert audit["total"] == job["audit_count"]
    assert len(audit["items"]) == 2
    page2 = client.get(f"/api/v1/bundle-jobs/{job['id']}/audit",
                       params={"limit": 2, "offset": 2}).json()
    assert page2["items"]
    assert {json.dumps(a, sort_keys=True) for a in audit["items"]}.isdisjoint(
        {json.dumps(a, sort_keys=True) for a in page2["items"]})

    risks = client.get(f"/api/v1/bundle-jobs/{job['id']}/risks",
                       params={"limit": 2}).json()
    assert risks["total"] == job["risk_count"]


def test_download_requires_succeeded(client):
    gate = threading.Event()
    release = threading.Event()

    def hook(job_id, path):
        gate.set()
        release.wait(timeout=10)

    bundle_jobs.on_file_hook = hook
    r = _upload(client, make_zip({"a.txt": "ip 1.1.1.1\n"}))
    job_id = r.json()["job"]["id"]
    assert gate.wait(timeout=5)
    try:
        dl = client.get(f"/api/v1/bundle-jobs/{job_id}/download")
        assert dl.status_code == 409
    finally:
        release.set()
    _wait(client, job_id)


def test_unknown_job_404(client):
    assert client.get("/api/v1/bundle-jobs/deadbeef").status_code == 404
    assert client.get("/api/v1/bundle-jobs/deadbeef/audit").status_code == 404
    assert client.get("/api/v1/bundle-jobs/deadbeef/risks").status_code == 404
    assert client.get("/api/v1/bundle-jobs/deadbeef/manifest").status_code == 404
    assert client.post("/api/v1/bundle-jobs/deadbeef/cancel").status_code == 404
    assert client.get("/api/v1/bundle-jobs/deadbeef/download").status_code == 404


def test_openapi_documents_bundle_routes(client):
    spec = client.get("/openapi.json").json()
    paths = spec["paths"]
    for p in [
        "/api/v1/bundle-jobs",
        "/api/v1/bundle-jobs/{job_id}",
        "/api/v1/bundle-jobs/{job_id}/cancel",
        "/api/v1/bundle-jobs/{job_id}/audit",
        "/api/v1/bundle-jobs/{job_id}/risks",
        "/api/v1/bundle-jobs/{job_id}/manifest",
        "/api/v1/bundle-jobs/{job_id}/download",
    ]:
        assert p in paths, p
    create_responses = paths["/api/v1/bundle-jobs"]["post"]["responses"]
    assert "409" in create_responses and "422" in create_responses
    dl_responses = paths["/api/v1/bundle-jobs/{job_id}/download"]["get"]["responses"]
    assert "409" in dl_responses
