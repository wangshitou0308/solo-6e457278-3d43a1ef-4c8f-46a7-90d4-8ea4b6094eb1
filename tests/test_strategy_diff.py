"""策略变更对照（POST /api/v1/strategies/diff）与覆盖轨迹的测试。"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from redactor.crypto import MasterKey
from redactor.engine import RedactionEngine
from redactor.models import Strategy
from redactor.samples import SAMPLE_STRATEGY, sample_ndjson

KEY = MasterKey(b"0" * 32)


@pytest.fixture()
def client(isolated_data):
    return TestClient(isolated_data["app"])


def _strategy(rules, risk_detectors=None, name="s"):
    return {
        "name": name,
        "rules": rules,
        "risk_detectors": risk_detectors if risk_detectors is not None
        else ["email", "phone", "ipv4", "access_token", "id_card", "bank_card"],
    }


def _payload(baseline, candidate, content=None, fmt="ndjson", limits=None):
    body = {
        "format": fmt,
        "content": content if content is not None else '{"m": "a@b.com"}\n',
        "baseline": baseline,
        "candidate": candidate,
    }
    if limits is not None:
        body["limits"] = limits
    return body


def _diff(client, baseline, candidate, **kw):
    r = client.post("/api/v1/strategies/diff",
                    json=_payload(baseline, candidate, **kw))
    assert r.status_code == 200, r.text
    return r.json()


def _zeros(summary):
    return all(v == 0 for v in summary.values())


# ---------- 引擎覆盖轨迹（单元） ----------


def _trace_engine(rules, risk_detectors=None):
    s = Strategy(name="t", rules=[__import__("redactor.models", fromlist=["Rule"]).Rule(**r)
                                  for r in rules],
                 risk_detectors=risk_detectors or [])
    return RedactionEngine(s, KEY, collect_coverage=True)


def test_coverage_trace_field_rule_string_span_whole_value():
    engine = _trace_engine([{"id": "f", "name": "f",
                             "match": {"key_names": ["email"]}, "action": "mask"}])
    engine.process_record({"email": "a@b.com", "n": 1}, 0)
    assert len(engine.coverage) == 1
    ev = engine.coverage[0]
    assert ev.field_path == "$.email" and ev.span == (0, 7)
    assert ev.rule_id == "f" and ev.action == "mask" and ev.match_type == "field"


def test_coverage_trace_field_rule_non_string_span_none():
    engine = _trace_engine([{"id": "t", "name": "t",
                             "match": {"key_names": ["n"]}, "action": "tokenize"}])
    engine.process_record({"n": 12345}, 0)
    assert engine.coverage[0].span is None


def test_coverage_trace_content_rule_per_span_with_labels():
    engine = _trace_engine([{"id": "e", "name": "e",
                             "match": {"detectors": ["email"]}, "action": "mask"}])
    engine.process_record({"m": "a@b.com and c@d.org"}, 0)
    spans = [ev.span for ev in engine.coverage]
    assert spans == [(0, 7), (12, 19)]
    assert all(ev.hit_by == ("detector:email",) for ev in engine.coverage)
    assert all(ev.match_type == "content" for ev in engine.coverage)


def test_coverage_trace_disabled_by_default():
    s = Strategy.model_validate(_strategy(
        [{"id": "e", "name": "e", "match": {"detectors": ["email"]}, "action": "mask"}],
        risk_detectors=[]))
    engine = RedactionEngine(s, KEY)
    engine.process_record({"m": "a@b.com"}, 0)
    assert engine.coverage == []


def test_coverage_trace_never_contains_values():
    engine = _trace_engine([{"id": "p", "name": "p",
                             "match": {"value_patterns": [r"SECRET-\d{3}"]},
                             "action": "delete"}])
    engine.process_record({"m": "x SECRET-123 y"}, 0)
    blob = repr(engine.coverage)
    assert "SECRET" not in blob and r"\d" not in blob


# ---------- 基线一致性与改名 ----------


def test_identical_strategies_empty_diff(client):
    body = _diff(client, SAMPLE_STRATEGY, SAMPLE_STRATEGY, content=sample_ndjson())
    assert body["passed"] is True
    assert _zeros(body["summary"])
    for cat in ("coverage_gained", "coverage_lost", "action_changes",
                "winner_changes", "type_changes", "risks_new", "risks_resolved"):
        assert body[cat] == []
    assert body["truncated"] == []
    assert body["key_fingerprint"].startswith("sha256:")
    # 未设限时三项门槛均为 limit=null 且通过
    assert {c["name"] for c in body["checks"]} == {
        "new_risks", "lost_coverage", "type_changes"}
    assert all(c["limit"] is None and c["passed"] for c in body["checks"])


def test_rule_name_only_change_is_not_a_diff(client):
    renamed = json.loads(json.dumps(SAMPLE_STRATEGY))
    renamed["rules"][0]["name"] = "完全不同的名字"
    body = _diff(client, SAMPLE_STRATEGY, renamed, content=sample_ndjson())
    assert _zeros(body["summary"]), body["summary"]
    assert body["passed"] is True


def test_rule_rewrite_same_handling_is_winner_change_not_coverage_gain(client):
    """仅规则换名（id+name 变化）而处理一致：记胜出规则变化，不算覆盖改善。"""
    baseline = _strategy([{"id": "mail-old", "name": "旧邮箱规则",
                           "match": {"detectors": ["email"]}, "action": "mask"}])
    candidate = _strategy([{"id": "mail-new", "name": "新邮箱规则",
                            "match": {"detectors": ["email"]}, "action": "mask"}])
    body = _diff(client, baseline, candidate)
    assert body["summary"]["coverage_gained"] == 0
    assert body["summary"]["coverage_lost"] == 0
    assert body["summary"]["winner_changes"] == 1
    w = body["winner_changes"][0]
    assert w["from_rule_id"] == "mail-old" and w["to_rule_id"] == "mail-new"
    assert w["action"] == "mask"
    assert w["location"]["field_path"] == "$.m"
    assert (w["location"]["span_start"], w["location"]["span_end"]) == (0, 7)


# ---------- 覆盖增减与动作变化 ----------


def test_coverage_gained_when_candidate_adds_rule(client):
    baseline = _strategy([{"id": "e", "name": "e",
                           "match": {"detectors": ["email"]}, "action": "mask"}])
    candidate = _strategy([
        {"id": "e", "name": "e", "match": {"detectors": ["email"]}, "action": "mask"},
        {"id": "ip", "name": "ip", "match": {"detectors": ["ipv4"]},
         "action": "tokenize"},
    ])
    body = _diff(client, baseline, candidate,
                 content='{"m": "from 10.0.0.1"}\n')
    assert body["summary"]["coverage_gained"] == 1
    item = body["coverage_gained"][0]
    assert item["rule_id"] == "ip" and item["action"] == "tokenize"
    assert item["hit_by"] == ["detector:ipv4"]
    assert (item["location"]["span_start"], item["location"]["span_end"]) == (5, 13)
    assert item["location"]["line_no"] == 1
    assert body["passed"] is True


def test_coverage_lost_gate_blocks_ci(client):
    baseline = _strategy([{"id": "e", "name": "e",
                           "match": {"detectors": ["email"]}, "action": "mask"}])
    candidate = _strategy([{"id": "noop", "name": "n",
                            "match": {"key_names": ["zzz"]}, "action": "mask"}])
    body = _diff(client, baseline, candidate,
                 limits={"max_lost_coverage": 0})
    assert body["summary"]["coverage_lost"] == 1
    assert body["passed"] is False
    chk = {c["name"]: c for c in body["checks"]}["lost_coverage"]
    assert chk == {"name": "lost_coverage", "limit": 0, "actual": 1,
                   "passed": False}
    # 放宽到 1 则放行
    body2 = _diff(client, baseline, candidate,
                  limits={"max_lost_coverage": 1})
    assert body2["passed"] is True


def test_action_change_same_position(client):
    baseline = _strategy([{"id": "p", "name": "p",
                           "match": {"detectors": ["phone"]}, "action": "tokenize"}])
    candidate = _strategy([{"id": "p", "name": "p",
                            "match": {"detectors": ["phone"]}, "action": "delete"}])
    body = _diff(client, baseline, candidate,
                 content='{"m": "call 13800001234"}\n')
    assert _zeros({k: v for k, v in body["summary"].items()
                   if k in ("coverage_gained", "coverage_lost", "winner_changes")})
    assert body["summary"]["action_changes"] == 1
    ac = body["action_changes"][0]
    assert (ac["from_action"], ac["to_action"]) == ("tokenize", "delete")
    assert (ac["location"]["span_start"], ac["location"]["span_end"]) == (5, 16)


def test_field_rule_vs_content_rule_alignment(client):
    """基线整字段掩码、候选仅内容命中：未覆盖部分计失去，重叠部分计动作变化。"""
    baseline = _strategy([{"id": "f", "name": "f",
                           "match": {"field_paths": ["$.m"]}, "action": "mask"}],
                         risk_detectors=[])
    candidate = _strategy([{"id": "e", "name": "e",
                            "match": {"detectors": ["email"]}, "action": "tokenize"}],
                          risk_detectors=[])
    body = _diff(client, baseline, candidate, content='{"m": "x a@b.com y"}\n')
    s = body["summary"]
    assert (s["action_changes"], s["coverage_lost"], s["coverage_gained"]) == (1, 2, 0)
    spans = sorted((i["location"]["span_start"], i["location"]["span_end"])
                   for i in body["coverage_lost"])
    assert spans == [(0, 2), (9, 11)]


# ---------- 规则顺序变化的重叠命中稳定对齐 ----------


def test_rule_reorder_overlapping_hits_align_stably(client):
    """交换两条重叠内容规则的顺序：只有争议区间产生一条动作变化，不多算覆盖。"""
    rules = [
        {"id": "digits", "name": "d", "match": {"value_patterns": [r"\d{4,8}"]},
         "action": "mask"},
        {"id": "phone", "name": "p", "match": {"detectors": ["phone"]},
         "action": "tokenize"},
    ]
    baseline = _strategy(rules, risk_detectors=[])
    candidate = _strategy(list(reversed(rules)), risk_detectors=[])
    body = _diff(client, baseline, candidate,
                 content='{"m": "call 13800001234 now"}\n')
    s = body["summary"]
    assert s["coverage_gained"] == 0 and s["coverage_lost"] == 0
    assert s["action_changes"] == 1 and s["winner_changes"] == 0
    ac = body["action_changes"][0]
    # digits 命中 [5,13)，phone 命中 [5,16)；争议区间只有 [5,13)
    assert (ac["location"]["span_start"], ac["location"]["span_end"]) == (5, 13)
    assert (ac["from_rule_id"], ac["to_rule_id"]) == ("digits", "phone")
    assert (ac["from_action"], ac["to_action"]) == ("mask", "tokenize")


def test_rule_reorder_same_action_is_winner_change(client):
    """同动作的重叠规则交换顺序：争议区间记胜出规则变化而非动作变化。"""
    rules = [
        {"id": "digits", "name": "d", "match": {"value_patterns": [r"\d{4,8}"]},
         "action": "tokenize"},
        {"id": "phone", "name": "p", "match": {"detectors": ["phone"]},
         "action": "tokenize"},
    ]
    baseline = _strategy(rules, risk_detectors=[])
    candidate = _strategy(list(reversed(rules)), risk_detectors=[])
    body = _diff(client, baseline, candidate,
                 content='{"m": "call 13800001234 now"}\n')
    s = body["summary"]
    assert s["action_changes"] == 0 and s["winner_changes"] == 1
    assert s["coverage_gained"] == 0 and s["coverage_lost"] == 0
    w = body["winner_changes"][0]
    assert (w["from_rule_id"], w["to_rule_id"]) == ("digits", "phone")
    assert w["action"] == "tokenize"


# ---------- 输出类型变化 ----------


def test_output_type_change_gate(client):
    baseline = _strategy([{"id": "t", "name": "t",
                           "match": {"key_names": ["n"]}, "action": "tokenize"}],
                         risk_detectors=[])
    candidate = _strategy([{"id": "t", "name": "t",
                            "match": {"key_names": ["n"]}, "action": "delete"}],
                          risk_detectors=[])
    body = _diff(client, baseline, candidate, content='{"n": 13800001234}\n',
                 limits={"max_type_changes": 0})
    assert body["summary"]["type_changes"] == 1
    tc = body["type_changes"][0]
    assert (tc["from_type"], tc["to_type"]) == ("number", "null")
    assert tc["location"]["field_path"] == "$.n"
    assert body["passed"] is False
    assert {c["name"]: c["passed"] for c in body["checks"]}["type_changes"] is False


def test_no_type_change_when_tokenizing_number(client):
    """数值令牌化保持 number 类型：候选丢失该处理也不产生类型变化。"""
    baseline = _strategy([{"id": "t", "name": "t",
                           "match": {"key_names": ["n"]}, "action": "tokenize"}],
                         risk_detectors=[])
    candidate = _strategy([{"id": "noop", "name": "n",
                            "match": {"key_names": ["zzz"]}, "action": "mask"}],
                          risk_detectors=[])
    body = _diff(client, baseline, candidate, content='{"n": 12345}\n')
    assert body["summary"]["coverage_lost"] == 1
    assert body["summary"]["type_changes"] == 0


# ---------- 残留风险增减 ----------


def test_new_residual_risk_gate(client):
    baseline = _strategy([{"id": "e", "name": "e",
                           "match": {"detectors": ["email"]}, "action": "mask"}])
    candidate = _strategy([{"id": "noop", "name": "n",
                            "match": {"key_names": ["zzz"]}, "action": "mask"}])
    body = _diff(client, baseline, candidate, limits={"max_new_risks": 0})
    assert body["summary"]["risks_new"] == 1
    item = body["risks_new"][0]
    assert item["detector"] == "email" and item["count"] == 1
    assert item["location"]["field_path"] == "$.m"
    assert body["passed"] is False


def test_resolved_residual_risk(client):
    candidate = _strategy([{"id": "e", "name": "e",
                            "match": {"detectors": ["email"]}, "action": "mask"}])
    baseline = _strategy([{"id": "noop", "name": "n",
                           "match": {"key_names": ["zzz"]}, "action": "mask"}])
    body = _diff(client, baseline, candidate)
    assert body["summary"]["risks_resolved"] == 1
    assert body["summary"]["risks_new"] == 0
    assert body["risks_resolved"][0]["detector"] == "email"
    assert body["passed"] is True


def test_risk_items_aggregated_by_position_and_detector(client):
    """同一位置同一识别器的多条残留合并为一个差异项，计数为条数。"""
    baseline = _strategy([{"id": "e", "name": "e",
                           "match": {"detectors": ["email"]}, "action": "mask"}])
    candidate = _strategy([{"id": "noop", "name": "n",
                            "match": {"key_names": ["zzz"]}, "action": "mask"}])
    body = _diff(client, baseline, candidate,
                 content='{"m": "a@b.com c@d.org"}\n')
    assert body["summary"]["risks_new"] == 2
    assert len(body["risks_new"]) == 1
    assert body["risks_new"][0]["count"] == 2


# ---------- NDJSON 空行与格式 ----------


def test_ndjson_blank_lines_keep_physical_line_numbers(client):
    baseline = _strategy([{"id": "e", "name": "e",
                           "match": {"detectors": ["email"]}, "action": "mask"}])
    candidate = _strategy([{"id": "noop", "name": "n",
                            "match": {"key_names": ["zzz"]}, "action": "mask"}])
    content = '{"m": "a@b.com"}\n\n\n{"m": "c@d.org"}\n'
    body = _diff(client, baseline, candidate, content=content)
    line_nos = sorted(i["location"]["line_no"] for i in body["coverage_lost"])
    assert line_nos == [1, 4]
    risk_lines = sorted(i["location"]["line_no"] for i in body["risks_new"])
    assert risk_lines == [1, 4]


def test_json_format_has_no_line_numbers(client):
    baseline = _strategy([{"id": "e", "name": "e",
                           "match": {"detectors": ["email"]}, "action": "mask"}])
    candidate = _strategy([{"id": "noop", "name": "n",
                            "match": {"key_names": ["zzz"]}, "action": "mask"}])
    body = _diff(client, baseline, candidate,
                 content=json.dumps({"m": "a@b.com"}), fmt="json")
    assert body["coverage_lost"][0]["location"]["line_no"] is None
    assert body["risks_new"][0]["location"]["line_no"] is None


def test_top_level_scalar_record(client):
    baseline = _strategy([{"id": "f", "name": "f",
                           "match": {"field_paths": ["$"]}, "action": "delete"}],
                         risk_detectors=[])
    candidate = _strategy([{"id": "noop", "name": "n",
                            "match": {"key_names": ["zzz"]}, "action": "mask"}],
                          risk_detectors=[])
    body = _diff(client, baseline, candidate, content='"plain text"\n')
    assert body["coverage_lost"][0]["location"]["field_path"] == "$"
    assert body["summary"]["type_changes"] == 1
    tc = body["type_changes"][0]
    assert (tc["from_type"], tc["to_type"]) == ("null", "string")


# ---------- 安全与副作用 ----------


def test_diff_response_never_leaks_values_or_patterns(client):
    baseline = _strategy(
        [{"id": "p", "name": "p", "match": {"value_patterns": [r"SECRET-\d{3}-[A-Z]+"]},
          "action": "delete"}],
        risk_detectors=[])
    candidate = _strategy([{"id": "noop", "name": "n",
                            "match": {"key_names": ["zzz"]}, "action": "mask"}],
                          risk_detectors=[])
    r = client.post("/api/v1/strategies/diff",
                    json=_payload(baseline, candidate,
                                  content='{"m": "has SECRET-123-ABC here"}\n'))
    assert r.status_code == 200
    blob = r.text
    assert "SECRET-123-ABC" not in blob
    assert r"SECRET-\d{3}-[A-Z]+" not in blob
    assert "has " not in blob  # 处理后文本同样不回显


def test_diff_does_not_persist_anything(client, isolated_data):
    baseline = _strategy([{"id": "e", "name": "e",
                           "match": {"detectors": ["email"]}, "action": "mask"}])
    _diff(client, baseline, SAMPLE_STRATEGY, content=sample_ndjson())
    # 不生成任何输出文件（先于会惰性建目录的列表接口断言）
    data_dir = isolated_data["data_dir"]
    assert not (data_dir / "jobs").exists()
    assert not (data_dir / "streams").exists()
    # 不产生作业、不写数据库
    assert client.get("/api/v1/jobs").json()["total"] == 0
    assert client.get("/api/v1/stream-jobs").json()["total"] == 0


# ---------- 错误处理与文档 ----------


def test_invalid_ndjson_reports_line(client):
    r = client.post("/api/v1/strategies/diff",
                    json=_payload(SAMPLE_STRATEGY, SAMPLE_STRATEGY,
                                  content='{"a": 1}\n{broken}\n'))
    assert r.status_code == 422
    assert r.json()["detail"]["line"] == 2


def test_invalid_strategy_422(client):
    bad = {"name": "bad", "rules": [
        {"id": "BAD ID", "name": "x", "match": {}, "action": "delete"}]}
    r = client.post("/api/v1/strategies/diff",
                    json=_payload(bad, SAMPLE_STRATEGY))
    assert r.status_code == 422
    r2 = client.post("/api/v1/strategies/diff",
                     json=_payload(SAMPLE_STRATEGY, bad))
    assert r2.status_code == 422


def test_invalid_limit_422(client):
    r = client.post("/api/v1/strategies/diff",
                    json=_payload(SAMPLE_STRATEGY, SAMPLE_STRATEGY,
                                  limits={"max_new_risks": -1}))
    assert r.status_code == 422


def test_openapi_documents_diff_route(client):
    spec = client.get("/openapi.json").json()
    assert "/api/v1/strategies/diff" in spec["paths"]
    op = spec["paths"]["/api/v1/strategies/diff"]["post"]
    assert "strategy" in op["tags"]
    schema_names = spec["components"]["schemas"]
    for name in ("StrategyDiffRequest", "StrategyDiffResponse", "DiffLocation",
                 "CoverageDiffItem", "RiskDiffItem", "DiffCheck"):
        assert name in schema_names
