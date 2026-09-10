"""脱敏引擎与识别器单元测试。"""
from __future__ import annotations

import pytest

from redactor.crypto import MasterKey
from redactor.detectors import (
    DETECTORS,
    _find_bank_card,
    _find_email,
    _find_id_card,
    _find_ipv4,
    _find_ipv6,
    _find_phone,
)
from redactor.engine import glob_to_regex, run_strategy
from redactor.models import Rule, Strategy


KEY = MasterKey(b"0" * 32)


def strat(rules, risk_detectors=None) -> Strategy:
    return Strategy(
        name="t",
        rules=[Rule(**r) for r in rules],
        risk_detectors=risk_detectors or [],
    )


# ---------- 识别器 ----------


@pytest.mark.parametrize(
    "finder,text,expected",
    [
        (_find_email, "a@b.com x a.b+c@sub.example.co.uk", ["a@b.com", "a.b+c@sub.example.co.uk"]),
        (_find_phone, "call 13800001234 or 23800001234 no", ["13800001234"]),
        (_find_ipv4, "from 10.0.0.1 and 256.1.1.1", ["10.0.0.1"]),
        (_find_ipv6, "via 2001:db8::1 done", ["2001:db8::1"]),
        (_find_id_card, "id 11010519491231002X bad 110105194912310029", ["11010519491231002X"]),
        (_find_bank_card, "card 6222020200001111117 end", ["6222020200001111117"]),
    ],
)
def test_detectors(finder, text, expected):
    got = [text[s:e] for s, e in finder(text)]
    assert got == expected


def test_access_token_detectors():
    from redactor.detectors import _find_access_token

    text = 'Authorization: Bearer abc123def456 and api_key="0123456789abcdef0123"'
    spans = _find_access_token(text)
    hits = {text[s:e] for s, e in spans}
    assert "abc123def456" in hits
    assert "0123456789abcdef0123" in hits


def test_all_detectors_registered():
    assert {"email", "phone", "ipv4", "ipv6", "access_token", "id_card", "bank_card"} <= set(DETECTORS)


# ---------- 路径通配 ----------


@pytest.mark.parametrize(
    "pattern,path,hit",
    [
        ("$.user.email", "user.email", True),
        ("user.email", "user.email", True),
        ("**.email", "user.email", True),
        ("**.email", "user.contacts[2].email", True),
        ("*.ip", "client.ip", True),
        ("*.ip", "meta.client.ip", False),
        ("items[*].id", "items[0].id", True),
        ("items[*].id", "items[12].id", True),
        ("items[?].id", "items[0].id", True),
        ("items[?].id", "items[00].id", False),
    ],
)
def test_glob(pattern, path, hit):
    rx = glob_to_regex(pattern)
    assert (rx.fullmatch(path) is not None) == hit


# ---------- 动作与结构 ----------


def test_delete_mask_tokenize_actions_preserve_structure():
    data = [
        {"email": "a@b.com", "phone": "13800001234", "password": "x",
         "nested": [{"ip": "1.2.3.4", "ok": True}], "count": 42},
    ]
    s = strat([
        {"id": "del", "name": "d", "match": {"key_names": ["password"]}, "action": "delete"},
        {"id": "mask-email", "name": "me", "match": {"key_names": ["email"]},
         "action": "mask", "keep_prefix": 1},
        {"id": "tok-phone", "name": "tp", "match": {"key_names": ["phone"]},
         "action": "tokenize"},
        {"id": "mask-ip", "name": "mi",
         "match": {"field_paths": ["**.ip"]}, "action": "mask"},
    ])
    res = run_strategy(s, data, KEY)
    r = res.records[0]
    assert set(r.keys()) == {"email", "phone", "password", "nested", "count"}
    assert r["password"] is None                      # 删除保留键结构
    assert r["email"].startswith("a") and "@" not in r["email"]
    assert r["phone"].startswith("T-")
    assert r["nested"][0]["ip"] == "*******"
    assert r["nested"][0]["ok"] is True
    assert r["count"] == 42
    assert res.stats.by_action == {"delete": 1, "mask": 2, "tokenize": 1}


def test_numeric_mask_keeps_type():
    s = strat([{"id": "m", "name": "m",
                "match": {"key_names": ["phone_num"]},
                "action": "mask", "keep_prefix": 2, "keep_suffix": 2}])
    res = run_strategy(s, [{"phone_num": 13800001234}], KEY)
    val = res.records[0]["phone_num"]
    assert isinstance(val, int)
    assert str(val).startswith("13") and str(val).endswith("34")


def test_float_mask_respects_sign_and_point():
    s = strat([{"id": "m", "name": "m",
                "match": {"key_names": ["balance"]},
                "action": "mask", "keep_prefix": 1, "keep_suffix": 2}])
    res = run_strategy(s, [{"balance": -9876.54}], KEY)
    val = res.records[0]["balance"]
    assert isinstance(val, float)
    assert str(val) == "-9000.54"


def test_deterministic_token_same_value_same_token_across_batch():
    s = strat([{"id": "tok", "name": "t",
                "match": {"key_names": ["phone"]}, "action": "tokenize"}])
    data = [{"phone": "13800001234"}, {"x": [{"phone": "13800001234"}]}, {"phone": "other"}]
    res = run_strategy(s, data, KEY)
    t1 = res.records[0]["phone"]
    t2 = res.records[1]["x"][0]["phone"]
    assert t1 == t2 and t1.startswith("T-")
    assert res.records[2]["phone"] != t1


def test_same_value_same_token_even_when_hitting_different_rules():
    # 回归：同一值即使命中不同规则（字段规则 vs 内容规则、不同规则 id），
    # 整批中也必须使用同一替身
    s = strat([
        {"id": "rule-field", "name": "字段令牌化",
         "match": {"key_names": ["phone"]}, "action": "tokenize"},
        {"id": "rule-text", "name": "文本识别令牌化",
         "match": {"detectors": ["phone"]}, "action": "tokenize"},
    ])
    data = [
        {"phone": "13800001234"},
        {"message": "call 13800001234"},
        {"deep": [{"phone": "13800001234"}]},
    ]
    res = run_strategy(s, data, KEY)
    t1 = res.records[0]["phone"]
    t2 = res.records[1]["message"].split()[-1]
    t3 = res.records[2]["deep"][0]["phone"]
    assert t1 == t2 == t3
    assert t1.startswith("T-")
    # 审计中确实是两条不同规则命中的
    rule_ids = {a.rule_id for a in res.audit}
    assert rule_ids == {"rule-field", "rule-text"}


def test_tokenization_preserves_value_type():
    # 回归：令牌化后必须保留原值类型
    s = strat([
        {"id": "tok", "name": "t",
         "match": {"key_names": ["phone", "amount", "ratio", "flag", "empty"]},
         "action": "tokenize"},
    ])
    data = [{"phone": 13800001234, "amount": -4200, "ratio": 0.25,
             "flag": True, "empty": None}]
    res = run_strategy(s, data, KEY)
    r = res.records[0]
    assert isinstance(r["phone"], int)
    assert len(str(abs(r["phone"]))) == len("13800001234")
    assert str(r["amount"]).startswith("-")
    assert isinstance(r["amount"], int)
    assert isinstance(r["ratio"], float)
    assert r["flag"] is True       # bool 不令牌化
    assert r["empty"] is None      # None 不令牌化


def test_numeric_token_deterministic_across_batch():
    s = strat([
        {"id": "a", "name": "a", "match": {"key_names": ["phone"]},
         "action": "tokenize"},
        {"id": "b", "name": "b", "match": {"key_patterns": ["mobile"]},
         "action": "tokenize"},
    ])
    res = run_strategy(s, [{"phone": 13800001234}, {"mobile": 13800001234}], KEY)
    assert res.records[0]["phone"] == res.records[1]["mobile"]
    assert isinstance(res.records[0]["phone"], int)


def test_content_rules_only_replace_hit_spans():
    s = strat([
        {"id": "em", "name": "e", "match": {"detectors": ["email"]},
         "action": "mask"},
        {"id": "ph", "name": "p", "match": {"detectors": ["phone"]},
         "action": "tokenize"},
    ])
    msg = "mail a@b.com or call 13800001234 please"
    res = run_strategy(s, [{"message": msg}], KEY)
    out = res.records[0]["message"]
    assert "mail " in out and " or call T-" in out and " please" in out
    assert "a@b.com" not in out


def test_overlapping_rules_first_wins_and_span_consumed():
    # phone 内容规则先定义，access_token 后定义；同一字符区间只被处理一次
    s = strat([
        {"id": "ph", "name": "p", "match": {"detectors": ["phone"]},
         "action": "tokenize"},
        {"id": "tok", "name": "t", "match": {"detectors": ["access_token"]},
         "action": "delete"},
    ])
    res = run_strategy(s, [{"m": "13800001234"}], KEY)
    assert res.records[0]["m"].startswith("T-")


def test_content_rule_scoped_by_field_path():
    s = strat([
        {"id": "only-msg", "name": "o",
         "match": {"field_paths": ["$.message"], "detectors": ["email"]},
         "action": "delete"},
    ])
    res = run_strategy(s, [{"message": "a@b.com", "other": "a@b.com"}], KEY)
    assert res.records[0]["message"] == ""
    assert res.records[0]["other"] == "a@b.com"


def test_value_regex_rule():
    s = strat([
        {"id": "digits", "name": "d",
         "match": {"value_patterns": [r"\d{4}"]}, "action": "mask"},
    ])
    res = run_strategy(s, [{"m": "code 1234 ok"}], KEY)
    assert "1234" not in res.records[0]["m"]
    # 审计只记录序号，不包含原始正则文本
    assert res.audit[0].hit_by == ["value_pattern#1"]


def test_audit_hit_by_never_leaks_regex_source():
    # 回归：审计不得通过 hit_by 写入原始正则文本
    secret_pattern = r"SECRET-\d{3}-[A-Z]+"
    s = strat([
        {"id": "pat", "name": "p",
         "match": {"value_patterns": [secret_pattern]}, "action": "delete"},
    ])
    res = run_strategy(s, [{"m": "x SECRET-123-ABC y"}], KEY)
    blob = repr(res.audit)
    assert secret_pattern not in blob
    assert "SECRET-123-ABC" not in blob
    assert res.audit[0].hit_by == ["value_pattern#1"]


def test_content_replacements_no_offset_leftovers():
    # 回归：多条内容规则、替换长度不一致时，
    # 统一按起点降序替换，不能因位置偏移留下已命中的原文
    s = strat([
        {"id": "ip", "name": "ip", "match": {"detectors": ["ipv4"]},
         "action": "mask"},  # 等长替换
        {"id": "mail", "name": "mail", "match": {"detectors": ["email"]},
         "action": "delete"},  # 缩短替换
        {"id": "ph", "name": "ph", "match": {"detectors": ["phone"]},
         "action": "tokenize"},  # 变长替换
    ])
    text = "a a@b.com 10.0.0.1 13800001234 z c@d.org 255.1.2.3"
    res = run_strategy(s, [{"m": text}], KEY)
    out = res.records[0]["m"]
    for leftover in ["a@b.com", "c@d.org", "10.0.0.1", "255.1.2.3", "13800001234"]:
        assert leftover not in out, f"残留原文: {leftover} -> {out}"
    # 安全上下文前缀 a / z 仍保留，IP 被等宽掩码
    assert out.startswith("a ")
    assert out.rstrip("*").rstrip().endswith("z")
    assert "********" in out


def test_content_replacements_with_different_lengths_and_ordering():
    # 相邻命中 + 变长/缩短替换混合，逐字符核对输出，专门防止位移缺陷
    s = strat([
        {"id": "mail", "name": "mail", "match": {"detectors": ["email"]},
         "action": "tokenize"},  # 变长（29 字符）
        {"id": "ip", "name": "ip", "match": {"detectors": ["ipv4"]},
         "action": "delete"},   # 缩短
        {"id": "ph", "name": "ph", "match": {"detectors": ["phone"]},
         "action": "mask"},     # 等长
    ])
    text = "x a@b.com|10.0.0.1|13800001234|y"
    res = run_strategy(s, [{"m": text}], KEY)
    out = res.records[0]["m"]
    assert "a@b.com" not in out and "10.0.0.1" not in out and "13800001234" not in out
    assert out.startswith("x T-")
    assert out.endswith("||" + "*" * 11 + "|y")
    # 三条审计，occurrences 各 1
    by_rule = {a.rule_id: a.occurrences for a in res.audit}
    assert by_rule == {"mail": 1, "ip": 1, "ph": 1}


def test_same_span_same_token_field_and_content():
    # 同一段文字被字段规则与内容规则令牌化时替身一致（已在
    # test_same_value_same_token_even_when_hitting_different_rules 覆盖跨记录，
    # 这里再覆盖字符串确定性）
    s = strat([
        {"id": "f", "name": "f", "match": {"key_names": ["p"]},
         "action": "tokenize"},
        {"id": "c", "name": "c", "match": {"detectors": ["phone"]},
         "action": "tokenize"},
    ])
    res = run_strategy(s, [{"p": "13800001234"}, {"m": "x13800001234y"}], KEY)
    assert res.records[0]["p"] in res.records[1]["m"]


def test_audit_never_contains_raw_value():
    raw = "secret@example.com"
    s = strat([{"id": "e", "name": "e", "match": {"detectors": ["email"]},
                "action": "tokenize"}])
    res = run_strategy(s, [{"m": raw}], KEY)
    blob = repr(res.audit)
    assert raw not in blob and "secret" not in blob


def test_needs_review_flags_residual_risk_and_skips_handled_fields():
    # 邮箱字段已掩码 => 不报残留；未处理字段中的邮箱 => 需复核
    s = strat(
        [{"id": "me", "name": "me", "match": {"key_names": ["email"]},
          "action": "mask", "keep_prefix": 1}],
        risk_detectors=["email"],
    )
    res = run_strategy(s, [{"email": "alice@example.com",
                            "note": "cc bob@example.com"}], KEY)
    assert res.needs_review is True
    assert [r.field_path for r in res.risks] == ["$.note"]


def test_disabled_rules_skipped():
    s = strat([{"id": "me", "name": "me", "match": {"key_names": ["email"]},
                "action": "delete", "enabled": False}])
    res = run_strategy(s, [{"email": "a@b.com"}], KEY)
    assert res.records[0]["email"] == "a@b.com"
    assert res.audit == []


def test_ndjson_line_no_recorded():
    s = strat([{"id": "me", "name": "me", "match": {"detectors": ["email"]},
                "action": "delete"}])
    data = [{"m": "a@b.com"}, {"m": "c@d.com"}]
    res = run_strategy(s, data, KEY, is_ndjson=True)
    assert [a.line_no for a in res.audit] == [1, 2]


def test_ndjson_strings_inside_list_structure_preserved():
    s = strat([{"id": "e", "name": "e", "match": {"detectors": ["email"]},
                "action": "delete"}])
    data = [{"tags": ["x", "a@b.com", "y"]}]
    res = run_strategy(s, data, KEY)
    assert res.records[0]["tags"] == ["x", "", "y"]


# ---------- 策略校验 ----------


def test_invalid_regex_rejected():
    with pytest.raises(Exception):
        Rule(id="r1", name="r", match={"key_patterns": ["("]}, action="delete")


def test_unknown_detector_rejected():
    with pytest.raises(Exception):
        Rule(id="r1", name="r", match={"detectors": ["nope"]}, action="delete")


def test_duplicate_rule_ids_rejected():
    with pytest.raises(Exception):
        Strategy(name="x", rules=[
            Rule(id="r1", name="r", match={"key_names": ["a"]}, action="delete"),
            Rule(id="r1", name="r", match={"key_names": ["b"]}, action="delete"),
        ])


def test_rule_requires_match_dimension():
    with pytest.raises(Exception):
        Rule(id="r1", name="r", match={}, action="delete")
