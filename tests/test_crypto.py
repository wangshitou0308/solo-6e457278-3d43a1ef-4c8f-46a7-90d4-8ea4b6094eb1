"""主密钥加载与令牌化回归测试。"""
from __future__ import annotations

import os
import stat

import pytest

from redactor.crypto import (
    MasterKey,
    MasterKeyError,
    deterministic_number_token,
    deterministic_token,
)


def _write_key(path, raw: bytes, mode: int = 0o600):
    path.write_bytes(raw)
    os.chmod(path, mode)


def test_generated_key_is_32_bytes_mode_600(tmp_path, monkeypatch):
    monkeypatch.setenv("REDACTOR_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("REDACTOR_MASTER_KEY", raising=False)
    import importlib
    from redactor import config
    importlib.reload(config)

    key = MasterKey.load()
    key_path = config.settings.key_path
    assert key_path.exists()
    assert len(key_path.read_bytes()) == 32
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    # 再次加载得到同一密钥（确定性令牌一致）
    again = MasterKey.load()
    assert deterministic_token(key, "13800001234") == deterministic_token(again, "13800001234")


def test_existing_key_read_as_raw_32_bytes_without_strip(tmp_path, monkeypatch):
    # 密钥以换行/空格结尾时必须按原始字节使用，strip 会改变 HMAC 结果
    raw = bytes(range(1, 33))
    key_path = tmp_path / "master.key"
    _write_key(key_path, raw + b"\n")
    monkeypatch.setenv("REDACTOR_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("REDACTOR_MASTER_KEY", raising=False)
    import importlib
    from redactor import config
    importlib.reload(config)

    with pytest.raises(MasterKeyError):
        MasterKey.load()  # 33 字节：拒绝，而不是悄悄 strip 成 32 字节

    _write_key(key_path, raw, mode=0o644)
    key = MasterKey.load()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600  # 既有密钥权限收紧
    # 与直接用原始字节构造的密钥产生完全相同的 HMAC 令牌
    assert deterministic_token(key, "v") == deterministic_token(MasterKey(raw), "v")


def test_existing_key_permissions_tightened(tmp_path, monkeypatch):
    raw = b"a" * 32
    key_path = tmp_path / "master.key"
    _write_key(key_path, raw, mode=0o644)
    monkeypatch.setenv("REDACTOR_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("REDACTOR_MASTER_KEY", raising=False)
    import importlib
    from redactor import config
    importlib.reload(config)

    MasterKey.load()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_short_key_rejected():
    with pytest.raises(MasterKeyError):
        MasterKey(b"short")


def test_text_token_deterministic_and_type():
    key = MasterKey(b"k" * 32)
    t1 = deterministic_token(key, "abc")
    t2 = deterministic_token(key, "abc")
    t3 = deterministic_token(key, "abd")
    assert t1 == t2 and t1 != t3
    assert isinstance(t1, str) and t1.startswith("T-")


@pytest.mark.parametrize("value", [13800001234, 42, -9876543210, 0, -1, 100])
def test_integer_token_preserves_type_and_width(value):
    key = MasterKey(b"k" * 32)
    tok = deterministic_number_token(key, value)
    assert isinstance(tok, int)
    # 位数宽度必须精确保留（单数字 0/负数单数字同样保持一位）
    assert len(str(abs(tok))) == len(str(abs(value)))
    assert (tok < 0) == (value < 0)
    assert deterministic_number_token(key, value) == tok  # 确定性


def test_integer_token_no_leading_zero():
    key = MasterKey(b"k" * 32)
    for value in [10, 100, 1000, 4200, 13800001234]:
        tok = deterministic_number_token(key, value)
        assert not str(tok).lstrip("-").startswith("0")


def test_float_token_preserves_type_and_structure():
    key = MasterKey(b"k" * 32)
    tok = deterministic_number_token(key, -9876.54)
    assert isinstance(tok, float)
    assert tok < 0
    text = str(tok)
    assert "." in text
    before, after = text.lstrip("-").split(".")
    assert len(before) == 4 and len(after) == 2


def test_bool_not_tokenized_as_int():
    key = MasterKey(b"k" * 32)
    assert deterministic_number_token(key, True) is True
    assert deterministic_number_token(key, False) is False
