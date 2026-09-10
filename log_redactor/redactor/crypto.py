"""基于本地密钥的确定性令牌化。

设计要点
--------
* 同一明文（按字段的规范化字符串）在整批乃至跨作业中始终映射到同一令牌，
  便于保留跨记录的关联关系，同时不暴露原值。
* 采用 HMAC-SHA256(key, namespace || value) 截断后做可逆风格的
  "TOKEN-xxxx" 替身；HMAC 不可逆推原值，且无需联网、无第三方服务。
* 密钥来自环境变量 ``REDACTOR_MASTER_KEY``；缺省时在数据目录自动生成
  一份 32 字节随机密钥（文件权限 600），删除该文件即令全部历史令牌失效。
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

from .config import settings

_TOKEN_BYTES = 18  # 144 bit，碰撞概率可忽略；输出为 24 个 base32 字符


class MasterKey:
    """加载/生成并持有本地主密钥。"""

    def __init__(self, raw: bytes) -> None:
        if len(raw) < 16:
            raise ValueError("主密钥长度至少 16 字节")
        self._raw = raw

    @classmethod
    def load(cls) -> "MasterKey":
        env_value = os.environ.get(settings.key_env)
        if env_value:
            return cls(env_value.encode("utf-8"))

        key_path: Path = settings.key_path
        if key_path.exists():
            raw = key_path.read_bytes().strip()
        else:
            raw = secrets.token_bytes(32)
            key_path.write_bytes(raw)
            os.chmod(key_path, 0o600)
        return cls(raw)

    def digest(self, namespace: str, value: str) -> bytes:
        return hmac.new(
            self._raw,
            f"{namespace}\x00{value}".encode("utf-8"),
            hashlib.sha256,
        ).digest()


def _encode_token(data: bytes) -> str:
    """生成形如 ``T-7YQK4P...`` 的令牌（RFC4648 base32，无填充）。"""
    import base64

    return base64.b32encode(data).decode("ascii").rstrip("=")


def deterministic_token(key: MasterKey, namespace: str, value: str) -> str:
    """对 *value* 生成确定性、不可逆的替身令牌。

    namespace 通常是规则名或字段路径，避免 "13800000000" 在不同语义字段
    （手机号 vs 订单尾号）之间被等同。
    """
    tag = key.digest(namespace, value)
    return "T-" + _encode_token(tag[:_TOKEN_BYTES])


def key_fingerprint(key: MasterKey) -> str:
    """主密钥指纹（仅用于审计展示，不泄露密钥本身）。"""
    fp = key.digest("fingerprint", "master-key-v1")
    return "sha256:" + fp[:8].hex()
