"""基于本地密钥的确定性令牌化。

设计要点
--------
* 同一明文（连同其原始类型）在整批乃至跨作业中始终映射到同一令牌；
  **不区分命中的规则**——同一值即使被不同规则命中也得到同一替身，
  便于在整批数据中追踪同一敏感实体。
* 替身保留原值类型：字符串 -> ``T-xxxx`` 字符串；整数 -> 等宽（必要时扩宽）
  的正整数；浮点数 -> 保留符号/小数点结构的浮点；bool/None 不令牌化。
* 采用 HMAC-SHA256(key, namespace || value) 作为伪随机源；HMAC 不可逆推
  原值，且无需联网、无第三方服务。
* 密钥来自环境变量 ``REDACTOR_MASTER_KEY``；缺省时在数据目录生成
  一份 **32 字节原始随机**密钥（文件权限 600），删除该文件即令全部
  历史令牌失效。文件密钥按原始字节读取，绝不做 strip/解码改写。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import stat
from pathlib import Path

from . import config

_TOKEN_BYTES = 18  # 144 bit，碰撞概率可忽略；输出为 29 个 base32 字符

# 全局统一命名空间：令牌映射与规则无关，保证跨规则一致性
_TOKEN_NAMESPACE = "deterministic-token-v1"


class MasterKeyError(ValueError):
    pass


class MasterKey:
    """加载/生成并持有本地主密钥。

    * 环境变量密钥按 UTF-8 文本处理，允许任意长度 >= 16 字节；
    * 文件密钥固定为 32 字节原始字节，逐字节读取不做 strip；
    * 既有文件加载时强制把权限收紧为 0600。
    """

    FILE_KEY_BYTES = 32

    def __init__(self, raw: bytes) -> None:
        if not isinstance(raw, (bytes, bytearray)) or len(raw) < 16:
            raise MasterKeyError("主密钥长度至少 16 字节")
        self._raw = bytes(raw)

    @classmethod
    def load(cls) -> "MasterKey":
        env_value = os.environ.get(config.settings.key_env)
        if env_value:
            return cls(env_value.encode("utf-8"))

        key_path: Path = config.settings.key_path
        if key_path.exists():
            raw = key_path.read_bytes()  # 原始 32 字节，不 strip、不解码
            if len(raw) != cls.FILE_KEY_BYTES:
                raise MasterKeyError(
                    f"密钥文件 {key_path} 必须是 {cls.FILE_KEY_BYTES} 字节原始密钥，"
                    f"实际 {len(raw)} 字节；请删除后重新生成或改用 "
                    f"{config.settings.key_env} 环境变量"
                )
            # 收紧既有文件权限：仅属主可读写
            current = stat.S_IMODE(key_path.stat().st_mode)
            if current != 0o600:
                os.chmod(key_path, 0o600)
        else:
            raw = secrets.token_bytes(cls.FILE_KEY_BYTES)
            key_path.parent.mkdir(parents=True, exist_ok=True)
            # 先以 0600 创建，避免短暂的宽松权限窗口
            fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, raw)
            finally:
                os.close(fd)
            os.chmod(key_path, 0o600)
        return cls(raw)

    def digest(self, namespace: str, value: str) -> bytes:
        return hmac.new(
            self._raw,
            f"{namespace}\x00{value}".encode("utf-8"),
            hashlib.sha256,
        ).digest()


def encode_text_token(data: bytes) -> str:
    """生成形如 ``T-7YQK4P...`` 的令牌（RFC4648 base32，无填充）。"""
    return "T-" + base64.b32encode(data).decode("ascii").rstrip("=")


def deterministic_token(key: MasterKey, value: str) -> str:
    """对字符串值生成确定性、不可逆、跨规则一致的替身令牌。"""
    tag = key.digest(_TOKEN_NAMESPACE, "str:" + value)
    return encode_text_token(tag[:_TOKEN_BYTES])


def deterministic_number_token(key: MasterKey, value: int | float) -> int | float:
    """对数值生成保持类型的确定性替身。

    整数替身保留位数宽度（空间不足时扩到可容纳的最小宽度）且不以 0 开头；
    浮点替身保留符号、位数与小数点位置。
    """
    if isinstance(value, bool):  # bool 是 int 的子类，按约定不令牌化
        return value
    text = str(value)
    tag = key.digest(_TOKEN_NAMESPACE, "num:" + text)
    n_digits = sum(c.isdigit() for c in text)
    digit_stream = "".join(f"{b:03d}" for b in tag)  # 十进制数字流，长度恒为 768
    stream = (digit_stream * (n_digits // len(digit_stream) + 1))[:n_digits]
    if isinstance(value, int):
        token_text = stream
        if token_text[0] == "0":
            token_text = "1" + token_text[1:]
        token = int(("-" if value < 0 else "") + token_text)
        return token

    # float：保留 '-' 与 '.' 的结构，只替换数字位
    out: list[str] = []
    di = 0
    for ch in text:
        if ch.isdigit():
            # 整数部分首位避免 0，保持宽度与可解析性
            if di == 0 and stream[0] == "0":
                out.append("1")
            else:
                out.append(stream[di])
            di += 1
        else:
            out.append(ch)
    return float("".join(out))


def key_fingerprint(key: MasterKey) -> str:
    """主密钥指纹（仅用于审计展示，不泄露密钥本身）。"""
    fp = key.digest("fingerprint", "master-key-v1")
    return "sha256:" + fp[:8].hex()
