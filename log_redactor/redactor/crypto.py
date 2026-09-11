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

令牌关联域（``token_context``）
* 传入上下文时，域标识为 ``HMAC-SHA256(主密钥, 上下文)``（不可逆，
  上下文原文不持久化），域子密钥为 ``HMAC-SHA256(主密钥, 域标识)``；
  令牌算法不变，只换密钥，因此不同上下文下同一原值必为不同替身。
* 未传上下文走全局域，直接使用主密钥，替身与历史行为逐字节一致。
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

# ---------- 令牌关联域（token_context） ----------
# 上下文原文只参与一次 HMAC 即被丢弃，只有域标识（不可逆摘要）会被持久化；
# 域派生子密钥再经一次带独立标签的 HMAC 得到，与主密钥及全局命名空间隔离。
_DOMAIN_ID_NAMESPACE = "token-domain-id-v1"
_DOMAIN_KEY_NAMESPACE = "token-domain-key-v1"

#: 关联域上下文最大长度（字符数）
MAX_TOKEN_CONTEXT = 128
#: 全局域（未传 token_context）的域指纹
GLOBAL_DOMAIN_FINGERPRINT = "global"


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


# ---------- 令牌关联域 ----------


def normalize_token_context(token_context: str | None) -> str | None:
    """规范化调用方提交的关联域上下文。

    去首尾空白；空串/纯空白/未传等价（返回 None，走全局域）。
    非字符串由调用方/Pydantic 拦截，这里只处理字符串。
    """
    if token_context is None:
        return None
    text = token_context.strip()
    return text or None


def validate_token_context(token_context: str | None) -> str | None:
    """规范化并校验关联域上下文；超过 128 字符抛 ``ValueError``。

    非法请求必须在创建任何文件或数据库记录之前被拦下。
    """
    text = normalize_token_context(token_context)
    if text is not None and len(text) > MAX_TOKEN_CONTEXT:
        raise ValueError(f"token_context 最长 {MAX_TOKEN_CONTEXT} 个字符")
    return text


def domain_identifier(key: MasterKey, token_context: str | None) -> bytes | None:
    """由主密钥与上下文原文计算不可逆域标识（HMAC-SHA256 全 32 字节）。

    全局域（未传上下文）返回 None；上下文原文不持久化、不进日志，
    仅凭域标识无法逆推出上下文。
    """
    if token_context is None:
        return None
    return key.digest(_DOMAIN_ID_NAMESPACE, "ctx:" + token_context)


def domain_id_hex(key: MasterKey, token_context: str | None) -> str | None:
    tag = domain_identifier(key, token_context)
    return tag.hex() if tag is not None else None


def domain_fingerprint(domain_id: bytes | str | None) -> str:
    """对外展示的域指纹：全局域为 ``global``，隔离域为 ``dom:<前 8 字节 hex>``。

    输入可为 :func:`domain_identifier` 的字节结果，也可为持久化的 hex 串。
    """
    if domain_id is None:
        return GLOBAL_DOMAIN_FINGERPRINT
    if isinstance(domain_id, str):
        domain_id = bytes.fromhex(domain_id)
    return "dom:" + domain_id[:8].hex()


def derive_domain_key(master: MasterKey, domain_id: bytes | str) -> MasterKey:
    """由主密钥与域标识派生出域专属子密钥（32 字节）。

    HMAC 派生子密钥不可逆推主密钥；不同域的子密钥相互独立，
    因而同一原值在不同上下文下必为不同替身。
    """
    if isinstance(domain_id, str):
        domain_id = bytes.fromhex(domain_id)
    return MasterKey(master.digest(_DOMAIN_KEY_NAMESPACE, domain_id.hex()))


def resolve_token_domain(
    master: MasterKey,
    token_context: str | None = None,
    *,
    domain_id: bytes | str | None = None,
) -> tuple[MasterKey, str, bytes | None]:
    """解析令牌关联域，返回 ``(生效密钥, 域指纹, 域标识)``。

    * 未传上下文（全局域）：直接使用主密钥、指纹 ``global``、域标识 None；
    * 隔离域：上下文优先（在线请求路径），或由持久化的域标识恢复
      （worker/重启续跑路径，此时上下文原文已不可得）。

    全局域的替身与历史行为逐字节一致（同一 HMAC 命名空间）。
    """
    if token_context is None and domain_id is None:
        return master, GLOBAL_DOMAIN_FINGERPRINT, None
    if domain_id is None:
        domain_id = domain_identifier(master, token_context)
    assert domain_id is not None
    if isinstance(domain_id, str):
        domain_id_bytes = bytes.fromhex(domain_id)
    else:
        domain_id_bytes = domain_id
    return (
        derive_domain_key(master, domain_id_bytes),
        domain_fingerprint(domain_id_bytes),
        domain_id_bytes,
    )
