"""运行期配置。

所有配置均可通过环境变量覆盖；默认全部落到本地目录，离线可用。
配置惰性加载：仅在真正初始化数据库/密钥时创建数据目录，
import 包本身不会在文件系统留下任何东西。
"""
from __future__ import annotations

import functools
import os
from dataclasses import dataclass
from pathlib import Path


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    db_path: Path
    key_path: Path
    key_env: str = "REDACTOR_MASTER_KEY"

    @classmethod
    def load(cls) -> "Settings":
        data_dir = Path(_env("REDACTOR_DATA_DIR", str(Path.cwd() / "data")))
        data_dir.mkdir(parents=True, exist_ok=True)
        return cls(
            data_dir=data_dir,
            db_path=data_dir / "redactor.db",
            key_path=data_dir / "master.key",
        )


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.load()


def reset_settings_cache() -> None:
    """测试辅助：环境变量变化后丢弃缓存。"""
    get_settings.cache_clear()


class _LazySettings:
    """模块级 ``settings`` 的惰性代理：首次访问属性时才真正建目录。"""

    def __getattr__(self, name: str) -> object:
        return getattr(get_settings(), name)


settings = _LazySettings()
