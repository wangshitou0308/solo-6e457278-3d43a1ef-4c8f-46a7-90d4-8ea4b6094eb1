"""运行期配置。

所有配置均可通过环境变量覆盖；默认全部落到本地目录，离线可用。
"""
from __future__ import annotations

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


settings = Settings.load()
