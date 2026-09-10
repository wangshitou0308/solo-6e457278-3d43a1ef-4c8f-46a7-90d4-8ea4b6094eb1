"""共享 fixtures：临时数据目录、隔离密钥与数据库。"""
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def isolated_data(tmp_path, monkeypatch):
    monkeypatch.setenv("REDACTOR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("REDACTOR_MASTER_KEY", raising=False)

    # 重新加载 settings 与 app 级单例
    import importlib

    from redactor import config
    importlib.reload(config)

    from redactor import crypto, database, app as app_mod
    importlib.reload(crypto)
    importlib.reload(database)
    importlib.reload(app_mod)

    yield {
        "data_dir": config.settings.data_dir,
        "app": app_mod.app,
        "settings": config.settings,
    }


@pytest.fixture()
def fixed_key(monkeypatch):
    """固定测试密钥，保证令牌可预测。"""
    monkeypatch.setenv("REDACTOR_MASTER_KEY", "unit-test-master-key-0123456789")
    from redactor.crypto import MasterKey
    return MasterKey.load()
