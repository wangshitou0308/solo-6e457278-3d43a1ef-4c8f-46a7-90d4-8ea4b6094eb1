"""共享 fixtures：临时数据目录、隔离密钥与数据库。

不使用 importlib.reload，避免重加载后类身份分裂；直接重建 settings 并替换
app 模块级单例（db / master_key）。
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1] / "log_redactor"
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def isolated_data(tmp_path, monkeypatch):
    monkeypatch.setenv("REDACTOR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("REDACTOR_MASTER_KEY", raising=False)

    from redactor import config, database, crypto, app as app_mod

    config.reset_settings_cache()
    new_settings = config.get_settings()
    # 用惰性单例的同一缓存对象，保证 app/config 各处引用一致
    monkeypatch.setattr(config, "settings", config._LazySettings())
    new_db = database.Database(new_settings.db_path)
    new_key = crypto.MasterKey.load()
    monkeypatch.setattr(app_mod, "db", new_db)
    monkeypatch.setattr(app_mod, "master_key", new_key)
    # app 的 getter 已被注入实例，直接返回
    monkeypatch.setattr(app_mod, "get_db", lambda: new_db)
    monkeypatch.setattr(app_mod, "get_master_key", lambda: new_key)

    yield {
        "data_dir": new_settings.data_dir,
        "app": app_mod.app,
        "settings": new_settings,
    }
