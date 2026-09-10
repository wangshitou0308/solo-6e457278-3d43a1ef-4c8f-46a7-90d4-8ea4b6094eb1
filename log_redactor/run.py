#!/usr/bin/env python3
"""一键启动本地脱敏 API。

用法：
    python run.py                 # 默认 127.0.0.1:8080
    PORT=9000 python run.py       # 自定义端口
    python run.py --host 0.0.0.0 --port 9000
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import uvicorn  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="启动本地日志脱敏 API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    print(f"▶  本地日志脱敏 API: http://{args.host}:{args.port}/docs")
    print("   健康检查: /healthz  示例策略: GET /api/v1/sample/strategy")
    uvicorn.run("redactor.app:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
