"""内置示例策略与示例日志（也会同步写到 examples/ 目录）。"""
from __future__ import annotations

import copy
import json

SAMPLE_STRATEGY: dict = {
    "name": "backend-incident-sample",
    "version": "1.0",
    "description": "后端故障样本提交前的示例脱敏策略：删除凭据、掩码邮箱/IP、确定性令牌化手机号与令牌、掩码身份证。",
    "rules": [
        {
            "id": "delete-credentials",
            "name": "删除凭据类字段",
            "description": "密码、密钥、Authorization 等字段整字段删除",
            "match": {
                "key_names": ["password", "passwd", "authorization", "secret", "api_key"],
                "key_globs": ["*_secret", "*secret*", "*token*", "*password*"],
            },
            "action": "delete",
        },
        {
            "id": "mask-email-field",
            "name": "掩码邮箱字段",
            "match": {"field_paths": ["**.email", "$.email", "**.mail"]},
            "action": "mask",
            "mask_char": "*",
            "keep_prefix": 1,
            "keep_suffix": 0,
        },
        {
            "id": "tokenize-phone-field",
            "name": "令牌化手机号字段",
            "match": {"key_names": ["phone", "mobile", "tel", "telephone"]},
            "action": "tokenize",
        },
        {
            "id": "mask-email-in-text",
            "name": "掩码自由文本中的邮箱",
            "match": {"detectors": ["email"]},
            "action": "mask",
            "mask_char": "*",
            "keep_prefix": 1,
            "keep_suffix": 0,
        },
        {
            "id": "scan-phone-in-text",
            "name": "令牌化文本中的手机号",
            "match": {"detectors": ["phone"]},
            "action": "tokenize",
        },
        {
            "id": "mask-ip-in-text",
            "name": "掩码文本中的 IP 地址",
            "match": {"detectors": ["ipv4", "ipv6"]},
            "action": "mask",
            "mask_char": "*",
        },
        {
            "id": "tokenize-access-token",
            "name": "令牌化访问令牌",
            "match": {"detectors": ["access_token"]},
            "action": "tokenize",
        },
        {
            "id": "mask-id-card",
            "name": "掩码身份证号",
            "match": {"detectors": ["id_card"]},
            "action": "mask",
            "mask_char": "*",
            "keep_prefix": 6,
            "keep_suffix": 4,
        },
    ],
    "risk_detectors": ["email", "phone", "ipv4", "access_token", "id_card", "bank_card"],
}

SAMPLE_RECORDS: list[dict] = [
    {
        "ts": "2026-09-10T08:12:03Z",
        "level": "ERROR",
        "service": "order-api",
        "user": {
            "id": 10086,
            "email": "zhangsan@example.com",
            "phone": "13800001234",
            "password": "Pa$$w0rd!",
        },
        "client_ip": "10.23.56.78",
        "message": (
            "user zhangsan@example.com login failed from 10.23.56.78, "
            "contact 13800001234; bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMDA4NiJ9.s9K2mXq7"
        ),
        "upstream": {"authorization": "Bearer abc.def.ghi", "addr": "2001:db8::1"},
    },
    {
        "ts": "2026-09-10T08:12:09Z",
        "level": "WARN",
        "service": "pay-gateway",
        "operator": {
            "name": "lisi",
            "mail": "lisi@corp.example.cn",
            "mobile": "15912345678",
            "id_card": "11010519491231002X",
        },
        "note": "refund card 6222020200001111117 pending",
        "access_token": "ak_live_9f2a7c4e1b8d46a09f3e5c7d8a1b2e4f",
    },
    {
        "ts": "2026-09-10T08:12:15Z",
        "level": "INFO",
        "service": "order-api",
        "user": {"id": 10086, "email": "zhangsan@example.com", "phone": "13800001234"},
        "client_ip": "10.23.56.79",
        "message": "retry for same user — 同一敏感值应得到同一替身令牌",
    },
]


def sample_strategy_dict() -> dict:
    return copy.deepcopy(SAMPLE_STRATEGY)


def sample_ndjson() -> str:
    return "\n".join(json.dumps(r, ensure_ascii=False) for r in SAMPLE_RECORDS) + "\n"


def sample_json() -> str:
    return json.dumps(SAMPLE_RECORDS, ensure_ascii=False, indent=2)
