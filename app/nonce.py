"""一次性 CSP 随机数生成。"""
from __future__ import annotations

import secrets


def generate_nonce(num_bytes: int = 18) -> str:
    """生成 base64 编码的密码学随机数；每次调用结果不同。

    使用 ``secrets`` 提供的 CSPRNG，18 字节即 144 位熵，
    足以满足 CSP nonce “不可预测、一次性”的要求。
    """
    if num_bytes < 16:
        raise ValueError("nonce 至少需要 16 字节（128 位）熵")
    return secrets.token_urlsafe(num_bytes)
