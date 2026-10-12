"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Interface bắt buộc:
    detect(text: str) -> list[dict]
    redact(text: str) -> str
"""
from __future__ import annotations

import re


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong văn bản (VN_CCCD, VN_BANK_ACCOUNT, VN_PHONE, EMAIL).
    
    Mỗi entity: {"type": str, "start": int, "end": int}
    """
    entities: list[dict] = []

    # 1. EMAIL
    for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # 2. VN_BANK_ACCOUNT: thường đứng sau "STK" hoặc "số tài khoản" (8-16 chữ số)
    for m in re.finditer(r"(?:STK|s\u1ed1\s+t\xe0i\s+kho\u1ea3n)\s+(\d{8,16})\b", text, re.IGNORECASE):
        entities.append({"type": "VN_BANK_ACCOUNT", "start": m.start(1), "end": m.end(1)})

    bank_spans = {(e["start"], e["end"]) for e in entities if e["type"] == "VN_BANK_ACCOUNT"}

    # 3. VN_CCCD: 12 chữ số liên tiếp (loại trừ nếu trùng span của số tài khoản)
    for m in re.finditer(r"\b\d{12}\b", text):
        if not any(s <= m.start() and m.end() <= e for s, e in bank_spans):
            entities.append({"type": "VN_CCCD", "start": m.start(), "end": m.end()})

    cccd_spans = {(e["start"], e["end"]) for e in entities if e["type"] == "VN_CCCD"}

    # 4. VN_PHONE: 10 chữ số bắt đầu bằng 0 (loại trừ nếu đã nằm trong CCCD hoặc STK)
    for m in re.finditer(r"\b0\d{9}\b", text):
        if not any(s <= m.start() and m.end() <= e for s, e in bank_spans | cccd_spans):
            entities.append({"type": "VN_PHONE", "start": m.start(), "end": m.end()})

    # Sắp xếp theo vị trí bắt đầu
    entities.sort(key=lambda x: (x["start"], x["end"]))
    return entities


def redact(text: str) -> str:
    """Thay thế mọi thực thể PII được phát hiện bằng [REDACTED_<TYPE>].
    
    Thay từ cuối văn bản về đầu để offset không bị lệch.
    """
    entities = detect(text)
    if not entities:
        return text

    # Khử trùng/chồng lấn (chọn entity dài hơn nếu chồng lấn)
    non_overlapping: list[dict] = []
    for ent in entities:
        if not non_overlapping:
            non_overlapping.append(ent)
            continue
        prev = non_overlapping[-1]
        if ent["start"] < prev["end"]:
            # Có overlap, giữ entity có độ dài lớn hơn
            if (ent["end"] - ent["start"]) > (prev["end"] - prev["start"]):
                non_overlapping[-1] = ent
        else:
            non_overlapping.append(ent)

    # Thay từ cuối về đầu
    result = text
    for ent in reversed(non_overlapping):
        start, end = ent["start"], ent["end"]
        replacement = f"[REDACTED_{ent['type']}]"
        result = result[:start] + replacement + result[end:]

    return result
