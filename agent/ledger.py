"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

Interface bắt buộc:
    append(entry: dict, path: pathlib.Path) -> dict
    verify(path: pathlib.Path) -> bool
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _compute_hash(data: dict) -> str:
    """Tính SHA256 hex digest của dict (loại trừ field 'hash', sắp xếp keys)."""
    record = {k: v for k, v in data.items() if k != "hash"}
    encoded = json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Ghi thêm một entry vào audit ledger với hash chain.
    
    Tự động thêm `prev_hash` và `hash`.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists() and path.stat().st_size > 0:
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            last_entry = json.loads(lines[-1])
            prev_hash = last_entry.get("hash", "0" * 64)

    record = dict(entry)
    record["prev_hash"] = prev_hash
    record["hash"] = _compute_hash(record)

    line = json.dumps(record, ensure_ascii=False) + "\n"
    with path.open("a", encoding="utf-8") as f:
        f.write(line)

    return record


def verify(path: Path) -> bool:
    """Kiểm tra tính toàn vẹn của audit ledger.
    
    Trả về True nếu:
      - Mọi entry có reason non-empty
      - prev_hash của dòng n khớp với hash của dòng n-1 (dòng đầu là '0'*64)
      - hash của dòng n khớp với hash tính lại từ nội dung dòng đó
    """
    path = Path(path)
    if not path.exists():
        return True

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return True

    lines = [line.strip() for line in content.splitlines() if line.strip()]
    expected_prev = "0" * 64

    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False

        reason = entry.get("reason")
        if not reason or not str(reason).strip():
            return False

        if entry.get("prev_hash") != expected_prev:
            return False

        stored_hash = entry.get("hash")
        computed_hash = _compute_hash(entry)
        if stored_hash != computed_hash:
            return False

        expected_prev = stored_hash

    return True
