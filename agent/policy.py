"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Interface bắt buộc:
    check(context: PolicyContext) -> tuple[bool, str]
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"

_CACHED_PRINCIPALS: dict | None = None


def _get_principals() -> dict:
    global _CACHED_PRINCIPALS
    if _CACHED_PRINCIPALS is None:
        if PRINCIPALS_PATH.exists():
            _CACHED_PRINCIPALS = json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
        else:
            _CACHED_PRINCIPALS = {}
    return _CACHED_PRINCIPALS


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách bảo mật trước khi thực thi tool call.
    
    Luôn trả về (allow, reason) và reason KHÔNG BAO GIỜ để trống.
    """
    # 1. Rule TỐI THIỂU bắt buộc: restricted data + egress enabled -> DENY
    if context.data_classification == "restricted" and context.egress_enabled is True:
        return False, "Chính sách tối thiểu: Nghiêm cấm egress đối với dữ liệu classified restricted"

    # 2. Kiểm tra thời hạn hiệu lực (expires_at)
    if context.expires_at:
        try:
            exp_dt = datetime.fromisoformat(context.expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt <= datetime.now(timezone.utc):
                return False, f"Yêu cầu đã hết hạn tại mốc thời gian {context.expires_at}"
        except Exception:
            return False, f"Định dạng expires_at không hợp lệ: {context.expires_at}"

    # 3. Kiểm tra danh tính principal (OBO)
    if context.principal_id:
        principals = _get_principals()
        if context.principal_id not in principals:
            return False, f"Principal không tồn tại hoặc không xác định: {context.principal_id}"

        principal_info = principals[context.principal_id]

        # Kiểm tra mục đích (purpose) nếu có khai báo
        allowed_purposes = principal_info.get("purposes", [])
        if context.request_purpose and allowed_purposes and context.request_purpose not in allowed_purposes:
            return False, f"Mục đích '{context.request_purpose}' không được phép cho principal '{context.principal_id}'"

        # Kiểm tra tool được phép (effective permissions = allowed_tools ∩ agent_scopes ∩ parent_scopes)
        if context.requested_tool:
            principal_allowed_tools = set(principal_info.get("allowed_tools", []))
            if context.requested_tool not in principal_allowed_tools:
                return False, f"Tool '{context.requested_tool}' không nằm trong quyền được phép của principal '{context.principal_id}'"

            if context.agent_scopes and context.requested_tool not in set(context.agent_scopes):
                return False, f"Tool '{context.requested_tool}' vượt quá agent_scopes của agent"

            if context.delegation_depth > 0 and context.parent_scopes and context.requested_tool not in set(context.parent_scopes):
                return False, f"Tool '{context.requested_tool}' vượt quá parent_scopes khi ủy quyền ở delegation_depth {context.delegation_depth}"

    return True, f"Yêu cầu hợp lệ: Cho phép '{context.requested_tool or 'thao tác'}' cho principal '{context.principal_id or 'hệ thống'}'"
