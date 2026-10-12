"""BƯỚC 3c — trifecta split + egress allowlist (13').

Interface bắt buộc:
    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import pii, tools
from agent.ledger import append as append_ledger
from agent.policy import PolicyContext, check as policy_check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
PRINCIPALS_PATH = DATA_DIR / "principals.json"
CUSTOMERS_PATH = DATA_DIR / "customers.json"


def _hash_args(args: any) -> str:
    encoded = json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    """Xử lý yêu cầu người dùng qua kiến trúc Trifecta Split + OBO + Audit Ledger."""
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    agent_id = "lab24-agent"
    now_utc = datetime.now(timezone.utc)
    expires_at = (now_utc + timedelta(minutes=15)).isoformat()

    principals_data = {}
    if PRINCIPALS_PATH.exists():
        try:
            principals_data = json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass

    principal_allowed_tools = tuple(principals_data.get(principal_id, {}).get("allowed_tools", []))

    # --- RUN A: Search docs (Untrusted content boundary) ---
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs", "read_customer", "http_post"),
        parent_scopes=(),
        expires_at=expires_at,
    )
    allow_search, reason_search = policy_check(ctx_search)
    append_ledger({
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "run_id": run_id,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
        "tool": "search_docs",
        "args_hash": _hash_args({"query": message}),
        "classification": "internal",
        "decision": "allow" if allow_search else "deny",
        "reason": reason_search,
    }, ledger_path)

    if not allow_search:
        return "Yêu cầu tìm kiếm bị từ chối bởi chính sách bảo mật."

    docs = tools.search_docs(message)

    # Trích xuất ticket ID dạng số NGUYÊN từ TÊN FILE (không đọc từ free text của attacker)
    ticket_ids: list[int] = []
    for d in docs:
        m = re.search(r"ticket-(\d+)", d["id"])
        if m:
            ticket_ids.append(int(m.group(1)))

    # Kiểm tra dấu hiệu injection trên văn bản tổng hợp
    combined_raw_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_raw_text)

    # --- RUN B: Private data store (Trifecta Split boundary) ---
    # Chỉ ánh xạ customer_id từ NGUỒN TIN CẬY (related_tickets trong data/customers.json)
    customers_data = []
    if CUSTOMERS_PATH.exists():
        try:
            customers_data = json.loads(CUSTOMERS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass

    ticket_id_set = set(ticket_ids)
    matched_customers: list[str] = []
    for c in customers_data:
        cust_tickets = set(c.get("related_tickets", []))
        if cust_tickets & ticket_id_set:
            matched_customers.append(c["customer_id"])

    collected_records = []
    for cid in matched_customers:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("search_docs", "read_customer"),
            parent_scopes=principal_allowed_tools,
            expires_at=expires_at,
        )
        allow_read, reason_read = policy_check(ctx_read)
        append_ledger({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": "read_customer",
            "args_hash": _hash_args({"customer_id": cid}),
            "classification": "restricted",
            "decision": "allow" if allow_read else "deny",
            "reason": reason_read,
        }, ledger_path)

        if allow_read:
            try:
                rec = tools.read_customer(cid)
                collected_records.append(rec)
            except tools.ToolError:
                pass

    # Nếu có chỉ thị injection, kiểm tra PEP đối với egress http_post
    if injected is not None:
        target_url = injected.target_url or "http://127.0.0.1:10024/reconcile"
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="reconciliation",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=("search_docs", "read_customer", "http_post"),
            parent_scopes=principal_allowed_tools,
            expires_at=expires_at,
        )
        allow_post, reason_post = policy_check(ctx_post)
        append_ledger({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": "http_post",
            "args_hash": _hash_args({"url": target_url}),
            "classification": "restricted",
            "decision": "allow" if allow_post else "deny",
            "reason": reason_post,
        }, ledger_path)

        if allow_post:
            tools.http_post(target_url, {"records": collected_records})

    return llm.summarize(docs)
