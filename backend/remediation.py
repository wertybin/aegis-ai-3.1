"""AegisAI V2 Remediation Center (PHASE 6).

Explicit approval, immutable timestamped backups, verified changes and
rollback. The V1 ``/api/apply-patch`` endpoint remains unchanged; this module
adds an auditable workflow on top without breaking that contract.
"""

import hashlib
import json
import shutil
import threading
import uuid
from datetime import datetime
from pathlib import Path

from backend import history
from backend.auditor import apply_remediation_patch

BASE_DIR = Path(__file__).resolve().parent.parent
LAB_DIR = BASE_DIR / "sample_vulnerable_app"
BACKUP_DIR = BASE_DIR / "reports" / "backups"
LEDGER_FILE = BACKUP_DIR / "remediation_ledger.json"
APPROVAL_TTL_SECONDS = 600

_lock = threading.RLock()
_approvals: dict[str, dict] = {}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ensure() -> None:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def _read_ledger() -> list[dict]:
    _ensure()
    if not LEDGER_FILE.exists():
        return []
    try:
        data = json.loads(LEDGER_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _write_ledger(items: list[dict]) -> None:
    _ensure()
    LEDGER_FILE.write_text(json.dumps(items[:200], ensure_ascii=False, indent=2), encoding="utf-8")


def _find_audit(scan_id: str | None = None) -> dict | None:
    if scan_id:
        record = history.get_scan(scan_id)
        if record:
            result = record.get("result") or {}
            return result.get("audit") or (result if "findings" in result else None)
        return None
    for record in history.read_scans():
        result = record.get("result") or {}
        audit = result.get("audit") or (result if "findings" in result else None)
        if audit and audit.get("findings"):
            return audit
    return None


def list_proposals(scan_id: str | None = None) -> list[dict]:
    """Returns real proposed patches from an actual completed scan audit."""
    audit = _find_audit(scan_id)
    if not audit:
        return []
    source_path = str(audit.get("file_path") or "")
    resolved_source = Path(source_path).resolve() if source_path else None
    if resolved_source is None or LAB_DIR not in resolved_source.parents or not resolved_source.exists():
        return []
    proposals = []
    for index, finding in enumerate(audit.get("findings", []) or [], start=1):
        resolved = resolved_source
        proposals.append(
            {
                "id": f"PROP-{index:03d}",
                "title": finding.get("title", ""),
                "severity": finding.get("severity", ""),
                "endpoint": finding.get("endpoint", ""),
                "explanation": finding.get("explanation", ""),
                "file_path": str(resolved),
                "file_name": resolved.name,
                "vulnerable_snippet": finding.get("vulnerable_snippet", ""),
                "patched_snippet": finding.get("patched_snippet", ""),
                "source_scan_id": scan_id or "latest",
            }
        )
    return proposals


def create_approval(proposal_ids: list[str], note: str = "") -> dict:
    """Records an explicit user approval. No remediation happens here."""
    if not proposal_ids:
        raise ValueError("Select at least one recommendation to approve.")
    valid_ids = {p["id"] for p in list_proposals()}
    if not set(proposal_ids).issubset(valid_ids):
        raise ValueError("The approved recommendations do not match real scan results.")
    with _lock:
        approval_id = f"APPR-{uuid.uuid4().hex[:10]}"
        approval = {
            "id": approval_id,
            "proposal_ids": list(dict.fromkeys(proposal_ids)),
            "note": note[:500],
            "created_at": _now(),
            "status": "approved",
            "used": False,
        }
        _approvals[approval_id] = approval
        return dict(approval)


def _verify_approval(approval_id: str, proposal_id: str | None = None) -> dict:
    with _lock:
        approval = _approvals.get(approval_id)
        if not approval:
            raise PermissionError("Approval record not found.")
        if approval["status"] != "approved" or approval["used"]:
            raise PermissionError("This approval was already used or revoked.")
        created = datetime.fromisoformat(approval["created_at"])
        if (datetime.now() - created).total_seconds() > APPROVAL_TTL_SECONDS:
            approval["status"] = "expired"
            raise PermissionError("The approval has expired; approve again.")
    if proposal_id and proposal_id not in approval["proposal_ids"]:
        raise PermissionError("Approval was not granted for this recommendation.")
    return dict(approval)


def _create_backup(path: Path, reason: str) -> dict:
    _ensure()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_path = BACKUP_DIR / f"{path.stem}_{stamp}{path.suffix}.backup"
    shutil.copy2(path, backup_path)
    return {
        "id": backup_path.name,
        "path": str(backup_path),
        "source_file": str(path),
        "sha256": _sha256(backup_path),
        "reason": reason[:200],
        "created_at": _now(),
    }


def apply_approved(approval_id: str, file_path: str, proposal_id: str | None = None) -> dict:
    """Applies defensive patches only against a valid, explicit approval."""
    approval = _verify_approval(approval_id, proposal_id)
    target = Path(file_path).resolve()
    if LAB_DIR not in target.parents:
        raise PermissionError("This file is outside the lab scope; the patch cannot be applied.")
    if not target.exists():
        raise FileNotFoundError("Target file not found.")

    approved_files = {
        p["file_path"] for p in list_proposals() if p["id"] in approval["proposal_ids"]
    }
    if approved_files and str(target) not in approved_files:
        raise PermissionError("The approved recommendations do not belong to this file.")

    before_hash = _sha256(target)
    backup = _create_backup(target, f"approval={approval_id}")
    ok, message = apply_remediation_patch(target)
    after_hash = _sha256(target)
    changed = before_hash != after_hash

    entry = {
        "id": f"REM-{uuid.uuid4().hex[:10]}",
        "action": "apply",
        "approval_id": approval_id,
        "proposal_ids": approval["proposal_ids"],
        "file_path": str(target),
        "backup_id": backup["id"],
        "before_sha256": before_hash,
        "after_sha256": after_hash,
        "changed": changed,
        "message": message,
        "created_at": _now(),
    }
    with _lock:
        entries = _read_ledger()
        entries.insert(0, entry)
        _write_ledger(entries)
        if ok and changed:
            _approvals[approval_id]["used"] = True

    return {**entry, "ok": bool(ok and changed), "backup": backup}


def list_backups() -> list[dict]:
    _ensure()
    items = []
    for path in sorted(BACKUP_DIR.glob("*.backup"), reverse=True):
        items.append(
            {
                "id": path.name,
                "path": str(path),
                "size_bytes": path.stat().st_size,
                "created_at": datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"),
            }
        )
    return items


def rollback(backup_id: str) -> dict:
    """Restores a source file from an immutable backup and records the action."""
    candidate = (BACKUP_DIR / backup_id).resolve()
    if BACKUP_DIR not in candidate.parents or not candidate.exists():
        raise FileNotFoundError("Backup not found.")
    ledger = _read_ledger()
    source = None
    for entry in ledger:
        if entry.get("backup_id") == backup_id:
            source = Path(entry["file_path"])
            break
    if source is None:
        # Derive the original file name from the backup name (stem_suffix).
        name = backup_id.split("_", 1)[0]
        guesses = [LAB_DIR / f"{name}.py", LAB_DIR / f"{name}"]
        source = next((g for g in guesses if g.exists()), None)
    if source is None or LAB_DIR not in source.parents:
        raise ValueError("Could not determine the source file that owns the backup.")

    restore_hash = _sha256(candidate)
    shutil.copy2(candidate, source)
    entry = {
        "id": f"ROL-{uuid.uuid4().hex[:10]}",
        "action": "rollback",
        "backup_id": backup_id,
        "file_path": str(source),
        "restored_sha256": restore_hash,
        "created_at": _now(),
    }
    with _lock:
        entries = _read_ledger()
        entries.insert(0, entry)
        _write_ledger(entries)
    return entry


def list_ledger() -> list[dict]:
    return _read_ledger()
