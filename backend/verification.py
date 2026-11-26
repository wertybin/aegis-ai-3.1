"""AegisAI V2 Fix Verification (PHASE 7).

Re-analyzes the exact source file that was remediated. The "before" state is
computed from the immutable timestamped backup recorded by the remediation
ledger; the "after" state is computed from the current source bytes. Both
audits use the same static analyzer as the V1 audit, and both files carry
sha256 provenance. No result is simulated or inferred.
"""

import hashlib
import json
import shutil
import tempfile
import threading
import uuid
from datetime import datetime
from pathlib import Path

from backend.auditor import analyze_source_file
from backend.remediation import BACKUP_DIR, LAB_DIR, list_ledger

BASE_DIR = Path(__file__).resolve().parent.parent
VERIFICATIONS_FILE = BASE_DIR / "reports" / "verifications.json"
_lock = threading.RLock()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_verifications() -> list[dict]:
    if not VERIFICATIONS_FILE.exists():
        return []
    try:
        data = json.loads(VERIFICATIONS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _write_verifications(items: list[dict]) -> None:
    VERIFICATIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    VERIFICATIONS_FILE.write_text(
        json.dumps(items[:100], ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _finding_key(finding: dict) -> tuple[str, str, str]:
    return (
        str(finding.get("id", "")),
        str(finding.get("title", "")),
        str(finding.get("endpoint", "")),
    )


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        severity = str(finding.get("severity", "LOW")).upper()
        if severity in counts:
            counts[severity] += 1
    return counts


def _details(keys: set, mapping: dict) -> list[dict]:
    return [
        {
            "id": mapping[key].get("id"),
            "title": mapping[key].get("title"),
            "severity": mapping[key].get("severity"),
            "endpoint": mapping[key].get("endpoint"),
        }
        for key in sorted(keys, key=str)
    ]


def list_verifications(limit: int = 20) -> list[dict]:
    return _read_verifications()[: max(1, min(limit, 100))]


def latest_verification() -> dict | None:
    items = _read_verifications()
    return items[0] if items else None


def verify_apply(apply_id: str | None = None, backup_id: str | None = None) -> dict:
    """Verifies one real remediation against its immutable backup."""
    applies = [
        entry
        for entry in list_ledger()
        if entry.get("action") == "apply" and entry.get("changed") is True
    ]
    if apply_id:
        entry = next((e for e in applies if e.get("id") == apply_id), None)
    elif backup_id:
        entry = next((e for e in applies if e.get("backup_id") == backup_id), None)
    else:
        entry = applies[0] if applies else None

    if entry is None:
        raise ValueError("No verifiable successful patch record was found.")

    backup = (BACKUP_DIR / str(entry["backup_id"])).resolve()
    if BACKUP_DIR not in backup.parents or not backup.exists():
        raise FileNotFoundError("Patch backup not found; verification cannot be performed.")

    source = Path(str(entry["file_path"])).resolve()
    if LAB_DIR not in source.parents or not source.exists():
        raise ValueError("The source file is outside the lab scope or does not exist.")

    backup_hash = _sha256(backup)
    source_hash = _sha256(source)
    integrity = {
        "backup_sha256": backup_hash,
        "source_sha256": source_hash,
        "backup_matches_ledger": backup_hash == entry.get("before_sha256"),
        "source_matches_ledger": source_hash == entry.get("after_sha256"),
        "drift": (
            "none"
            if source_hash == entry.get("after_sha256")
            else "source_changed_since_apply (rollback or later edit)"
        ),
    }

    # Both audits are computed from real bytes with the same analyzer used by
    # the V1 static audit. The temporary copy keeps the original file name.
    with tempfile.TemporaryDirectory(prefix="aegis_verify_") as tmp_dir:
        before_file = Path(tmp_dir) / source.name
        shutil.copy2(backup, before_file)
        before_audit = analyze_source_file(before_file)
    after_audit = analyze_source_file(source)

    before_map = {_finding_key(f): f for f in before_audit["findings"]}
    after_map = {_finding_key(f): f for f in after_audit["findings"]}
    fixed_keys = set(before_map) - set(after_map)
    open_keys = set(before_map) & set(after_map)
    new_keys = set(after_map) - set(before_map)

    fixed = _details(fixed_keys, before_map)
    still_open = _details(open_keys, after_map)
    introduced = _details(new_keys, after_map)

    before_score = int(before_audit["score"])
    after_score = int(after_audit["score"])
    open_high = sum(1 for f in still_open if f.get("severity") in {"CRITICAL", "HIGH"})

    if introduced:
        status = "REGRESSION_DETECTED"
    elif not fixed:
        status = "NO_CHANGE"
    elif not open_high and after_score > before_score:
        status = "VERIFIED_FIXED"
    elif fixed:
        status = "PARTIALLY_VERIFIED"
    else:
        status = "UNKNOWN"

    record = {
        "id": f"VER-{uuid.uuid4().hex[:10]}",
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "engine": "aegis-fix-verifier-v1",
        "status": status,
        "policy": (
            "Before: the real patch backup and the current source file are rescanned with the same static analysis. "
            "Both SHA-256 values are recorded, and the finding sets are compared "
            "to list fixed, remaining and newly introduced findings."
        ),
        "apply_id": entry.get("id"),
        "backup_id": entry.get("backup_id"),
        "approval_id": entry.get("approval_id"),
        "file_path": str(source),
        "file_name": source.name,
        "integrity": integrity,
        "before": {
            "score": before_score,
            "finding_count": len(before_audit["findings"]),
            "severity_counts": _severity_counts(before_audit["findings"]),
            "endpoint_count": len(before_audit.get("endpoints", [])),
        },
        "after": {
            "score": after_score,
            "finding_count": len(after_audit["findings"]),
            "severity_counts": _severity_counts(after_audit["findings"]),
            "endpoint_count": len(after_audit.get("endpoints", [])),
        },
        "score_delta": after_score - before_score,
        "fixed": fixed,
        "still_open": still_open,
        "introduced": introduced,
        "evidence_note": (
            "Before/after audits were computed from the real backup and the real "
            "current source file; no simulated finding was used."
        ),
    }

    with _lock:
        items = _read_verifications()
        items.insert(0, record)
        _write_verifications(items)
    return record
