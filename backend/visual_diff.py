"""V3.1 — optional visual BEFORE/AFTER proof for authorized localhost targets.

Honest degradation is part of the design:
  * Playwright is OPTIONAL. If it is absent, capture_snapshot() reports
    available=False and never fabricates an image.
  * A visual difference alone NEVER marks a vulnerability as resolved. Only a
    verification scan can do that; the payload returned by image_diff() says so.

Screenshots and metadata are stored under reports/screenshots (gitignored).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

from backend.tool_registry import BASE_DIR
from backend.wsl_scanner import DastError, validate_dast_target

SCREENSHOT_DIR = BASE_DIR / "reports" / "screenshots"
META_FILE = SCREENSHOT_DIR / "snapshots.json"
VIEWPORT = {"width": 1440, "height": 900}


def playwright_status() -> dict:
    try:
        import playwright  # noqa: F401
        from playwright.sync_api import sync_playwright  # noqa: F401
    except ImportError as exc:
        return {
            "available": False,
            "browser": None,
            "install": "Optional: pip install playwright && python -m playwright install chromium",
            "error": type(exc).__name__,
        }
    return {"available": True, "browser": "chromium", "install": None, "error": None}


def _load_meta() -> list[dict]:
    try:
        data = json.loads(META_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _save_meta(items: list[dict]) -> None:
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    META_FILE.write_text(json.dumps(items[-40:], indent=2, ensure_ascii=False), encoding="utf-8")


def list_snapshots() -> dict:
    status = playwright_status()
    return {
        "ok": True,
        "available": status["available"],
        "install": status["install"],
        "viewport": VIEWPORT,
        "snapshots": list(reversed(_load_meta())),
        "policy": "Visual change alone never marks a finding resolved.",
    }


def capture_snapshot(target: str, label: str = "") -> dict:
    """Captures a real screenshot of an authorized localhost target."""
    status = playwright_status()
    if not status["available"]:
        return {"ok": False, "available": False, "error": "Playwright not installed", **status}
    try:
        safe_target = validate_dast_target(target)
    except DastError as exc:
        return {"ok": False, "available": False, "error": f"SCOPE BLOCKED: {exc}"}

    try:
        from playwright.sync_api import sync_playwright

        SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
        snapshot_id = "SS-" + datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + hashlib.sha1(
            f"{safe_target}{label}".encode("utf-8")
        ).hexdigest()[:4].upper()
        path = SCREENSHOT_DIR / f"{snapshot_id}.png"
        with sync_playwright() as engine:
            browser = engine.chromium.launch(headless=True)
            page = browser.new_page(viewport=VIEWPORT)
            page.goto(safe_target, wait_until="domcontentloaded", timeout=20000)
            page.screenshot(path=str(path), full_page=False)
            browser.close()
        meta = {
            "snapshot_id": snapshot_id,
            "scan_id": snapshot_id.rsplit("-", 1)[0],
            "ts": datetime.now().isoformat(),
            "target": safe_target,
            "label": str(label or "")[:80],
            "viewport": VIEWPORT,
            "path": str(path.relative_to(BASE_DIR)).replace("\\", "/"),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()[:16],
        }
        _save_meta(_load_meta() + [meta])
        return {"ok": True, "available": True, "snapshot": meta}
    except Exception as exc:
        return {
            "ok": False,
            "available": True,
            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
            "hint": "Run: python -m playwright install chromium",
        }


def _find(meta_id: str) -> dict | None:
    return next((item for item in _load_meta() if item.get("snapshot_id") == meta_id), None)


def image_diff(before_id: str, after_id: str) -> dict:
    """Real pixel comparison of two captured PNGs. No claim about fixing."""
    try:
        from PIL import Image, ImageChops
    except ImportError:
        return {"ok": False, "available": False, "error": "Pillow is required for image diff"}

    before_meta, after_meta = _find(before_id), _find(after_id)
    if not before_meta or not after_meta:
        return {"ok": False, "available": True, "error": "Unknown snapshot id"}
    try:
        before = Image.open(BASE_DIR / before_meta["path"]).convert("RGB")
        after = Image.open(BASE_DIR / after_meta["path"]).convert("RGB")
        if before.size != after.size:
            after = after.resize(before.size)
        diff = ImageChops.difference(before, after)
        gray = diff.convert("L")
        histogram = gray.histogram()
        total = before.size[0] * before.size[1]
        changed = sum(histogram[12:])
        changed_ratio = round(changed / total, 6) if total else 0.0
        bbox = diff.getbbox()
        overlay = SCREENSHOT_DIR / f"DIFF-{before_id}-{after_id}.png"
        diff.save(overlay)
        return {
            "ok": True,
            "available": True,
            "before": before_meta,
            "after": after_meta,
            "changed_pixels": changed,
            "total_pixels": total,
            "changed_ratio": changed_ratio,
            "difference_bbox": list(bbox) if bbox else None,
            "overlay_path": str(overlay.relative_to(BASE_DIR)).replace("\\", "/"),
            "policy": (
                "Screenshot difference is visual evidence only. A finding may be marked "
                "RESOLVED only after an appropriate verification scan."
            ),
        }
    except Exception as exc:
        return {"ok": False, "available": True, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}
