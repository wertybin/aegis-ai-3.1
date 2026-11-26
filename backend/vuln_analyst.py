"""AegisAI V2 Vulnerability Analyst (PHASE 5).

Two independent, evidence-backed capabilities:

1. CVSS v3.1 base score - computed locally with the official FIRST formula
   from a vector derived from the finding class. No external service, no
   fabricated data; the vector is deterministic for a given evidence class.

2. CVE enrichment - performed ONLY against the NVD 2.0 API using a real
   product+version observed by nmap and a trusted product->CPE allowlist.
   A CVE is attached only when NVD's CPE match criteria show the exact
   version as vulnerable. If NVD is unreachable, has no match, or the
   product is unknown, the CVE list stays empty and the reason is recorded.
   CVE IDs are never invented or copied from keyword-only matches.
"""

import math
import os
import re
import time
from datetime import datetime

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 6
MAX_LOOKUPS_PER_ANALYSIS = 4

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

# Trusted product -> CPE mapping. Only these products are queried against NVD;
# a product not in this map is skipped (CVE omitted), never guessed.
CPE_ALLOWLIST = {
    "werkzeug": ("palletsprojects", "werkzeug"),
    "flask": ("palletsprojects", "flask"),
    "django": ("djangoproject", "django"),
    "python": ("python", "python"),
    "nginx": ("nginx", "nginx"),
    "apache": ("apache", "http_server"),
    "openssh": ("openbsd", "openssh"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
}

# CVSS vectors are derived from the finding class, which itself comes from
# real scanner evidence. Values are intentionally conservative.
VECTOR_BY_KEY = {
    "SQL_INJECTION": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "TEMPLATE_INJECTION": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "XSS": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "PATH_TRAVERSAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "BROKEN_AUTHORIZATION": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    "HARDCODED_SECRET": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "EXPOSED_CREDENTIALS": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "SENSITIVE_EXPOSURE": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "MISSING_SECURITY_HEADER": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "INSECURE_COOKIE": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "TECHNOLOGY_DISCLOSURE": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "OPEN_PORT": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    "DNS_EXPOSURE": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
}

DEFAULT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"

_cve_cache: dict[str, dict] = {}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup (avoids binary floating point edge cases)."""
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def compute_cvss31(vector: str) -> dict:
    """Computes the CVSS v3.1 base score from a vector string."""
    try:
        parts = dict(item.split(":", 1) for item in vector.split("/") if ":" in item)
        if not vector.startswith("CVSS:3.1"):
            raise ValueError("not a CVSS:3.1 vector")
        av, ac, pr, ui = parts["AV"], parts["AC"], parts["PR"], parts["UI"]
        scope, c, i, a = parts["S"], parts["C"], parts["I"], parts["A"]
        iss = 1 - (1 - CIA[c]) * (1 - CIA[i]) * (1 - CIA[a])
        if scope == "C":
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
        exploitability = 8.22 * AV[av] * AC[ac] * (PR_C if scope == "C" else PR_U)[pr] * UI[ui]
        if impact <= 0:
            score = 0.0
        elif scope == "C":
            score = _roundup(min(1.08 * (impact + exploitability), 10))
        else:
            score = _roundup(min(impact + exploitability, 10))
    except Exception:
        return {"vector": vector, "base_score": None, "severity": "UNKNOWN"}

    if score == 0:
        rating = "NONE"
    elif score < 4.0:
        rating = "LOW"
    elif score < 7.0:
        rating = "MEDIUM"
    elif score < 9.0:
        rating = "HIGH"
    else:
        rating = "CRITICAL"
    return {"vector": vector, "base_score": score, "severity": rating}


def _parse_version(text: str) -> tuple[str, str] | None:
    """Extracts (product phrase, version) only from a real nmap version string.

    Keeps the full phrase before the version (e.g. "Werkzeug httpd") so that
    a trusted product token can be located anywhere in it.
    """
    value = str(text or "")
    match = re.search(r"(\d+\.\d+(?:\.\d+)*)", value)
    if not match:
        return None
    version = match.group(1)
    product = value[: match.start()].strip(" -_:,()")
    if not product:
        return None
    return product, version


def _cpe_for(product: str, version: str) -> str | None:
    """Resolves a trusted CPE only when a token matches the allowlist.

    Examples: "Werkzeug httpd" -> palletsprojects:werkzeug,
              "Python 3.14.4"  -> python:python.
    """
    for token in reversed(re.findall(r"[A-Za-z][A-Za-z0-9_+.-]*", product.lower())):
        vendor_and_product = CPE_ALLOWLIST.get(token.strip("-_"))
        if vendor_and_product:
            vendor, prod = vendor_and_product
            return f"cpe:2.3:a:{vendor}:{prod}:{version}:*:*:*:*:*:*:*"
    return None


def _query_nvd(cpe: str) -> dict:
    """Queries NVD; attaches CVEs only when CPE virtual-match says vulnerable."""
    if cpe in _cve_cache:
        return _cve_cache[cpe]

    result = {"cves": [], "status": "not_available", "cpe": cpe, "source": "NVD 2.0"}
    try:
        import requests

        response = requests.get(
            NVD_URL,
            params={"virtualMatchString": cpe, "resultsPerPage": 10},
            headers={"User-Agent": "AegisAI-V2-Defensive-Analyst/2.0"},
            timeout=NVD_TIMEOUT,
        )
        if response.status_code != 200:
            result["status"] = f"nvd_http_{response.status_code}"
            _cve_cache[cpe] = result
            return result

        payload = response.json()
        for entry in payload.get("vulnerabilities", []):
            cve = entry.get("cve") or {}
            cve_id = cve.get("id")
            if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
                continue
            description = next(
                (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "",
            )
            cvss = None
            metrics = cve.get("metrics") or {}
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
                for metric in metrics.get(metric_key, []) or []:
                    metric_data = metric.get("cvssData") or {}
                    if metric_data.get("baseScore") is not None:
                        cvss = metric_data.get("baseScore")
                        break
                if cvss is not None:
                    break
            result["cves"].append(
                {
                    "id": cve_id,
                    "description": description[:400],
                    "nvd_score": cvss,
                    "published": cve.get("published"),
                    "status": cve.get("vulnStatus"),
                }
            )
        result["status"] = "matched" if result["cves"] else "no_vulnerable_match"
    except Exception as exc:
        result["status"] = f"lookup_failed: {type(exc).__name__}"
    _cve_cache[cpe] = result
    return result


def analyze(audit: dict) -> dict:
    """Adds CVSS v3.1 scores to real finding groups and CPE-validated CVEs."""
    correlation = audit.get("correlations") or {}
    groups = correlation.get("groups", []) or []
    burnout = []

    for group in groups:
        vector = VECTOR_BY_KEY.get(group.get("key"), DEFAULT_VECTOR)
        cvss = compute_cvss31(vector)
        # Confidence stays separate: CVSS measures technical severity, not
        # how strongly the finding is evidenced.
        group["cvss"] = {
            **cvss,
            "classification": group.get("classification"),
            "confidence": group.get("confidence", 0),
        }
        burnout.append((cvss.get("base_score") or 0, group["id"]))

    # CVE lookup uses ONLY real version evidence from nmap.
    dast = audit.get("dast") or {}
    cve_results = []
    lookups = 0
    for port in (dast.get("nmap") or {}).get("ports", []) or []:
        if lookups >= MAX_LOOKUPS_PER_ANALYSIS:
            break
        parsed = _parse_version(port.get("version", ""))
        if not parsed:
            continue
        product, version = parsed
        cpe = _cpe_for(product, version)
        if not cpe:
            cve_results.append(
                {
                    "product": product,
                    "version": version,
                    "cpe": None,
                    "status": "no_trusted_cpe_mapping",
                    "cves": [],
                    "note": "Urun NVD CPE allowlist'inde olmadigi icin CVE sorgulanmadi.",
                }
            )
            continue
        result = _query_nvd(cpe)
        lookups += 1
        cve_results.append(
            {
                "product": product,
                "version": version,
                **result,
                "note": (
                    "Result of NVD CPE matching; only CVEs returned for a vulnerable CPE range"
                    " are listed."
                    if result["cves"]
                    else "No vulnerable CPE match was found in NVD for this exact version; no CVE was added."
                ),
            }
        )

    total_cves = sum(len(item.get("cves", [])) for item in cve_results)
    scored = [score for score, _ in burnout if score]
    summary = {
        "scored_groups": len(scored),
        "average_cvss": round(sum(scored) / len(scored), 1) if scored else None,
        "max_cvss": max(scored) if scored else None,
        "critical_cvss": sum(1 for s in scored if s >= 9.0),
        "high_cvss": sum(1 for s in scored if 7.0 <= s < 9.0),
        "medium_cvss": sum(1 for s in scored if 4.0 <= s < 7.0),
        "low_cvss": sum(1 for s in scored if 0 < s < 4.0),
        "cve_sources_queried": lookups,
        "total_cves": total_cves,
        "cvss_source": "FIRST CVSS v3.1 base formula (local, deterministic)",
        "cve_source": "NVD 2.0 API (CPE virtual-match validated)",
    }

    return {
        "engine": "aegis-vuln-analyst-v1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "policy": (
            "The CVSS v3.1 base score and the evidence-based finding class are computed locally "
            "and deterministically. A CVE is added only when confirmed by an NVD 2.0 CPE match; "
            "no CVE is added for an untrusted product, an unreachable API or no match."
        ),
        "summary": summary,
        "cve_lookups": cve_results,
        "findings": [
            {
                "id": group["id"],
                "title": group["title"],
                "classification": group.get("classification"),
                "cvss": group["cvss"],
            }
            for group in groups
        ],
    }
