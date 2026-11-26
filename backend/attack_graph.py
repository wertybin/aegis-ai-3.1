"""Attack Path Graph with strict separation of evidence and theory."""

from backend.correlation import _canonical_key


CLASS_COLORS = {
    "Confirmed": "#F43F5E",
    "Potential": "#F59E0B",
    "Unverified": "#38BDF8",
    "Informational": "#34D399",
    "False Positive": "#9CA3AF",
}


def _shared_evidence(a: dict, b: dict) -> list[str]:
    """Only a genuinely shared endpoint counts as a solid evidence link.

    Sharing the same *tool* (e.g. both found by ZAP) is explicitly NOT treated
    as proof of a relationship between two findings -- that would draw solid
    edges for unrelated issues. Such relations are, at most, theoretical.
    """
    shared = []
    a_endpoints = set(a.get("endpoints", []))
    b_endpoints = set(b.get("endpoints", []))
    if a_endpoints & b_endpoints:
        shared.append("shared endpoint evidence")
    return shared


def build_attack_graph(audit: dict) -> dict:
    """Builds a directed graph from correlation groups and surface assets."""
    correlation = audit.get("correlations") or {}
    surface = audit.get("attack_surface") or {}
    groups = correlation.get("groups", []) or []

    nodes = []
    for group in groups:
        nodes.append(
            {
                "id": group["id"],
                "kind": "finding",
                "label": group["title"][:70],
                "classification": group["classification"],
                "severity": group["severity"],
                "color": CLASS_COLORS.get(group["classification"], "#C084FC"),
                "evidence_count": len(group.get("evidence", [])),
                "risk_rank": group.get("risk_rank", 0),
                "endpoints": list(group.get("endpoints", []))[:8],
                "tools": list(group.get("tools", []))[:8],
                "evidence": [
                    {
                        "tool": item.get("tool"),
                        "title": item.get("title"),
                        "severity": item.get("severity"),
                        "endpoint": item.get("endpoint"),
                    }
                    for item in (group.get("evidence") or [])[:6]
                ],
            }
        )

    for node in surface.get("nodes", []) or []:
        if node.get("kind") in {"endpoint", "service", "resource"}:
            nodes.append(
                {
                    "id": node["id"],
                    "kind": node["kind"],
                    "label": node["label"][:70],
                    "classification": "Informational",
                    "severity": "INFO",
                    "color": "#64748B",
                    "evidence_count": len(node.get("evidence", [])),
                    "risk_rank": 0,
                }
            )

    edges = []
    theoretically_linked = 0
    for i, left in enumerate(groups):
        for right in groups[i + 1 :]:
            shared = _shared_evidence(left, right)
            if shared:
                edges.append(
                    {
                        "source": left["id"],
                        "target": right["id"],
                        "kind": "evidence",
                        "label": " + ".join(shared[:2]),
                        "confidence": "observed",
                        "note": "Two findings share the same real evidence.",
                    }
                )
            else:
                left_key = _canonical_key(left["title"])
                right_key = _canonical_key(right["title"])
                chain = {
                    ("SENSITIVE_EXPOSURE", "EXPOSED_CREDENTIALS"),
                    ("EXPOSED_CREDENTIALS", "BROKEN_AUTHORIZATION"),
                    ("SQL_INJECTION", "SENSITIVE_EXPOSURE"),
                    ("XSS", "INSECURE_COOKIE"),
                    ("OPEN_PORT", "SENSITIVE_EXPOSURE"),
                    # A hardcoded secret combined with an exposed debug/backup
                    # resource is a plausible chain, but not evidence-proven.
                    ("HARDCODED_SECRET", "SENSITIVE_EXPOSURE"),
                    ("SENSITIVE_EXPOSURE", "HARDCODED_SECRET"),
                    ("HARDCODED_SECRET", "EXPOSED_CREDENTIALS"),
                    ("EXPOSED_CREDENTIALS", "HARDCODED_SECRET"),
                }
                if (left_key, right_key) in chain:
                    theoretically_linked += 1
                    edges.append(
                        {
                            "source": left["id"],
                            "target": right["id"],
                            "kind": "theoretical",
                            "label": "possible attack chain",
                            "confidence": "theoretical",
                            "note": "This link is hypothetical; it has not been confirmed by real evidence.",
                        }
                    )

    for group in groups:
        endpoints = set(group.get("endpoints", []))
        for surface_node in surface.get("nodes", []) or []:
            if surface_node.get("kind") != "endpoint":
                continue
            path = surface_node["id"].split(":", 1)[1]
            if any(path in endpoint or endpoint in path for endpoint in endpoints if endpoint):
                edges.append(
                    {
                        "source": surface_node["id"],
                        "target": group["id"],
                        "kind": "evidence",
                        "label": "observed endpoint",
                        "confidence": "observed",
                        "note": "The finding was observed on this endpoint.",
                    }
                )

    degree: dict[str, int] = {}
    for edge in edges:
        degree[edge["source"]] = degree.get(edge["source"], 0) + 1
        degree[edge["target"]] = degree.get(edge["target"], 0) + 1
    for node in nodes:
        node["degree"] = degree.get(node["id"], 0)

    findings = [node for node in nodes if node["kind"] == "finding"]
    assets = [node for node in nodes if node["kind"] != "finding"]
    isolated = [node for node in nodes if node["degree"] == 0]
    top_risk = sorted(
        findings,
        key=lambda node: (node.get("risk_rank") or 999, -(node.get("evidence_count") or 0)),
    )[:10]

    return {
        "engine": "aegis-attack-graph-v1",
        "policy": (
            "A solid line shows a real evidence link; a dashed line shows a hypothetical attack path. "
            "Theoretical links are never presented as an executed attack."
        ),
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "evidence_edges": sum(1 for e in edges if e["kind"] == "evidence"),
            "theoretical_edges": theoretically_linked,
            "findings": len(findings),
            "assets": len(assets),
            "isolated_nodes": len(isolated),
            "confirmed": sum(1 for n in findings if n["classification"] == "Confirmed"),
            "potential": sum(1 for n in findings if n["classification"] == "Potential"),
            "unverified": sum(1 for n in findings if n["classification"] == "Unverified"),
            "informational": sum(1 for n in findings if n["classification"] == "Informational"),
            "max_degree": max(degree.values(), default=0),
        },
        "top_risk": [
            {
                "id": node["id"],
                "label": node["label"],
                "severity": node["severity"],
                "classification": node["classification"],
                "risk_rank": node["risk_rank"],
                "evidence_count": node["evidence_count"],
                "degree": node["degree"],
            }
            for node in top_risk
        ],
        "nodes": nodes[:100],
        "edges": edges[:240],
    }
