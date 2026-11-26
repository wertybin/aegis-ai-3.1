"""Attack Surface Intelligence built only from observed scan evidence."""

from urllib.parse import urlparse

from backend.local_http import fetch_target_snapshot


def _node(node_id: str, kind: str, label: str, detail: str, evidence: list[str]) -> dict:
    return {
        "id": node_id,
        "kind": kind,
        "label": label,
        "detail": detail[:240],
        "evidence": evidence[:8],
    }


def _edge(source: str, target: str, kind: str, reason: str) -> dict:
    return {
        "source": source,
        "target": target,
        "kind": kind,
        "reason": reason[:200],
    }


def build_attack_surface(audit: dict) -> dict:
    """Produces nodes/edges for the authorized localhost target."""
    dast = audit.get("dast") or {}
    target = dast.get("target") or audit.get("target") or ""
    snapshot = audit.get("target_snapshot")
    if snapshot is None and target.startswith(("http://", "https://")):
        try:
            snapshot = fetch_target_snapshot(target)
        except Exception as exc:
            snapshot = {"tool": "local_http", "error": str(exc)}

    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[str] = set()

    def add(node: dict) -> None:
        if node["id"] not in seen:
            seen.add(node["id"])
            nodes.append(node)

    parsed = urlparse(target)
    host = parsed.hostname or "127.0.0.1"
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    nmap = dast.get("nmap") or {}
    for port in nmap.get("ports", []) or []:
        port_id = f"service:{port.get('port', '')}"
        add(
            _node(
                port_id,
                "service",
                f"{host}:{port.get('port', '')}",
                f"{port.get('service', '')} {port.get('version', '')}".strip(),
                [f"nmap:{port.get('port', '')}", f"state={port.get('state', '')}"],
            )
        )

    endpoint_items: dict[str, list[str]] = {}
    for endpoint in audit.get("endpoints", []) or []:
        path = endpoint.get("path", "")
        if path:
            endpoint_items.setdefault(path, []).append(f"auditor:line {endpoint.get('line', '?')}")
    for item in (dast.get("ffuf") or {}).get("results", []) or []:
        path = item.get("path", "")
        if path:
            endpoint_items.setdefault(path, []).append(f"ffuf:HTTP {item.get('status', '?')}")
    for item in (dast.get("gofile") or {}).get("findings", []) or []:
        path = item.get("path", "")
        if path:
            endpoint_items.setdefault(path, []).append(f"gofile:HTTP {item.get('status', '?')}")
    for item in (dast.get("nuclei") or {}).get("findings", []) or []:
        endpoint = item.get("endpoint", "")
        if endpoint:
            path = urlparse(endpoint).path or "/"
            endpoint_items.setdefault(path, []).append(f"nuclei:{item.get('id', '')}")
    for alert in (dast.get("zap") or {}).get("alerts", []) or []:
        endpoint = alert.get("endpoint", "")
        if endpoint:
            path = urlparse(endpoint).path or "/"
            endpoint_items.setdefault(path, []).append(f"zap:{alert.get('title', '')[:60]}")
    for path in (snapshot or {}).get("endpoints", []) or []:
        if path:
            endpoint_items.setdefault(path, []).append("local_http:html reference")

    for path, evidence in sorted(endpoint_items.items()):
        add(_node(f"endpoint:{path}", "endpoint", path, "Observed HTTP route/resource", evidence))

    for item in (dast.get("gofile") or {}).get("findings", []) or []:
        if not item.get("hidden"):
            continue
        add(
            _node(
                f"resource:{item.get('path', '')}",
                "resource",
                item.get("path", ""),
                f"HTTP {item.get('status', '')} · {item.get('size', '')} bytes",
                [f"gofile:hidden=true", f"gobuster:status={item.get('status', '')}"],
            )
        )

    for technology in (snapshot or {}).get("technologies", []) or []:
        add(
            _node(
                f"tech:{technology.get('name', '')}",
                "technology",
                technology.get("name", ""),
                f"Detected from {technology.get('source', '')}",
                [f"{technology.get('source', '')}:{technology.get('evidence', '')}"],
            )
        )

    if (snapshot or {}).get("status_code"):
        add(
            _node(
                "app:web",
                "application",
                "Local web application",
                (snapshot.get("title") or "HTML response") + f" · HTTP {snapshot.get('status_code')}",
                [
                    f"local_http:status={snapshot.get('status_code')}",
                    f"local_http:sha256={str(snapshot.get('html_sha256', ''))[:12]}",
                ],
            )
        )

    service_ids = [node["id"] for node in nodes if node["kind"] == "service"]
    for service_id in service_ids:
        port_value = service_id.split(":", 1)[1]
        for node in nodes:
            if node["kind"] == "endpoint":
                observed = port_value == str(target_port)
                edges.append(
                    _edge(
                        service_id,
                        node["id"],
                        "evidence" if observed else "theoretical",
                        "Endpoint observed on the same authenticated target"
                        if observed
                        else "Same host, different port; relation not directly observed",
                    )
                )
        for node in nodes:
            if node["kind"] == "technology":
                evidence = any("nmap" in item for item in node["evidence"])
                edges.append(
                    _edge(
                        service_id,
                        node["id"],
                        "evidence" if evidence else "theoretical",
                        "Version/service evidence from nmap"
                        if evidence
                        else "Technology detected from HTML/header, not service banner",
                    )
                )

    for node in nodes:
        if node["kind"] != "resource":
            continue
        path = node["id"].split(":", 1)[1]
        for endpoint in nodes:
            if endpoint["kind"] != "endpoint":
                continue
            endpoint_path = endpoint["id"].split(":", 1)[1]
            if endpoint_path != "/" and path.startswith(endpoint_path):
                edges.append(
                    _edge(endpoint["id"], node["id"], "evidence", "Hidden resource located under observed route")
                )

    if any(node["id"] == "app:web" for node in nodes):
        for node in nodes:
            if node["kind"] == "endpoint":
                edges.append(
                    _edge("app:web", node["id"], "evidence", "Endpoint referenced by captured HTML or scanner")
                )

    stats = {
        "services": sum(1 for n in nodes if n["kind"] == "service"),
        "endpoints": sum(1 for n in nodes if n["kind"] == "endpoint"),
        "resources": sum(1 for n in nodes if n["kind"] == "resource"),
        "technologies": sum(1 for n in nodes if n["kind"] == "technology"),
        "evidence_edges": sum(1 for e in edges if e["kind"] == "evidence"),
        "theoretical_edges": sum(1 for e in edges if e["kind"] == "theoretical"),
    }

    return {
        "engine": "aegis-attack-surface-v1",
        "target": target,
        "scope": {
            "allowed_hosts": ["127.0.0.1", "localhost"],
            "host": host,
            "port": target_port,
            "mode": "defensive-local-only",
        },
        "snapshot_error": None if snapshot and not snapshot.get("error") else (snapshot or {}).get("error"),
        "snapshot": snapshot,
        "stats": stats,
        "nodes": nodes[:120],
        "edges": edges[:240],
    }
