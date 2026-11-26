from datetime import datetime
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _esc(value) -> str:
    """Escapes markup so code snippets (e.g. <h1>) render literally in ReportLab paragraphs."""
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _mini_table(header: list[str], rows: list[list[str]], widths: list[int]):
    table = Table([header] + rows, colWidths=widths)
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#581C87")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )
    return table


def _page_footer(canvas, doc) -> None:
    """Professional footer on every page: classification, tool, page number."""
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#6B21A8"))
    canvas.setLineWidth(0.6)
    canvas.line(40, 30, doc.pagesize[0] - 40, 30)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#6B7280"))
    canvas.drawString(40, 18, "CONFIDENTIAL · AegisAI V2 · Localhost defensive assessment")
    canvas.drawRightString(doc.pagesize[0] - 40, 18, f"Page {doc.page}")
    canvas.restoreState()


def generate_pdf_report(audit_data: dict, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = output_dir / f"AegisAI_Audit_Report_{timestamp}.pdf"
    counter = 2
    while pdf_path.exists():
        pdf_path = output_dir / f"AegisAI_Audit_Report_{timestamp}_{counter}.pdf"
        counter += 1

    doc = SimpleDocTemplate(str(pdf_path), pagesize=LETTER, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()

    cover_title_style = ParagraphStyle(
        "AegisCoverTitle",
        parent=styles["Heading1"],
        fontSize=26,
        leading=30,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#6B21A8"),
        spaceAfter=6,
    )
    cover_sub_style = ParagraphStyle(
        "AegisCoverSub",
        parent=styles["Normal"],
        fontSize=11,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#4B5563"),
        spaceAfter=18,
    )
    title_style = ParagraphStyle(
        "AegisTitle",
        parent=styles["Heading1"],
        fontSize=20,
        textColor=colors.HexColor("#6B21A8"),
        spaceAfter=12,
    )
    h2_style = ParagraphStyle(
        "AegisH2",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#1E1B4B"),
        spaceBefore=12,
        spaceAfter=6,
    )
    code_style = ParagraphStyle(
        "AegisCode",
        parent=styles["Code"],
        fontSize=8.5,
        backColor=colors.HexColor("#F3F4F6"),
        borderPadding=6,
        spaceAfter=8,
    )

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    findings = audit_data.get("findings", [])
    correlation = audit_data.get("correlations") or {}
    correlations = correlation
    corr_summary = correlations.get("summary") or {}
    vuln = audit_data.get("vulnerability_analysis") or {}
    vuln_summary = vuln.get("summary") or {}
    severity_counts = audit_data.get("severity_counts") or {}
    surface_stats = ((audit_data.get("attack_surface") or {}).get("stats") or {})
    graph_stats = ((audit_data.get("attack_graph") or {}).get("stats") or {})

    story = []

    # ------------------------------------------------------------------
    # COVER + EXECUTIVE SUMMARY (professional, computed from real data).
    # ------------------------------------------------------------------
    story.append(Spacer(1, 36))
    story.append(Paragraph("AEGIS-AI", cover_title_style))
    story.append(Paragraph("Defensive Security Assessment · V2 Intelligence Report", cover_sub_style))
    story.append(Spacer(1, 10))

    meta_rows = [
        ["Classification", "CONFIDENTIAL · Localhost defensive assessment"],
        ["Generated", generated],
        ["Audited target file", _esc(audit_data.get("file_name", "N/A"))],
        ["Security score", f"{audit_data.get('score', 0)} / 100"],
        ["Scope", "User-configured localhost targets only · no bundled addresses"],
        ["Evidence policy", "Real tool output only · no synthetic findings or placeholder metrics"],
    ]
    meta_table = Table(meta_rows, colWidths=[150, 360])
    meta_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3E8FF")),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#581C87")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ])
    )
    story.append(meta_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("Executive Summary", h2_style))
    crit = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)
    score = audit_data.get("score", 0)
    story.append(Paragraph(
        "This report presents the results of a localhost-only defensive assessment. "
        f"The audited source produced <b>{len(findings)}</b> real static finding(s), "
        f"of which <b>{crit}</b> are CRITICAL and <b>{high}</b> are HIGH severity. "
        f"The computed security score is <b>{score}/100</b>. "
        "Vulnerabilities were correlated from real tool evidence, scored locally with the "
        "FIRST CVSS v3.1 base formula, and — where a valid CPE version match existed — checked "
        "against the NVD 2.0 API. Findings backed only by static code evidence are labeled "
        "<i>Potential</i>; they are not presented as dynamically confirmed.",
        styles["Normal"],
    ))
    story.append(Spacer(1, 8))

    exec_rows = [
        ["Metric", "Value", "Source"],
        [
            "Static findings",
            str(len(findings)),
            f"CRITICAL {severity_counts.get('CRITICAL', 0)} · HIGH {severity_counts.get('HIGH', 0)} "
            f"· MEDIUM {severity_counts.get('MEDIUM', 0)} · LOW {severity_counts.get('LOW', 0)}",
        ],
        [
            "Correlation groups",
            str(corr_summary.get("total", 0)),
            f"Confirmed {corr_summary.get('confirmed', 0)} · Potential {corr_summary.get('potential', 0)} "
            f"· Unverified {corr_summary.get('unverified', 0)} · AI mode {_esc(corr_summary.get('ai_mode', 'deterministic'))}",
        ],
        [
            "CVSS v3.1",
            str(vuln_summary.get("max_cvss", "-")),
            f"Max {vuln_summary.get('max_cvss', '-')} · avg {vuln_summary.get('average_cvss', '-')} · "
            f"{len(vuln.get('findings', []))} scored group(s)",
        ],
        [
            "Validated CVEs",
            str(vuln_summary.get("total_cves", 0)),
            f"NVD lookups {vuln_summary.get('cve_sources_queried', 0)} · CPE virtual-match only",
        ],
        [
            "Attack surface",
            str(surface_stats.get("endpoints", 0)),
            f"{surface_stats.get('endpoints', 0)} endpoint(s) · {surface_stats.get('technologies', 0)} technology(ies)",
        ],
        [
            "Attack graph",
            str(graph_stats.get("nodes", 0)),
            f"{graph_stats.get('nodes', 0)} nodes · {graph_stats.get('evidence_edges', 0)} evidence edges · "
            f"{graph_stats.get('theoretical_edges', 0)} theoretical (labeled) edges",
        ],
    ]
    exec_table = Table(exec_rows, colWidths=[120, 70, 320])
    exec_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#581C87")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )
    story.append(exec_table)
    story.append(Spacer(1, 14))

    dast_exec = audit_data.get("dast") or {}
    guard_exec = dast_exec.get("guardrail") or {}
    if guard_exec:
        story.append(Paragraph(
            f"<b>Guardrail:</b> {_esc(guard_exec.get('mode', '-'))} / "
            f"{'ALLOW' if guard_exec.get('ok') else 'BLOCK'}",
            styles["Normal"],
        ))
    story.append(Paragraph(
        "All values in this report are read from the persisted real scan result. "
        "No simulated vulnerabilities, scores, or evidence are included.",
        styles["Normal"],
    ))

    story.append(PageBreak())

    # ------------------------------------------------------------------
    # TECHNICAL SECTIONS (original V1 sections, unchanged content).
    # ------------------------------------------------------------------
    story.append(Paragraph("AEGIS-AI // Defensive Security Audit Report", title_style))
    story.append(Paragraph(f"<b>Generated:</b> {generated}", styles["Normal"]))
    story.append(Paragraph(f"<b>Audited Target File:</b> {_esc(audit_data.get('file_name', 'N/A'))}", styles["Normal"]))
    story.append(Paragraph(f"<b>Security Score:</b> {audit_data.get('score', 0)} / 100", styles["Normal"]))
    story.append(Spacer(1, 14))

    # Discovered Endpoints Table
    story.append(Paragraph("1. Discovered Routes & Endpoints", h2_style))
    endpoints = audit_data.get("endpoints", [])
    ep_rows = [["Route / Endpoint", "Source File", "Line"]]
    for ep in endpoints:
        ep_rows.append([_esc(ep["path"]), _esc(ep["file"]), str(ep["line"])])
    if len(ep_rows) == 1:
        ep_rows.append(["No explicit routes detected", "-", "-"])

    ep_table = Table(ep_rows, colWidths=[240, 160, 80])
    ep_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#581C87")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ])
    )
    story.append(ep_table)
    story.append(Spacer(1, 14))

    # Findings & Remediation Diffs
    story.append(Paragraph("2. Security Findings & Code Remediation", h2_style))
    if not findings:
        story.append(Paragraph("No OWASP static vulnerabilities detected. Target passed verification.", styles["Normal"]))
    else:
        for idx, item in enumerate(findings, start=1):
            story.append(
                Paragraph(
                    f"<b>{idx}. [{_esc(item['severity'])}] {_esc(item['title'])}</b> ({_esc(item['endpoint'])})",
                    styles["Normal"],
                )
            )
            story.append(Paragraph(_esc(item["explanation"]), styles["Normal"]))
            story.append(Spacer(1, 4))
            story.append(Paragraph("<b>Vulnerable Code:</b>", styles["Normal"]))
            story.append(Paragraph(_esc(item["vulnerable_snippet"]).replace("\n", "<br/>"), code_style))
            story.append(Paragraph("<b>Recommended Secure Patch:</b>", styles["Normal"]))
            story.append(Paragraph(_esc(item["patched_snippet"]).replace("\n", "<br/>"), code_style))
            story.append(Spacer(1, 10))

    dast = audit_data.get("dast")
    if dast:
        story.append(Paragraph("3. Dynamic Analysis (WSL2 DAST)", h2_style))
        story.append(Paragraph(f"<b>Live Target:</b> {_esc(dast.get('target', 'N/A'))}", styles["Normal"]))
        tool_bits = [
            f"{_esc(name)}={_esc(info.get('status', '?'))}"
            for name, info in (dast.get("tools") or {}).items()
        ]
        if tool_bits:
            story.append(Paragraph("<b>Tool Status:</b> " + ", ".join(tool_bits), styles["Normal"]))
        story.append(Spacer(1, 8))

        ffuf = dast.get("ffuf") or {}
        story.append(Paragraph("<b>ffuf - Discovered Routes</b>", styles["Normal"]))
        if ffuf.get("results"):
            rows = [
                [_esc(item["path"][:45]), str(item.get("status", "")), str(item.get("length", ""))]
                for item in ffuf["results"]
            ]
            story.append(_mini_table(["Path", "HTTP", "Length"], rows, [300, 70, 80]))
        else:
            story.append(Paragraph(_esc(ffuf.get("error") or "No additional routes discovered."), styles["Normal"]))
        story.append(Spacer(1, 8))

        gofile = dast.get("gofile") or {}
        story.append(Paragraph("<b>GoFile - Hidden Files &amp; Directories</b>", styles["Normal"]))
        if gofile.get("findings"):
            rows = [
                [_esc(f["path"][:60]), str(f.get("status", "")), "YES" if f.get("hidden") else "no"]
                for f in gofile["findings"][:15]
            ]
            story.append(_mini_table(["Path", "HTTP", "Hidden"], rows, [320, 70, 70]))
            story.append(Paragraph(
                f"Hidden/sensitive entries: {gofile.get('hidden_count', 0)}", styles["Normal"]
            ))
        else:
            story.append(Paragraph(_esc(gofile.get("error") or "No hidden files found."), styles["Normal"]))
        story.append(Spacer(1, 8))

        sqlmap = dast.get("sqlmap") or {}
        story.append(Paragraph("<b>sqlmap - Injection Test</b>", styles["Normal"]))
        if sqlmap.get("injectable"):
            story.append(Paragraph(
                "SQL injection confirmed. Parameters: "
                f"{_esc(', '.join(sqlmap.get('parameters', [])))} | "
                f"Techniques: {_esc(', '.join(sqlmap.get('types', [])))} | "
                f"DBMS: {_esc(sqlmap.get('dbms') or 'unknown')}",
                styles["Normal"],
            ))
            for payload in sqlmap.get("payloads", [])[:2]:
                story.append(Paragraph(_esc(payload), code_style))
        else:
            story.append(Paragraph(_esc(sqlmap.get("error") or "No SQL injection detected."), styles["Normal"]))
        story.append(Spacer(1, 8))

        zap = dast.get("zap") or {}
        story.append(Paragraph("<b>OWASP ZAP - High/Medium Alerts</b>", styles["Normal"]))
        if zap.get("alerts"):
            rows = [
                [
                    _esc(alert["risk"]),
                    _esc(alert["title"][:45]),
                    _esc((alert.get("endpoint") or "-")[:55]),
                ]
                for alert in zap["alerts"][:15]
            ]
            story.append(_mini_table(["Risk", "Alert", "Endpoint"], rows, [80, 210, 230]))
        else:
            story.append(Paragraph(_esc(zap.get("error") or "No high/medium alerts."), styles["Normal"]))
        story.append(Spacer(1, 8))

        nmap = dast.get("nmap") or {}
        story.append(Paragraph("<b>Nmap - Port &amp; Service Discovery</b>", styles["Normal"]))
        if nmap.get("ports"):
            rows = [
                [
                    _esc(p["port"]),
                    _esc(p["state"]),
                    _esc(p["service"]),
                    _esc(p.get("version", "")[:55]),
                ]
                for p in nmap["ports"][:12]
            ]
            story.append(_mini_table(["Port", "State", "Service", "Version"], rows, [70, 70, 90, 250]))
        else:
            story.append(Paragraph(_esc(nmap.get("error") or "No open ports found."), styles["Normal"]))
        story.append(Spacer(1, 8))

        dns = dast.get("dnsrecon") or {}
        story.append(Paragraph("<b>dnsrecon - Offline DNS Recon</b>", styles["Normal"]))
        story.append(Paragraph(
            f"Resolver: {_esc(dns.get('resolver', '-'))} | Zone: {_esc(dns.get('domain', '-'))}",
            styles["Normal"],
        ))
        dns_rows = [
            ["A/NS/MX/TXT", _esc(r["type"]), _esc(r["value"][:70])]
            for r in dns.get("records", [])[:8]
        ]
        dns_rows += [
            ["A (brute)", _esc(s["host"]), _esc(s["ip"])]
            for s in dns.get("subdomains", [])[:10]
        ]
        dns_rows += [
            ["PTR", _esc(p["ip"]), _esc(p["host"])]
            for p in dns.get("ptr", [])[:5]
        ]
        if dns_rows:
            story.append(_mini_table(["Record", "Name / Key", "Value"], dns_rows, [85, 195, 200]))
        else:
            story.append(Paragraph(_esc(dns.get("error") or "No DNS records discovered."), styles["Normal"]))
        story.append(Spacer(1, 8))

        nuclei = dast.get("nuclei") or {}
        story.append(Paragraph("<b>Nuclei - Template-Based Findings</b>", styles["Normal"]))
        if nuclei.get("findings"):
            rows = [
                [
                    _esc(f["severity"]),
                    _esc(f["id"]),
                    _esc(f["endpoint"][:60]),
                ]
                for f in nuclei["findings"][:15]
            ]
            story.append(_mini_table(["Severity", "Template", "Endpoint"], rows, [70, 160, 250]))
        else:
            story.append(Paragraph(_esc(nuclei.get("error") or "No template findings."), styles["Normal"]))

        guard = dast.get("guardrail") or {}
        if guard:
            story.append(Spacer(1, 8))
            story.append(Paragraph(
                f"<b>Output Guardrail:</b> {_esc(guard.get('mode', '-'))} / "
                f"{'ALLOW' if guard.get('ok') else 'BLOCK'}",
                styles["Normal"],
            ))

    if correlation:
        story.append(Paragraph("4. AI Correlation Engine", h2_style))
        summary = correlation.get("summary", {})
        story.append(Paragraph(
            "Groups: {total} | Confirmed: {confirmed} | Potential: {potential} | "
            "Unverified: {unverified} | Informational: {informational} | "
            "Evidence items: {evidence_items}".format(**{
                key: summary.get(key, 0) for key in (
                    "total", "confirmed", "potential", "unverified",
                    "informational", "evidence_items",
                )
            }),
            styles["Normal"],
        ))
        story.append(Paragraph(_esc(correlation.get("policy", "")), styles["Normal"]))
        story.append(Spacer(1, 8))
        for group in correlation.get("groups", [])[:15]:
            story.append(Paragraph(
                f"<b>{_esc(group['id'])} · [{_esc(group['classification'])}] "
                f"{_esc(group['title'])}</b> (rank {group.get('risk_rank', '-')})",
                styles["Normal"],
            ))
            story.append(Paragraph(
                f"Severity: {_esc(group.get('severity', '-'))} | "
                f"Confidence: {group.get('confidence', 0):.2f} | "
                f"Tools: {_esc(', '.join(group.get('tools', [])))}",
                styles["Normal"],
            ))
            story.append(Paragraph(_esc(group.get("reason", "")), styles["Normal"]))
            if group.get("ai_analysis"):
                story.append(Paragraph(f"<b>AI analysis:</b> {_esc(group['ai_analysis'])}", styles["Normal"]))
            story.append(Paragraph(
                f"<b>Recommendation:</b> {_esc(group.get('ai_recommendation') or group.get('recommendation', ''))}",
                styles["Normal"],
            ))
            endpoints = ", ".join(group.get("endpoints", [])[:3])
            if endpoints:
                story.append(Paragraph(f"Endpoint(s): {_esc(endpoints)}", styles["Normal"]))
            story.append(Spacer(1, 8))

    if vuln:
        story.append(Paragraph("5. Vulnerability Analyst (CVSS v3.1 / CVE)", h2_style))
        summary = vuln.get("summary", {})
        story.append(Paragraph(
            "Scored groups: {scored_groups} | Max CVSS: {max_cvss} | Average: {average_cvss} | "
            "Critical: {critical_cvss} | High: {high_cvss} | Medium: {medium_cvss} | Low: {low_cvss} | "
            "NVD lookups: {cve_sources_queried} | CVEs: {total_cves}".format(
                **{k: summary.get(k, 0) for k in (
                    "scored_groups", "max_cvss", "average_cvss", "critical_cvss",
                    "high_cvss", "medium_cvss", "low_cvss", "cve_sources_queried", "total_cves",
                )}
            ),
            styles["Normal"],
        ))
        story.append(Paragraph(_esc(vuln.get("policy", "")), styles["Normal"]))
        story.append(Paragraph(
            f"CVSS source: {_esc(summary.get('cvss_source', ''))}<br/>"
            f"CVE source: {_esc(summary.get('cve_source', ''))}",
            styles["Normal"],
        ))
        story.append(Spacer(1, 6))
        rows = []
        for finding in vuln.get("findings", [])[:15]:
            cvss = finding.get("cvss") or {}
            rows.append([
                _esc(finding.get("id", "")),
                _esc(finding.get("title", "")[:45]),
                _esc(cvss.get("severity", "-")),
                str(cvss.get("base_score", "-")),
                _esc(cvss.get("vector", "")),
            ])
        if rows:
            story.append(_mini_table(
                ["ID", "Finding", "Rating", "Score", "CVSS v3.1 Vector"],
                rows,
                [45, 155, 55, 35, 190],
            ))
        story.append(Spacer(1, 8))
        for lookup in vuln.get("cve_lookups", []):
            story.append(Paragraph(
                f"<b>{_esc(lookup.get('product', ''))} {_esc(lookup.get('version', ''))}</b> "
                f"— status: {_esc(lookup.get('status', ''))}",
                styles["Normal"],
            ))
            story.append(Paragraph(_esc(lookup.get("note", "")), styles["Normal"]))
            for item in lookup.get("cves", []):
                story.append(Paragraph(
                    f"<b>{_esc(item.get('id', ''))}</b> "
                    f"(NVD score: {item.get('nvd_score', '-')}, {_esc(item.get('status', '-'))}) "
                    f"— {_esc(item.get('description', '')[:220])}",
                    styles["Normal"],
                ))
            story.append(Spacer(1, 6))

    # ------------------------------------------------------------------
    # V2 SECTIONS (PHASE 11) — all derived from the same real scan result.
    # ------------------------------------------------------------------
    surface = audit_data.get("attack_surface") or {}
    if surface:
        story.append(Paragraph("6. Attack Surface", h2_style))
        story.append(Paragraph(
            f"Scope target: {_esc(surface.get('target', '-'))} · "
            f"engine: {_esc(surface.get('engine', '-'))}",
            styles["Normal"],
        ))
        srows = [
            ["Metric", "Value"],
            ["Services", str(surface_stats.get("services", 0))],
            ["Endpoints", str(surface_stats.get("endpoints", 0))],
            ["Resources", str(surface_stats.get("resources", 0))],
            ["Technologies", str(surface_stats.get("technologies", 0))],
            ["Evidence edges", str(surface_stats.get("evidence_edges", 0))],
            ["Theoretical edges", str(surface_stats.get("theoretical_edges", 0))],
        ]
        story.append(_mini_table(["Attack Surface Metric", "Count"], srows[1:], [360, 100]))

        surface_nodes = surface.get("nodes") or []
        if surface_nodes:
            nrows = []
            for node in surface_nodes[:15]:
                if isinstance(node, dict):
                    nrows.append([
                        _esc(node.get("kind", "-")),
                        _esc(node.get("label", "-"))[:55],
                        str(node.get("severity", "-")),
                    ])
            if nrows:
                story.append(Spacer(1, 6))
                story.append(_mini_table(["Kind", "Node", "Severity"], nrows, [90, 320, 70]))

    graph = audit_data.get("attack_graph") or {}
    if graph:
        story.append(Paragraph("7. Attack Graph", h2_style))
        story.append(Paragraph(_esc(graph.get("policy", "")), styles["Normal"]))
        story.append(Paragraph(
            f"Nodes: {graph_stats.get('nodes', 0)} · Edges: {graph_stats.get('edges', 0)} · "
            f"Evidence edges: {graph_stats.get('evidence_edges', 0)} · "
            f"Theoretical edges: {graph_stats.get('theoretical_edges', 0)}",
            styles["Normal"],
        ))
        erows = []
        for edge in (graph.get("edges") or [])[:15]:
            if isinstance(edge, dict):
                erows.append([
                    _esc(edge.get("source", "-")),
                    _esc(edge.get("target", "-")),
                    _esc(edge.get("kind", "-")),
                    _esc(edge.get("label", "-"))[:45],
                ])
        if erows:
            story.append(Spacer(1, 6))
            story.append(_mini_table(
                ["Source", "Target", "Kind", "Label"], erows, [70, 70, 90, 250]
            ))
            story.append(Paragraph(
                "Solid edges are backed by shared real evidence (endpoint or correlated finding). "
                "Dashed/theoretical edges are explicitly labeled as hypothetical and are not proof of exploitability.",
                styles["Normal"],
            ))

    snapshot = audit_data.get("target_snapshot") or {}
    if snapshot:
        story.append(Paragraph("8. Scope & Evidence Provenance", h2_style))
        story.append(Paragraph(
            f"Snapshot tool: {_esc(snapshot.get('tool', '-'))} · "
            f"target: {_esc(snapshot.get('target', '-'))} · "
            f"captured: {_esc(snapshot.get('captured_at', '-'))} · "
            f"HTTP status: {snapshot.get('status_code', '-')}",
            styles["Normal"],
        ))
        headers = snapshot.get("headers") or {}
        if headers.get("server"):
            story.append(Paragraph(f"Observed server header: {_esc(headers['server'])}", styles["Normal"]))
        story.append(Paragraph(
            "This assessment is strictly limited to localhost / 127.0.0.1 and explicitly defined "
            "local lab applications. SSRF, DNS rebinding, redirect abuse, and command injection are "
            "guarded against; tool calls are allowlisted and time-bounded. Every displayed value in "
            "this report originates from the persisted real scan record.",
            styles["Normal"],
        ))

    doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)
    return pdf_path
