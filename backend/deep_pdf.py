"""AEGIS AI V3 — PDF export of the REAL unified deep-scan correlation.

This file is intentionally separate from ``pdf_report.py``: the V1 audit PDF
and its endpoint contract stay untouched. Only real stored tool output is
rendered here — no synthetic findings and no placeholder metrics.
"""

from __future__ import annotations

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
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#6B21A8"))
    canvas.setLineWidth(0.6)
    canvas.line(40, 30, doc.pagesize[0] - 40, 30)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#6B7280"))
    canvas.drawString(40, 18, "CONFIDENTIAL · AEGIS-AI V3 · Deep Security Engine · real tool output only")
    canvas.drawRightString(doc.pagesize[0] - 40, 18, f"Page {doc.page}")
    canvas.restoreState()


def generate_deep_report(correlation: dict, output_dir: Path) -> Path:
    """Writes a PDF built exclusively from the supplied correlation payload."""
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"AegisAI_Deep_Report_{stamp}.pdf"
    counter = 2
    while path.exists():
        path = output_dir / f"AegisAI_Deep_Report_{stamp}_{counter}.pdf"
        counter += 1

    doc = SimpleDocTemplate(
        str(path), pagesize=LETTER, topMargin=42, bottomMargin=42,
        title="AEGIS-AI V3 Deep Security Report", author="AEGIS-AI V3",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "DeepTitle", parent=styles["Heading1"], fontSize=23, leading=27,
        alignment=TA_CENTER, textColor=colors.HexColor("#6B21A8"), spaceAfter=6,
    )
    sub_style = ParagraphStyle(
        "DeepSub", parent=styles["Normal"], fontSize=10.5, alignment=TA_CENTER,
        textColor=colors.HexColor("#4B5563"), spaceAfter=16,
    )
    h2_style = ParagraphStyle(
        "DeepH2", parent=styles["Heading2"], fontSize=13,
        textColor=colors.HexColor("#1E1B4B"), spaceBefore=12, spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "DeepBody", parent=styles["Normal"], fontSize=8.8, leading=12,
    )
    evidence_style = ParagraphStyle(
        "DeepEvidence", parent=styles["Code"], fontSize=7.2, leading=9.5,
        backColor=colors.HexColor("#F3F4F6"), borderPadding=5, spaceAfter=6,
    )

    stats = correlation.get("stats") or {}
    groups = correlation.get("groups") or []
    breakdown = stats.get("severity_breakdown") or {}
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    story = [Spacer(1, 30), Paragraph("AEGIS-AI :: DEEP ENGINE", title_style)]
    story.append(Paragraph("Unified evidence report · 11 real scanning modules", sub_style))

    meta = [
        ["Classification", "CONFIDENTIAL · user-configured localhost scope"],
        ["Generated", generated],
        ["Correlation mode", _esc(correlation.get("mode") or "deterministic")],
        ["Raw real findings", str(stats.get("raw_findings", 0))],
        ["Unified groups", str(stats.get("unified_groups", 0))],
        ["Multi-tool confirmed", str(stats.get("multi_tool_correlations", 0))],
        ["Severity", (
            f"CRITICAL {breakdown.get('CRITICAL', 0)} · HIGH {breakdown.get('HIGH', 0)} · "
            f"MEDIUM {breakdown.get('MEDIUM', 0)} · LOW {breakdown.get('LOW', 0)} · INFO {breakdown.get('INFO', 0)}"
        )],
        ["Evidence policy", "Real tool output only · no synthetic findings, no placeholder metrics"],
        ["Execution policy", "No exploit, no payload, no destructive test · approval-gated remediation"],
    ]
    table = Table(meta, colWidths=[150, 360])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3E8FF")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#581C87")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(table)
    story.append(Spacer(1, 14))

    ai_summary = correlation.get("ai_summary") or ""
    if ai_summary:
        story.append(Paragraph("AI Explanation (evidence-bound)", h2_style))
        story.append(Paragraph(_esc(ai_summary)[:1800], body_style))
        story.append(Spacer(1, 8))

    story.append(Paragraph("Unified Findings", h2_style))
    if not groups:
        story.append(Paragraph("No real deep-scan findings are stored yet.", body_style))
    else:
        rows = [["#", "Severity", "Finding", "Source tools", "Confidence"]]
        for index, group in enumerate(groups[:60], start=1):
            rows.append([
                str(index),
                _esc(group.get("severity") or "-"),
                _esc(str(group.get("title") or "")[:85]),
                _esc(", ".join(group.get("source_tools") or [])[:70]),
                _esc(group.get("confidence") or "-"),
            ])
        summary_table = Table(rows, colWidths=[24, 62, 232, 116, 76], repeatRows=1)
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#581C87")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9CA3AF")),
            ("FONTSIZE", (0, 0), (-1, -1), 7.4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FAFAFC")]),
        ]))
        story.append(summary_table)

        story.append(PageBreak())
        story.append(Paragraph("Evidence Detail", h2_style))
        for index, group in enumerate(groups[:60], start=1):
            loc = group.get("endpoint") or (
                f"{group.get('file')}:{group.get('line')}" if group.get("file") else "endpoint/file: -"
            )
            story.append(Paragraph(
                f"<b>{index}. {_esc(str(group.get('title') or '')[:150])}</b> "
                f"[{_esc(group.get('severity') or '-')}]", body_style,
            ))
            story.append(Paragraph(
                f"Location: {_esc(loc)[:220]}<br/>"
                f"Source tools: {_esc(', '.join(group.get('source_tools') or []))}<br/>"
                f"Confidence: {_esc(group.get('confidence') or '-')}"
                + (f"<br/>CVE: {_esc(', '.join(group.get('cve') or []))}" if group.get("cve") else ""),
                body_style,
            ))
            for piece in (group.get("evidence") or [])[:6]:
                story.append(Paragraph(_esc(str(piece)[:420]), evidence_style))
            if group.get("remediation"):
                story.append(Paragraph(f"FIX: {_esc(str(group['remediation'])[:350])}", body_style))
            if group.get("ai_explanation"):
                story.append(Paragraph(f"AI: {_esc(str(group['ai_explanation'])[:700])}", body_style))
            story.append(Spacer(1, 10))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return path
