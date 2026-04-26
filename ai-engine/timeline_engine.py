"""
SPECTRA — Phase 1 (Part C): Timeline Engine
============================================
Extracts timestamps from all evidence artifacts, sorts chronologically,
groups related events, and generates a human-readable crime timeline.
"""

import sys
import logging
from datetime import datetime, timezone
from typing import Optional
from collections import defaultdict
from pathlib import Path

log = logging.getLogger("spectra.timeline")

# ── Event grouping rules ──────────────────────────────────────────────────────
GROUP_RULES = [
    {
        "name":    "Authentication Activity",
        "matches": lambda a: (a.get("type") == "event_log" and
                              a.get("event_id") in {4625, 4648, 4776, 4720}),
        "color":   "#EF4444",
    },
    {
        "name":    "TOR / Dark Web Access",
        "matches": lambda a: (a.get("type") == "browser_history" and
                              ".onion" in str(a.get("url", "")) or
                              "torproject" in str(a.get("url", ""))),
        "color":   "#8B5CF6",
    },
    {
        "name":    "Suspicious Network Traffic",
        "matches": lambda a: (a.get("type") == "network_packet" and
                              a.get("suspicious_port", False)),
        "color":   "#F59E0B",
    },
    {
        "name":    "Risky File Activity",
        "matches": lambda a: (a.get("type") == "file" and
                              a.get("risk_flag") in {"high", "medium"}),
        "color":   "#EC4899",
    },
    {
        "name":    "Audit Log Manipulation",
        "matches": lambda a: (a.get("type") == "event_log" and
                              a.get("event_id") in {1102, 104}),
        "color":   "#DC2626",
    },
    {
        "name":    "Scheduled Task / Service",
        "matches": lambda a: (a.get("type") == "event_log" and
                              a.get("event_id") in {4698, 7045}),
        "color":   "#0EA5E9",
    },
]


def _extract_timestamp(artifact: dict) -> Optional[datetime]:
    """Try all known timestamp fields, return UTC datetime."""
    for field in ("timestamp", "created_at", "modified_at", "accessed_at"):
        raw = artifact.get(field)
        if not raw:
            continue
        try:
            if isinstance(raw, str):
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            else:
                dt = raw
            return dt.astimezone(timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


def _assign_group(artifact: dict) -> str:
    for rule in GROUP_RULES:
        try:
            if rule["matches"](artifact):
                return rule["name"]
        except Exception:
            pass
    return "General Activity"


def build_timeline(artifacts: list[dict]) -> dict:
    """
    Input:  flat list of artifacts (from EvidenceCollector)
    Output: {
        "events":  [ { timestamp, group, description, severity, artifact } ],
        "summary": { ... },
        "groups":  { group_name: [events] },
    }
    """
    events = []

    for artifact in artifacts:
        ts = _extract_timestamp(artifact)
        if not ts:
            continue

        group = _assign_group(artifact)
        description = _describe(artifact)
        score = artifact.get("final_score") or artifact.get("rule_score") or 0

        severity = (
            "critical" if score >= 80 else
            "high"     if score >= 60 else
            "medium"   if score >= 40 else
            "low"
        )

        events.append({
            "timestamp":   ts.isoformat(),
            "epoch":       ts.timestamp(),
            "group":       group,
            "description": description,
            "severity":    severity,
            "threat_score": score,
            "artifact_type": artifact.get("type", "unknown"),
            "artifact":    artifact,
        })

    # Sort chronologically
    events.sort(key=lambda e: e["epoch"])

    # Group events
    grouped: dict[str, list] = defaultdict(list)
    for ev in events:
        grouped[ev["group"]].append(ev)

    # Build summary
    summary = {
        "total_events":    len(events),
        "critical_events": sum(1 for e in events if e["severity"] == "critical"),
        "high_events":     sum(1 for e in events if e["severity"] == "high"),
        "time_range": {
            "start": events[0]["timestamp"] if events else None,
            "end":   events[-1]["timestamp"] if events else None,
        },
        "groups":          {g: len(v) for g, v in grouped.items()},
        "top_threats":     sorted(events, key=lambda e: e["threat_score"], reverse=True)[:5],
    }

    log.info(f"Timeline built: {len(events)} events across {len(grouped)} groups")
    return {
        "events":  events,
        "summary": summary,
        "groups":  dict(grouped),
    }


def _describe(artifact: dict) -> str:
    t = artifact.get("type", "")
    if t == "file":
        return f"File accessed: {artifact.get('name', '')} ({artifact.get('extension', '')}, {artifact.get('size_bytes', 0):,} bytes)"
    elif t == "event_log":
        return f"Event ID {artifact.get('event_id')} on {artifact.get('computer', '?')} by {artifact.get('user', '?')}"
    elif t == "browser_history":
        url = artifact.get("url", "")
        return f"Browser visit: {url[:80]}{'…' if len(url) > 80 else ''}"
    elif t == "network_packet":
        return f"Network packet: {artifact.get('src_ip')} → {artifact.get('dst_ip')}:{artifact.get('dst_port')} ({artifact.get('size_bytes', 0)} bytes)"
    return "Unknown artifact"


def render_text_timeline(timeline: dict) -> str:
    """Human-readable text report."""
    lines = [
        "=" * 60,
        "  SPECTRA — CRIME TIMELINE RECONSTRUCTION",
        "=" * 60,
        f"  Total events : {timeline['summary']['total_events']}",
        f"  Critical     : {timeline['summary']['critical_events']}",
        f"  High         : {timeline['summary']['high_events']}",
        "",
    ]
    if timeline["events"]:
        lines.append(f"  Time range   : {timeline['summary']['time_range']['start']}")
        lines.append(f"               → {timeline['summary']['time_range']['end']}")
    lines += ["", "─" * 60, "  CHRONOLOGICAL EVENT LOG", "─" * 60]

    for ev in timeline["events"]:
        severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(ev["severity"], "⚪")
        lines.append(
            f"  {severity_icon} [{ev['timestamp']}]  Score:{ev['threat_score']:>3}  {ev['group']}\n"
            f"       {ev['description']}"
        )

    lines += ["", "─" * 60, "  GROUP SUMMARY", "─" * 60]
    for group, count in timeline["summary"]["groups"].items():
        lines.append(f"  • {group:<40} {count:>4} events")

    return "\n".join(lines)


if __name__ == "__main__":
    # Quick test with mock data
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "ingestion"))
    from evidence_collector import (
        BrowserHistoryParser, EventLogParser, NetworkPacketParser
    )
    mock = (
        BrowserHistoryParser()._mock_history()
        + EventLogParser()._mock_events()
        + NetworkPacketParser()._mock_packets()
    )
    timeline = build_timeline(mock)
    print(render_text_timeline(timeline))
