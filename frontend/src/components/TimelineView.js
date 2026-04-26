// src/components/TimelineView.js
import React from "react";

const SEV_COLOR = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e" };

const DEMO_EVENTS = [
  { timestamp: "2024-01-15T02:00:00Z", severity: "high",     threat_score: 70, group: "Suspicious Network Traffic", description: "Network packet: 192.168.1.50 → 185.220.101.1:4444 (1024 bytes)" },
  { timestamp: "2024-01-15T02:30:00Z", severity: "critical",  threat_score: 80, group: "TOR / Dark Web Access",       description: "Browser visit: https://torproject.org" },
  { timestamp: "2024-01-15T02:45:00Z", severity: "medium",    threat_score: 50, group: "General Activity",            description: "Browser visit: https://pastebin.com/raw/xK9mA" },
  { timestamp: "2024-01-15T03:14:00Z", severity: "high",      threat_score: 60, group: "Authentication Activity",     description: "Event ID 4625 on WORKSTATION-01 by admin (failed login)" },
  { timestamp: "2024-01-15T03:15:00Z", severity: "critical",  threat_score: 80, group: "Audit Log Manipulation",      description: "Event ID 1102 on WORKSTATION-01 — audit log cleared" },
  { timestamp: "2024-01-15T03:20:00Z", severity: "critical",  threat_score: 95, group: "Risky File Activity",         description: "File accessed: mimikatz.exe (.exe, 1,024,000 bytes)" },
];

export default function TimelineView({ timeline }) {
  const events = timeline?.events?.length > 0 ? timeline.events : DEMO_EVENTS;

  return (
    <div className="timeline-panel">
      <h2 className="panel-title">Crime Timeline Reconstruction</h2>

      {timeline?.summary && (
        <div className="timeline-summary">
          <span>Total: <strong>{timeline.summary.total_events}</strong></span>
          <span>Critical: <strong style={{ color: "#ef4444" }}>{timeline.summary.critical_events}</strong></span>
          <span>From: <strong>{timeline.summary.time_range?.start
            ? new Date(timeline.summary.time_range.start).toLocaleString() : "—"}</strong></span>
        </div>
      )}

      <div className="timeline-track">
        {events.map((ev, i) => (
          <div className="timeline-item" key={i}>
            <div className="timeline-dot-wrap">
              <div className="timeline-dot" style={{ background: SEV_COLOR[ev.severity] || "#6366f1" }}/>
              {i < events.length - 1 && <div className="timeline-line"/>}
            </div>
            <div className="timeline-body">
              <div className="timeline-meta">
                <span className="timeline-time">{new Date(ev.timestamp).toLocaleString()}</span>
                <span className="timeline-group" style={{ color: SEV_COLOR[ev.severity] }}>{ev.group}</span>
                <span className="timeline-score">Score: {ev.threat_score}</span>
              </div>
              <p className="timeline-desc">{ev.description}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
