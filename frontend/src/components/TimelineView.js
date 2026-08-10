import React from "react";

// Group-specific colors (matching timeline_engine.py)
const GROUP_COLOR = {
  "Authentication Activity": "#EF4444",      // Red
  "TOR / Dark Web Access": "#8B5CF6",        // Purple
  "Suspicious Network Traffic": "#F59E0B",   // Amber
  "Risky File Activity": "#f97316",          // Orange
  "Audit Log Manipulation": "#DC2626",       // Dark Red
  "Scheduled Task / Service": "#0EA5E9",     // Sky Blue
  "General Activity": "#22c55e"              // Green (safe files)
};

// Fallback severity colors
const SEV_COLOR = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e"
};

export default function TimelineView({ timeline }) {
  const events = timeline?.events || [];

  return (
    <div className="timeline-panel">
      <h2 className="panel-title">Crime Timeline Reconstruction</h2>

      {timeline?.summary && (
        <div className="timeline-summary">
          <span>Total: <strong>{timeline.summary.total_events}</strong></span>
          <span>Critical: <strong style={{ color: "#ef4444" }}>
            {timeline.summary.critical_events}
          </strong></span>
          <span>From: <strong>
            {timeline.summary.time_range?.start
              ? new Date(timeline.summary.time_range.start).toLocaleString()
              : "—"}
          </strong></span>
        </div>
      )}

      {events.length === 0 ? (
        <div style={{ padding: "40px", textAlign: "center", color: "#94a3b8" }}>
          <p>No timeline data available yet.</p>
          <p style={{ marginTop: "10px", fontSize: "13px" }}>
            Go to <strong>Ingest</strong> tab → add evidence → click Ingest → click <strong>Run Analysis</strong>
          </p>
        </div>
      ) : (
        <div className="timeline-track">
          {events.map((ev, i) => {
            // Use group color if available, otherwise fall back to severity color
            const dotColor = GROUP_COLOR[ev.group] || SEV_COLOR[ev.severity] || "#6366f1";
            
            return (
              <div className="timeline-item" key={i}>
                <div className="timeline-dot-wrap">
                  <div className="timeline-dot"
                    style={{ background: dotColor }}/>
                  {i < events.length - 1 && <div className="timeline-line"/>}
                </div>
                <div className="timeline-body">
                  <div className="timeline-meta">
                    <span className="timeline-time">
                      {new Date(ev.timestamp).toLocaleString()}
                    </span>
                    <span className="timeline-group"
                      style={{ color: dotColor }}>
                      {ev.group}
                    </span>
                    <span className="timeline-score">Score: {ev.threat_score}</span>
                  </div>
                  <p className="timeline-desc">{ev.description}</p>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}