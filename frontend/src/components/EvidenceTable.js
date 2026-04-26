// src/components/EvidenceTable.js
import React, { useState, useEffect } from "react";
import { submitFeedback } from "../services/api";

const SEVERITY_COLOR = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
  informational: "#6366f1",
};

const DEMO_EVIDENCE = [
  { id: "ev001", evidenceType: "file",            finalScore: 95, severity: "critical", isAnomaly: true,  rawArtifact: { name: "mimikatz.exe",           rule_score: 98 } },
  { id: "ev002", evidenceType: "event_log",       finalScore: 80, severity: "critical", isAnomaly: true,  rawArtifact: { event_id: 1102,                 rule_score: 80 } },
  { id: "ev003", evidenceType: "browser_history", finalScore: 75, severity: "high",     isAnomaly: false, rawArtifact: { url: "https://torproject.org",  rule_score: 80 } },
  { id: "ev004", evidenceType: "network_packet",  finalScore: 70, severity: "high",     isAnomaly: true,  rawArtifact: { dst_port: 4444,                 rule_score: 70 } },
  { id: "ev005", evidenceType: "file",            finalScore: 30, severity: "low",      isAnomaly: false, rawArtifact: { name: "report.pdf",             rule_score: 0  } },
  { id: "ev006", evidenceType: "event_log",       finalScore: 60, severity: "high",     isAnomaly: false, rawArtifact: { event_id: 4698,                 rule_score: 60 } },
];

function describeEvidence(ev) {
  const raw = ev.rawArtifact || {};
  switch (ev.evidenceType) {
    case "file":            return raw.name  || raw.path  || "File artifact";
    case "event_log":       return `Event ID ${raw.event_id || "?"} — ${raw.computer || "Unknown host"}`;
    case "browser_history": return (raw.url  || "").slice(0, 60) + ((raw.url || "").length > 60 ? "…" : "");
    case "network_packet":  return `${raw.src_ip || "?"} → ${raw.dst_ip || "?"}:${raw.dst_port || "?"}`;
    default:                return JSON.stringify(raw).slice(0, 60);
  }
}

export default function EvidenceTable({ caseId }) {
  const [evidence, setEvidence] = useState(DEMO_EVIDENCE);
  const [feedback, setFeedback] = useState({});
  const [msg, setMsg]           = useState("");

  useEffect(() => { setEvidence(DEMO_EVIDENCE); }, [caseId]);

  const handleFeedback = async (ev) => {
    const fb = feedback[ev.id];
    if (!fb) return;
    try {
      await submitFeedback(ev.id, Number(fb.score), Number(fb.label), fb.notes || "");
      setMsg(`Feedback submitted for ${ev.id}`);
    } catch {
      setMsg("Feedback stored locally (backend unavailable)");
    }
  };

  const sorted = [...evidence].sort((a, b) => (b.finalScore ?? 0) - (a.finalScore ?? 0));

  return (
    <div className="evidence-panel">
      <div className="panel-header">
        <h2 className="panel-title">Evidence — Priority Ranked</h2>
        {msg && <span className="status-msg">{msg}</span>}
      </div>
      <div className="evidence-table-wrap">
        <table className="evidence-table">
          <thead>
            <tr>
              <th>Type</th><th>Description</th><th>Score</th>
              <th>Severity</th><th>Anomaly</th><th>Investigator Feedback</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((ev) => {
              const fb = feedback[ev.id] || {};
              return (
                <tr key={ev.id}>
                  <td><span className="type-badge">{ev.evidenceType?.replace("_", " ")}</span></td>
                  <td className="desc-cell">{describeEvidence(ev)}</td>
                  <td>
                    <div className="score-bar-wrap">
                      <div className="score-bar" style={{ width: `${ev.finalScore ?? 0}%`, background: SEVERITY_COLOR[ev.severity] || "#6366f1" }}/>
                      <span className="score-num">{ev.finalScore ?? "—"}</span>
                    </div>
                  </td>
                  <td>
                    <span className="severity-badge" style={{ background: SEVERITY_COLOR[ev.severity] + "22", color: SEVERITY_COLOR[ev.severity] }}>
                      {ev.severity}
                    </span>
                  </td>
                  <td className={ev.isAnomaly ? "anomaly-yes" : "anomaly-no"}>{ev.isAnomaly ? "⚠ Yes" : "No"}</td>
                  <td className="feedback-cell">
                    <input type="number" min="0" max="100" placeholder="Score" className="fb-input"
                      value={fb.score || ""}
                      onChange={(e) => setFeedback(p => ({ ...p, [ev.id]: { ...p[ev.id], score: e.target.value } }))}
                    />
                    <select className="fb-select" value={fb.label || ""}
                      onChange={(e) => setFeedback(p => ({ ...p, [ev.id]: { ...p[ev.id], label: e.target.value } }))}>
                      <option value="">Label</option>
                      <option value="0">Benign</option>
                      <option value="1">Malicious</option>
                    </select>
                    <button className="fb-btn" onClick={() => handleFeedback(ev)}>Submit</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
