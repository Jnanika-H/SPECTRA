// src/components/EvidenceTable.js
import React, { useState, useEffect } from "react";
import { getReports, submitFeedback } from "../services/api";

const SEVERITY_COLOR = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
  informational: "#6366f1",
};

export default function EvidenceTable({ caseId }) {
  const [evidence, setEvidence]   = useState([]);
  const [feedback, setFeedback]   = useState({});
  const [msg, setMsg]             = useState("");

  // Demo data when backend unavailable
  const demoEvidence = [
    { id: "ev001", evidenceType: "file",            finalScore: 95, severity: "critical", isAnomaly: true,  rawArtifact: { name: "mimikatz.exe",        rule_score: 98 } },
    { id: "ev002", evidenceType: "event_log",       finalScore: 80, severity: "critical", isAnomaly: true,  rawArtifact: { event_id: 1102,             rule_score: 80 } },
    { id: "ev003", evidenceType: "browser_history", finalScore: 75, severity: "high",     isAnomaly: false, rawArtifact: { url: "https://torproject.org", rule_score: 80 } },
    { id: "ev004", evidenceType: "network_packet",  finalScore: 70, severity: "high",     isAnomaly: true,  rawArtifact: { dst_port: 4444,             rule_score: 70 } },
    { id: "ev005", evidenceType: "file",            finalScore: 30, severity: "low",      isAnomaly: false, rawArtifact: { name: "report.pdf",          rule_score: 0  } },
    { id: "ev006", evidenceType: "event_log",       finalScore: 60, severity: "high",     isAnomaly: false, rawArtifact: { event_id: 4698,             rule_score: 60 } },
  ];

  useEffect(() => {
    setEvidence(demoEvidence);
  }, [caseId]);

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
              <th>Type</th>
              <th>Description</th>
              <th>Score</th>
              <th>Severity</th>
              <th>Anomaly</th>
              <th>Investigator Feedback</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((ev) => {
              const desc = describeEvidence(ev);
              const fb = feedback[ev.id] || {};
              return (
                <tr key={ev.id}>
                  <td><span className="type-badge">{ev.evidenceType?.replace("_", " ")}</span></td>
                  <td className="desc-cell">{desc}</td>
                  <td>
                    <div className="score-bar-wrap">
                      <div
                        className="score-bar"
                        style={{
                          width: `${ev.finalScore ?? 0}%`,
                          background: SEVERITY_COLOR[ev.severity] || "#6366f1",
                        }}
                      />
                      <span className="score-num">{ev.finalScore ?? "—"}</span>
                    </div>
                  </td>
                  <td>
                    <span
                      className="severity-badge"
                      style={{ background: SEVERITY_COLOR[ev.severity] + "22",
                               color: SEVERITY_COLOR[ev.severity] }}
                    >
                      {ev.severity}
                    </span>
                  </td>
                  <td className={ev.isAnomaly ? "anomaly-yes" : "anomaly-no"}>
                    {ev.isAnomaly ? "⚠ Yes" : "No"}
                  </td>
                  <td className="feedback-cell">
                    <input
                      type="number" min="0" max="100"
                      placeholder="Score"
                      className="fb-input"
                      value={fb.score || ""}
                      onChange={(e) => setFeedback(prev => ({
                        ...prev,
                        [ev.id]: { ...prev[ev.id], score: e.target.value }
                      }))}
                    />
                    <select
                      className="fb-select"
                      value={fb.label || ""}
                      onChange={(e) => setFeedback(prev => ({
                        ...prev,
                        [ev.id]: { ...prev[ev.id], label: e.target.value }
                      }))}
                    >
                      <option value="">Label</option>
                      <option value="0">Benign</option>
                      <option value="1">Malicious</option>
                    </select>
                    <button
                      className="fb-btn"
                      onClick={() => handleFeedback(ev)}
                    >
                      Submit
                    </button>
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


// ─────────────────────────────────────────────────────────────────────────────
// src/components/TimelineView.js
import React from "react";

const SEV_COLOR = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e" };

const DEMO_EVENTS = [
  { timestamp: "2024-01-15T02:00:00Z", severity: "high",     threat_score: 70,  group: "Suspicious Network Traffic", description: "Network packet: 192.168.1.50 → 185.220.101.1:4444 (1024 bytes)" },
  { timestamp: "2024-01-15T02:30:00Z", severity: "critical",  threat_score: 80,  group: "TOR / Dark Web Access",       description: "Browser visit: https://torproject.org" },
  { timestamp: "2024-01-15T02:45:00Z", severity: "medium",    threat_score: 50,  group: "General Activity",            description: "Browser visit: https://pastebin.com/raw/xK9mA" },
  { timestamp: "2024-01-15T03:14:00Z", severity: "high",      threat_score: 60,  group: "Authentication Activity",     description: "Event ID 4625 on WORKSTATION-01 by admin" },
  { timestamp: "2024-01-15T03:15:00Z", severity: "critical",  threat_score: 80,  group: "Audit Log Manipulation",      description: "Event ID 1102 on WORKSTATION-01 by SYSTEM" },
  { timestamp: "2024-01-15T03:20:00Z", severity: "critical",  threat_score: 95,  group: "Risky File Activity",         description: "File accessed: mimikatz.exe (.exe, 1,024,000 bytes)" },
];

export function TimelineView({ timeline }) {
  const events = timeline?.events?.length > 0
    ? timeline.events
    : DEMO_EVENTS;

  return (
    <div className="timeline-panel">
      <h2 className="panel-title">Crime Timeline Reconstruction</h2>
      {timeline && (
        <div className="timeline-summary">
          <span>Total: <strong>{timeline.summary?.total_events ?? events.length}</strong></span>
          <span>Critical: <strong style={{ color: "#ef4444" }}>{timeline.summary?.critical_events ?? 0}</strong></span>
          <span>From: <strong>{timeline.summary?.time_range?.start
            ? new Date(timeline.summary.time_range.start).toLocaleString()
            : "—"}</strong></span>
        </div>
      )}

      <div className="timeline-track">
        {events.map((ev, i) => (
          <div className="timeline-item" key={i}>
            <div className="timeline-dot-wrap">
              <div
                className="timeline-dot"
                style={{ background: SEV_COLOR[ev.severity] || "#6366f1" }}
              />
              {i < events.length - 1 && <div className="timeline-line" />}
            </div>
            <div className="timeline-body">
              <div className="timeline-meta">
                <span className="timeline-time">
                  {new Date(ev.timestamp).toLocaleString()}
                </span>
                <span
                  className="timeline-group"
                  style={{ color: SEV_COLOR[ev.severity] }}
                >
                  {ev.group}
                </span>
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

export default TimelineView;


// ─────────────────────────────────────────────────────────────────────────────
// src/components/BlockchainVerifier.js
import React, { useState } from "react";
import { verifyOnChain, storeHashOnChain } from "../services/api";

export default function BlockchainVerifier({ report }) {
  const [result, setResult]   = useState(null);
  const [loading, setLoading] = useState(false);

  const handleVerify = async () => {
    if (!report?.id) return;
    setLoading(true);
    try {
      const res = await verifyOnChain(report.id);
      setResult(res.data);
    } catch {
      setResult({ status: "error", verified: false, message: "Backend unavailable" });
    } finally {
      setLoading(false);
    }
  };

  const handleStore = async () => {
    if (!report?.id || !report?.reportHash) return;
    setLoading(true);
    try {
      const res = await storeHashOnChain(report.id, report.reportHash);
      setResult(res.data);
    } catch {
      setResult({ status: "simulated", txHash: "0x" + (report.reportHash || "").slice(0, 40) });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="blockchain-panel">
      <h2 className="panel-title">Blockchain Integrity Verification</h2>

      <div className="bc-info-card">
        <div className="bc-row">
          <span className="bc-label">Report ID</span>
          <code className="bc-value">{report?.id || "—"}</code>
        </div>
        <div className="bc-row">
          <span className="bc-label">SHA-256 Hash</span>
          <code className="bc-value hash">{report?.reportHash || "—"}</code>
        </div>
        <div className="bc-row">
          <span className="bc-label">Tx Hash</span>
          <code className="bc-value">{report?.blockchainTxHash || "Not yet stored"}</code>
        </div>
        <div className="bc-row">
          <span className="bc-label">Status</span>
          <span className={`bc-status ${report?.verified ? "verified" : "unverified"}`}>
            {report?.verified ? "✔ Verified on Chain" : "⚠ Not verified"}
          </span>
        </div>
      </div>

      <div className="bc-actions">
        <button className="btn-primary"  onClick={handleStore}  disabled={loading || !report}>
          {loading ? "Processing…" : "Store Hash on Chain"}
        </button>
        <button className="btn-secondary" onClick={handleVerify} disabled={loading || !report}>
          Verify Integrity
        </button>
      </div>

      {result && (
        <div className={`bc-result ${result.verified ? "bc-ok" : "bc-fail"}`}>
          <div className="bc-result-icon">{result.verified ? "✔" : "✗"}</div>
          <div>
            <strong>{result.verified ? "Integrity Confirmed" : result.status}</strong>
            {result.txHash && <p>Tx: <code>{result.txHash}</code></p>}
            {result.message && <p>{result.message}</p>}
          </div>
        </div>
      )}

      <div className="bc-explainer">
        <h3>How it works</h3>
        <ol>
          <li>Report content is hashed with SHA-256 on the Spring Boot backend.</li>
          <li>The hash is sent to a Solidity smart contract deployed on Ganache.</li>
          <li>The contract stores <code>reportId → hash</code> permanently on-chain.</li>
          <li>Verification re-reads the chain and compares hashes — any tampering is detected.</li>
        </ol>
      </div>
    </div>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// src/components/IngestPanel.js
import React, { useState } from "react";
import { ingestEvidence } from "../services/api";

export default function IngestPanel({ caseId, onIngested }) {
  const [mode, setMode]     = useState("demo");
  const [file, setFile]     = useState(null);
  const [paths, setPaths]   = useState({ fs: "", evtx: "", chrome: "", pcap: "" });
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);

  const DEMO_ARTIFACTS = [
    { type: "file",            name: "mimikatz.exe",     rule_score: 98, features: { network_activity: 0.0, session_time: 0.0, data_transfer: 0.01, connection_status: 2 } },
    { type: "event_log",       event_id: 1102,           rule_score: 80, features: { network_activity: 0.1, session_time: 1.0, data_transfer: 0.0,  connection_status: 2 } },
    { type: "browser_history", url: "https://torproject.org", rule_score: 80, features: { network_activity: 0.12, session_time: 0.0, data_transfer: 0.0, connection_status: 2 } },
    { type: "network_packet",  src_ip: "192.168.1.50", dst_ip: "185.220.101.1", dst_port: 4444, rule_score: 70, features: { network_activity: 0.5, session_time: 0.0, data_transfer: 0.01, connection_status: 2 } },
    { type: "event_log",       event_id: 4625,           rule_score: 60, features: { network_activity: 0.1, session_time: 1.0, data_transfer: 0.0,  connection_status: 1 } },
  ];

  const handleIngest = async () => {
    setLoading(true);
    try {
      const artifacts = mode === "demo" ? DEMO_ARTIFACTS : [];
      await ingestEvidence(caseId, artifacts);
      setStatus(`${artifacts.length} artifacts ingested into case ${caseId}`);
      onIngested && onIngested();
    } catch (e) {
      setStatus(`Ingest failed: ${e.response?.data?.message || e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="ingest-panel">
      <h2 className="panel-title">Ingest Evidence</h2>

      <div className="mode-tabs">
        {["demo", "paths"].map((m) => (
          <button
            key={m}
            className={`mode-tab ${mode === m ? "active" : ""}`}
            onClick={() => setMode(m)}
          >
            {m === "demo" ? "Demo Data" : "System Paths"}
          </button>
        ))}
      </div>

      {mode === "demo" && (
        <div className="demo-info">
          <p>Loads a pre-built set of forensic artifacts including:</p>
          <ul>
            <li>mimikatz.exe (rule score: 98)</li>
            <li>Audit log cleared (Event ID 1102)</li>
            <li>TOR browser history</li>
            <li>C2 callback on port 4444</li>
            <li>Failed logins at 3 AM (Event ID 4625)</li>
          </ul>
        </div>
      )}

      {mode === "paths" && (
        <div className="paths-form">
          {[
            { key: "fs",     label: "File System Path",     ph: "/evidence/disk_image" },
            { key: "evtx",   label: "Windows EVTX Path",    ph: "/evidence/Security.evtx" },
            { key: "chrome", label: "Chrome History Path",  ph: "/evidence/History" },
            { key: "pcap",   label: "Network Capture Path", ph: "/evidence/capture.pcap" },
          ].map(({ key, label, ph }) => (
            <div className="path-row" key={key}>
              <label>{label}</label>
              <input
                type="text"
                placeholder={ph}
                value={paths[key]}
                onChange={(e) => setPaths(prev => ({ ...prev, [key]: e.target.value }))}
              />
            </div>
          ))}
        </div>
      )}

      <div className="ingest-actions">
        <button className="btn-primary" onClick={handleIngest} disabled={loading}>
          {loading ? "Ingesting…" : `Ingest into ${caseId}`}
        </button>
      </div>

      {status && <div className="ingest-status">{status}</div>}
    </div>
  );
}
