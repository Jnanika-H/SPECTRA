// src/components/IngestPanel.js
import React, { useState } from "react";
import { ingestEvidence } from "../services/api";

const DEMO_ARTIFACTS = [
  { type: "file",            name: "mimikatz.exe",          rule_score: 98, features: { network_activity: 0.0,  session_time: 0.0, data_transfer: 0.01, connection_status: 2 } },
  { type: "event_log",       event_id: 1102,                rule_score: 80, features: { network_activity: 0.1,  session_time: 1.0, data_transfer: 0.0,  connection_status: 2 } },
  { type: "browser_history", url: "https://torproject.org", rule_score: 80, features: { network_activity: 0.12, session_time: 0.0, data_transfer: 0.0,  connection_status: 2 } },
  { type: "network_packet",  src_ip: "192.168.1.50", dst_ip: "185.220.101.1", dst_port: 4444, rule_score: 70, features: { network_activity: 0.5, session_time: 0.0, data_transfer: 0.01, connection_status: 2 } },
  { type: "event_log",       event_id: 4625,                rule_score: 60, features: { network_activity: 0.1,  session_time: 1.0, data_transfer: 0.0,  connection_status: 1 } },
];

export default function IngestPanel({ caseId, onIngested }) {
  const [mode, setMode]     = useState("demo");
  const [paths, setPaths]   = useState({ fs: "", evtx: "", chrome: "", pcap: "" });
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);

  const handleIngest = async () => {
    setLoading(true);
    try {
      const artifacts = mode === "demo" ? DEMO_ARTIFACTS : [];
      await ingestEvidence(caseId, artifacts);
      setStatus(`${artifacts.length} artifacts ingested into case ${caseId}`);
      onIngested && onIngested();
    } catch (e) {
      setStatus(`Ingest failed: ${e.response?.data?.message || e.message}`);
    } finally { setLoading(false); }
  };

  return (
    <div className="ingest-panel">
      <h2 className="panel-title">Ingest Evidence</h2>

      <div className="mode-tabs">
        {["demo", "paths"].map((m) => (
          <button key={m} className={`mode-tab ${mode === m ? "active" : ""}`} onClick={() => setMode(m)}>
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
              <input type="text" placeholder={ph} value={paths[key]}
                onChange={(e) => setPaths(p => ({ ...p, [key]: e.target.value }))}
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
