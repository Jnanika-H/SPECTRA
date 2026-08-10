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
      let artifacts;
      if (mode === "demo") {
        artifacts = DEMO_ARTIFACTS;
      } else {
        // Send paths to backend for real evidence collection
        const config = {};
        if (paths.fs) config.fs_path = paths.fs;
        if (paths.evtx) config.evtx_path = paths.evtx;
        if (paths.chrome) config.chrome_history = paths.chrome;
        if (paths.pcap) config.pcap_path = paths.pcap;
        
        if (Object.keys(config).length === 0) {
          setStatus("Please enter at least one path");
          setLoading(false);
          return;
        }
        
        // Send config to backend as array (backend expects List)
        artifacts = [{ mode: "collect", config }];
      }
      
      await ingestEvidence(caseId, artifacts);
      setStatus(`Evidence ingested into case ${caseId}. Click Run Analysis.`);
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
          <div className="info-box" style={{
            background: '#fff3cd', 
            border: '1px solid #ffc107', 
            padding: '12px', 
            borderRadius: '4px',
            marginBottom: '15px',
            fontSize: '14px',
            color: '#856404'  // Dark yellow/brown text for better contrast
          }}>
            <strong style={{color: '#856404'}}>⚠️ Large Folder Scanning:</strong>
            <ul style={{margin: '8px 0', paddingLeft: '20px', color: '#856404'}}>
              <li>Maximum 1,000 files per scan (prevents timeouts)</li>
              <li>Automatically skips: node_modules, .git, __pycache__, etc.</li>
              <li>For large folders (Downloads, Desktop), consider scanning subfolders</li>
              <li>Example: <code style={{background: '#ffeaa7', padding: '2px 4px', borderRadius: '3px', color: '#2d3436'}}>C:\Users\YourName\Documents</code> instead of entire Desktop</li>
            </ul>
          </div>
          
          {[
            { key: "fs",     label: "File System Path",     ph: "C:\\Users\\YourName\\Documents" },
            { key: "evtx",   label: "Windows EVTX Path",    ph: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx" },
            { key: "chrome", label: "Chrome History Path",  ph: "C:\\Users\\YourName\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History" },
            { key: "pcap",   label: "Network Capture Path", ph: "C:\\Evidence\\capture.pcap" },
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
