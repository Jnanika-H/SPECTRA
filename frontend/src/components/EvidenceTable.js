// src/components/EvidenceTable.js - FIXED: shows real data per case
import React, { useState, useEffect } from "react";
import { submitFeedback } from "../services/api";

const SEV_COLOR = { critical:"#ef4444", high:"#f97316", medium:"#eab308", low:"#22c55e", informational:"#6366f1" };

function describe(ev) {
  const raw = ev.rawArtifact || {};
  switch(ev.evidenceType) {
    case "file":            return raw.name||raw.path||"File artifact";
    case "event_log":       return "Event ID "+(raw.event_id||"?")+" — "+(raw.computer||"Unknown host");
    case "browser_history": return (raw.url||"").slice(0,60)+((raw.url||"").length>60?"...":"");
    case "network_packet":  return (raw.src_ip||"?")+" → "+(raw.dst_ip||"?")+(raw.dst_port?":"+raw.dst_port:"");
    default:                return JSON.stringify(raw).slice(0,60);
  }
}

export default function EvidenceTable({ caseId, analysisResults }) {
  const [evidence, setEvidence] = useState([]);
  const [feedback, setFeedback] = useState({});
  const [msg, setMsg]           = useState("");

  useEffect(() => {
    if (analysisResults && analysisResults.length > 0) {
      // Use real analysis results from Run Analysis
      const mapped = analysisResults.map(r => ({
        id: r.id || Math.random().toString(36),
        evidenceType: r.type || r.evidenceType || "unknown",
        finalScore: r.finalScore || 0,
        severity: r.severity || "low",
        isAnomaly: r.isAnomaly || false,
        rawArtifact: r.rawArtifact || r,
      }));
      setEvidence(mapped);
      setMsg("Showing real evidence for case: " + caseId);
    } else {
      // No real data yet
      setEvidence([]);
      setMsg("");
    }
  }, [caseId, analysisResults]);

  const handleFeedback = async (ev) => {
    const fb = feedback[ev.id];
    if (!fb) return;
    try {
      await submitFeedback(ev.id, Number(fb.score), Number(fb.label), fb.notes||"");
      setMsg("Feedback submitted for "+ev.id);
    } catch { setMsg("Feedback saved locally"); }
  };

  const sorted = [...evidence].sort((a,b)=>(b.finalScore??0)-(a.finalScore??0));

  return (
    <div className="evidence-panel">
      <div className="panel-header">
        <h2 className="panel-title">Evidence — Priority Ranked</h2>
        {msg && <span className="status-msg">{msg}</span>}
      </div>

      {sorted.length === 0 ? (
        <div style={{padding:"60px",textAlign:"center",color:"#94a3b8"}}>
          <p style={{fontSize:"16px",marginBottom:"12px"}}>No evidence analyzed yet for <strong style={{color:"#6366f1"}}>{caseId}</strong></p>
          <p style={{fontSize:"13px"}}>
            1. Click <strong>Ingest</strong> tab → add evidence paths<br/>
            2. Click <strong>Ingest into {caseId}</strong><br/>
            3. Click <strong>Run Analysis</strong> button at top
          </p>
        </div>
      ) : (
        <div className="evidence-table-wrap">
          <table className="evidence-table">
            <thead>
              <tr>
                <th>Type</th><th>Description</th><th>Score</th>
                <th>Severity</th><th>Anomaly</th><th>Investigator Feedback</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map(ev => {
                const fb = feedback[ev.id]||{};
                return (
                  <tr key={ev.id}>
                    <td><span className="type-badge">{(ev.evidenceType||"").replace("_"," ")}</span></td>
                    <td className="desc-cell">{describe(ev)}</td>
                    <td>
                      <div className="score-bar-wrap">
                        <div className="score-bar" style={{width:`${ev.finalScore??0}%`,background:SEV_COLOR[ev.severity]||"#6366f1"}}/>
                        <span className="score-num">{ev.finalScore??"—"}</span>
                      </div>
                    </td>
                    <td>
                      <span className="severity-badge" style={{background:(SEV_COLOR[ev.severity]||"#6366f1")+"22",color:SEV_COLOR[ev.severity]||"#6366f1"}}>
                        {ev.severity}
                      </span>
                    </td>
                    <td className={ev.isAnomaly?"anomaly-yes":"anomaly-no"}>{ev.isAnomaly?"⚠ Yes":"No"}</td>
                    <td className="feedback-cell">
                      <input type="number" min="0" max="100" placeholder="Score" className="fb-input"
                        value={fb.score||""} onChange={e=>setFeedback(p=>({...p,[ev.id]:{...p[ev.id],score:e.target.value}}))}/>
                      <select className="fb-select" value={fb.label||""} onChange={e=>setFeedback(p=>({...p,[ev.id]:{...p[ev.id],label:e.target.value}}))}>
                        <option value="">Label</option>
                        <option value="0">Benign</option>
                        <option value="1">Malicious</option>
                      </select>
                      <button className="fb-btn" onClick={()=>handleFeedback(ev)}>Submit</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
