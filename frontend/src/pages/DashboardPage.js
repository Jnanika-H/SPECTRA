// src/pages/DashboardPage.js - FIXED VERSION
import React, { useState, useEffect, useCallback } from "react";
import { useAuth } from "../context/AuthContext";
import { getReports, analyzeCase, generateReport, triggerRetrain } from "../services/api";
import api from "../services/api";
import ThreatScoreChart   from "../components/ThreatScoreChart";
import TimelineView       from "../components/TimelineView";
import EvidenceTable      from "../components/EvidenceTable";
import BlockchainVerifier from "../components/BlockchainVerifier";
import IngestPanel        from "../components/IngestPanel";
import "./DashboardPage.css";

export default function DashboardPage() {
  const { user, logout } = useAuth();
  const [reports, setReports]         = useState([]);
  const [selected, setSelected]       = useState(null);
  const [loading, setLoading]         = useState(false);
  const [statusMsg, setStatusMsg]     = useState("");
  const [activeTab, setActiveTab]     = useState("overview");
  const [caseId, setCaseId]           = useState("CASE-001");
  const [caseInput, setCaseInput]     = useState("CASE-001");
  const [timeline, setTimeline]       = useState(null);
  const [analysisData, setAnalysisData] = useState(null);

  const fetchReports = useCallback(async () => {
    try {
      const res = await getReports();
      setReports(res.data || []);
    } catch { setStatusMsg("Could not load reports."); }
  }, []);

  useEffect(() => { fetchReports(); }, []);

  useEffect(() => {
    const report = reports.find(r => r.caseId === caseId);
    if (report) { setSelected(report); }
    else { setSelected(null); setTimeline(null); setAnalysisData(null); }
  }, [caseId, reports]);

  const handleAnalyze = async () => {
    setLoading(true);
    setStatusMsg("Running AI analysis...");
    setTimeline(null);
    setAnalysisData(null);
    try {
      const analysisRes = await analyzeCase(caseId);
      const aData = analysisRes.data;
      setAnalysisData(aData);
      if (aData.timeline) setTimeline(aData.timeline);
      setStatusMsg("Analysis complete. Generating report...");
      const rep = await generateReport(caseId);
      const newReport = { ...rep.data, timeline: aData.timeline, analysisResults: aData.results };
      setReports(prev => [newReport, ...prev.filter(r => r.caseId !== caseId)]);
      setSelected(newReport);
      setStatusMsg("Report generated and stored.");
    } catch (e) {
      setStatusMsg("Analysis failed: " + (e.response?.data?.message || e.message));
    } finally { setLoading(false); }
  };

  const handleCaseChange = (newId) => {
    setCaseId(newId);
    setCaseInput(newId);
    setActiveTab("overview");
    setTimeline(null);
    setAnalysisData(null);
  };

  const stats = selected ? [
    { label: "Total Evidence",   value: selected.totalEvidence ?? 0,                                          color: "#6366f1" },
    { label: "Critical",         value: selected.criticalCount ?? 0,                                          color: "#ef4444" },
    { label: "High Severity",    value: selected.highCount     ?? 0,                                          color: "#f97316" },
    { label: "Anomalies",        value: selected.anomalyCount  ?? 0,                                          color: "#a855f7" },
    { label: "Avg Threat Score", value: (selected.averageThreatScore !== undefined && selected.averageThreatScore !== null) ? Math.round(selected.averageThreatScore)+"/100" : "0/100", color: "#14b8a6" },
  ] : [];

  const sevDist = selected ? {
    labels: ["Critical","High","Medium","Low"],
    data: [selected.criticalCount??0, selected.highCount??0,
           Math.max(0,(selected.totalEvidence??0)-(selected.criticalCount??0)-(selected.highCount??0)-(selected.anomalyCount??0)),
           selected.anomalyCount??0],
    colors: ["#ef4444","#f97316","#eab308","#22c55e"],
  } : null;

  const buildBar = () => {
    const results = analysisData?.results || selected?.analysisResults || [];
    if (!results.length) return null;
    const ts = {file:[],event_log:[],browser_history:[],network_packet:[]};
    results.forEach(r => { const t=r.type||r.evidenceType||""; if(ts[t]) ts[t].push(r.finalScore||0); });
    const avg = a => a.length ? Math.round(a.reduce((x,y)=>x+y,0)/a.length) : 0;
    return { labels:["File","Event Log","Browser","Network"], data:[avg(ts.file),avg(ts.event_log),avg(ts.browser_history),avg(ts.network_packet)], colors:["#6366f1","#ef4444","#f97316","#14b8a6"] };
  };
  const barData = buildBar();

  const uniqueReports = reports.filter((r, i, self) => i === self.findIndex(t => t.caseId === r.caseId));

  return (
    <div className="dash-root">
      <aside className="dash-sidebar">
        <div className="sidebar-brand">
          <span className="sidebar-logo">S</span>
          <span className="sidebar-title">SPECTRA</span>
        </div>
        <nav className="sidebar-nav">
          {[
            {id:"overview",label:"Overview",icon:"⬡"},
            {id:"evidence",label:"Evidence",icon:"🗂"},
            {id:"timeline",label:"Timeline",icon:"⏱"},
            {id:"blockchain",label:"Blockchain",icon:"⛓"},
            {id:"ingest",label:"Ingest",icon:"＋"},
          ].map(tab => (
            <button key={tab.id} className={"sidebar-link"+(activeTab===tab.id?" active":"")} onClick={()=>setActiveTab(tab.id)}>
              <span className="sidebar-icon">{tab.icon}</span>{tab.label}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="sidebar-user">{user?.username}</div>
          <button className="sidebar-logout" onClick={logout}>Sign out</button>
        </div>
      </aside>

      <main className="dash-main">
        <header className="dash-topbar">
          <div className="topbar-left">
            <label className="topbar-label">Case:</label>
            <select className="topbar-select" value={caseId} onChange={e=>handleCaseChange(e.target.value)}>
              {uniqueReports.map(r => <option key={"opt-"+r.id+"-"+r.caseId} value={r.caseId}>{r.caseId}</option>)}
              {!uniqueReports.find(r=>r.caseId===caseId) && <option key={"opt-new-"+caseId} value={caseId}>{caseId}</option>}
            </select>
            <input className="topbar-caseid" placeholder="Enter case ID..." value={caseInput}
              onChange={e=>setCaseInput(e.target.value)}
              onKeyDown={e=>{if(e.key==="Enter")handleCaseChange(caseInput);}}
            />
            <button className="btn-secondary" style={{padding:"6px 10px",fontSize:"12px"}} onClick={()=>handleCaseChange(caseInput)}>Go</button>
          </div>
          <div className="topbar-right">
            {statusMsg && <span className="topbar-status">{statusMsg}</span>}
            <button className="btn-primary" onClick={handleAnalyze} disabled={loading}>{loading?"Analyzing...":"Run Analysis"}</button>
            <button className="btn-secondary" onClick={async()=>{setStatusMsg("Retraining...");try{const r=await triggerRetrain();setStatusMsg("Retrain: "+r.data.status);}catch{setStatusMsg("Retrain failed.");}}}>Retrain Model</button>
          </div>
        </header>

        <div className="dash-content">

          {activeTab==="overview" && (
            <>
              {!selected ? (
                <div style={{padding:"60px",textAlign:"center",color:"#94a3b8"}}>
                  <p style={{fontSize:"18px",marginBottom:"16px"}}>No report found for <strong style={{color:"#6366f1"}}>{caseId}</strong></p>
                  <p style={{fontSize:"14px"}}>Go to <strong>Ingest</strong> tab → add evidence → click <strong>Run Analysis</strong></p>
                </div>
              ) : (
                <>
                  <div className="stat-grid">
                    {stats.map(s=>(
                      <div className="stat-card" key={s.label} style={{borderTopColor:s.color}}>
                        <div className="stat-value" style={{color:s.color}}>{s.value}</div>
                        <div className="stat-label">{s.label}</div>
                      </div>
                    ))}
                  </div>
                  <div className="chart-row">
                    <div className="chart-card">
                      <h3 className="chart-title">Threat Severity Distribution</h3>
                      {sevDist && sevDist.data.some(v=>v>0) ? (
                        <ThreatScoreChart type="doughnut" labels={sevDist.labels} data={sevDist.data} colors={sevDist.colors}/>
                      ) : <p style={{color:"#94a3b8",textAlign:"center",marginTop:"30px",fontSize:"13px"}}>Run Analysis to see chart</p>}
                    </div>
                    <div className="chart-card">
                      <h3 className="chart-title">Scores by Evidence Type</h3>
                      {barData ? (
                        <ThreatScoreChart type="bar" labels={barData.labels} data={barData.data} colors={barData.colors}/>
                      ) : <p style={{color:"#94a3b8",textAlign:"center",marginTop:"30px",fontSize:"13px"}}>Run Analysis to see chart</p>}
                    </div>
                  </div>
                  <div className="report-meta-card">
                    <h3>Report — {selected.caseId}</h3>
                    <p>Investigator: <strong>{selected.investigator}</strong> | Generated: {selected.createdAt?new Date(selected.createdAt).toLocaleString():"—"}</p>
                    <p>Status: <span className={"badge badge-"+(selected.status||"draft")}>{selected.status||"draft"}</span></p>
                    <p>SHA-256: <code className="hash-code">{selected.reportHash||"—"}</code></p>
                    <p>Blockchain: <span style={{color:selected.verified?"#22c55e":"#f97316"}}>{selected.verified?"✔ Verified on Chain":"⚠ Not verified"}</span></p>
                  </div>
                </>
              )}
            </>
          )}

          {activeTab==="evidence" && (
            <EvidenceTable caseId={caseId} analysisResults={analysisData?.results}/>
          )}

          {activeTab==="timeline" && (
            <TimelineView timeline={timeline||selected?.timeline}/>
          )}

          {activeTab==="blockchain" && (
            <BlockchainVerifier report={selected}/>
          )}

          {activeTab==="ingest" && (
            <IngestPanel caseId={caseId} onIngested={()=>{setStatusMsg("Evidence ingested. Click Run Analysis.");setActiveTab("overview");}}/>
          )}
        </div>
      </main>
    </div>
  );
}
