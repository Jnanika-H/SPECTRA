// src/pages/DashboardPage.js
import React, { useState, useEffect, useCallback } from "react";
import { useAuth } from "../context/AuthContext";
import {
  getReports, analyzeCase, generateReport,
  verifyOnChain, triggerRetrain
} from "../services/api";
import ThreatScoreChart   from "../components/ThreatScoreChart";
import TimelineView       from "../components/TimelineView";
import EvidenceTable      from "../components/EvidenceTable";
import BlockchainVerifier from "../components/BlockchainVerifier";
import IngestPanel        from "../components/IngestPanel";
import "./DashboardPage.css";

export default function DashboardPage() {
  const { user, logout } = useAuth();

  const [reports, setReports]     = useState([]);
  const [selected, setSelected]   = useState(null);
  const [loading, setLoading]     = useState(false);
  const [statusMsg, setStatusMsg] = useState("");
  const [activeTab, setActiveTab] = useState("overview");
  const [caseId, setCaseId]       = useState("CASE-001");

  const fetchReports = useCallback(async () => {
    try {
      const res = await getReports();
      setReports(res.data);
      if (res.data.length > 0 && !selected) setSelected(res.data[0]);
    } catch {
      setStatusMsg("Could not load reports from backend.");
    }
  }, [selected]);

  useEffect(() => { fetchReports(); }, []);

  // ── Actions ────────────────────────────────────────────────────────────────

  const handleAnalyze = async () => {
    setLoading(true);
    setStatusMsg("Running AI analysis…");
    try {
      await analyzeCase(caseId);
      setStatusMsg("Analysis complete. Generating report…");
      const rep = await generateReport(caseId);
      setReports((prev) => [rep.data, ...prev.filter(r => r.caseId !== caseId)]);
      setSelected(rep.data);
      setStatusMsg("Report generated and stored.");
    } catch (e) {
      setStatusMsg(`Analysis failed: ${e.response?.data?.message || e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleRetrain = async () => {
    setStatusMsg("Triggering self-learning retrain…");
    try {
      const res = await triggerRetrain();
      setStatusMsg(`Retrain: ${res.data.status} — ${res.data.message || ""}`);
    } catch {
      setStatusMsg("Retrain request failed.");
    }
  };

  // ── Stats from selected report ─────────────────────────────────────────────
  const stats = selected
    ? [
        { label: "Total Evidence",    value: selected.totalEvidence   ?? 0, color: "#6366f1" },
        { label: "Critical",          value: selected.criticalCount   ?? 0, color: "#ef4444" },
        { label: "High Severity",     value: selected.highCount       ?? 0, color: "#f97316" },
        { label: "Anomalies",         value: selected.anomalyCount    ?? 0, color: "#a855f7" },
        { label: "Avg Threat Score",  value: selected.averageThreatScore
                                              ? `${Math.round(selected.averageThreatScore)}/100`
                                              : "—",                        color: "#14b8a6" },
      ]
    : [];

  const severityDist = selected
    ? {
        labels: ["Critical", "High", "Medium", "Low"],
        data:   [
          selected.criticalCount ?? 0,
          selected.highCount     ?? 0,
          Math.max(0, (selected.totalEvidence ?? 0)
            - (selected.criticalCount ?? 0)
            - (selected.highCount ?? 0)
            - (selected.anomalyCount ?? 0)),
          selected.anomalyCount ?? 0,
        ],
        colors: ["#ef4444", "#f97316", "#eab308", "#22c55e"],
      }
    : null;

  // ── Layout ─────────────────────────────────────────────────────────────────
  return (
    <div className="dash-root">
      {/* ── Sidebar ── */}
      <aside className="dash-sidebar">
        <div className="sidebar-brand">
          <span className="sidebar-logo">S</span>
          <span className="sidebar-title">SPECTRA</span>
        </div>

        <nav className="sidebar-nav">
          {[
            { id: "overview",    label: "Overview",     icon: "⬡" },
            { id: "evidence",    label: "Evidence",     icon: "🗂" },
            { id: "timeline",    label: "Timeline",     icon: "⏱" },
            { id: "blockchain",  label: "Blockchain",   icon: "⛓" },
            { id: "ingest",      label: "Ingest",       icon: "＋" },
          ].map((tab) => (
            <button
              key={tab.id}
              className={`sidebar-link ${activeTab === tab.id ? "active" : ""}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <span className="sidebar-icon">{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-user">{user?.username}</div>
          <button className="sidebar-logout" onClick={logout}>Sign out</button>
        </div>
      </aside>

      {/* ── Main content ── */}
      <main className="dash-main">
        {/* Topbar */}
        <header className="dash-topbar">
          <div className="topbar-left">
            <label htmlFor="case-select" className="topbar-label">Case:</label>
            <select
              id="case-select"
              className="topbar-select"
              value={caseId}
              onChange={(e) => {
                setCaseId(e.target.value);
                const rep = reports.find(r => r.caseId === e.target.value);
                setSelected(rep || null);
              }}
            >
              {reports.map(r => (
                <option key={r.caseId} value={r.caseId}>{r.caseId}</option>
              ))}
              <option value="CASE-001">CASE-001 (demo)</option>
              <option value="CASE-002">CASE-002 (demo)</option>
            </select>

            <input
              className="topbar-caseid"
              placeholder="Enter case ID…"
              value={caseId}
              onChange={(e) => setCaseId(e.target.value)}
            />
          </div>

          <div className="topbar-right">
            {statusMsg && <span className="topbar-status">{statusMsg}</span>}
            <button className="btn-primary" onClick={handleAnalyze} disabled={loading}>
              {loading ? "Analyzing…" : "Run Analysis"}
            </button>
            <button className="btn-secondary" onClick={handleRetrain}>
              Retrain Model
            </button>
          </div>
        </header>

        {/* Tab content */}
        <div className="dash-content">

          {/* ── Overview ── */}
          {activeTab === "overview" && (
            <>
              <div className="stat-grid">
                {stats.map((s) => (
                  <div className="stat-card" key={s.label} style={{ borderTopColor: s.color }}>
                    <div className="stat-value" style={{ color: s.color }}>{s.value}</div>
                    <div className="stat-label">{s.label}</div>
                  </div>
                ))}
              </div>

              {severityDist && (
                <div className="chart-row">
                  <div className="chart-card">
                    <h3 className="chart-title">Threat Severity Distribution</h3>
                    <ThreatScoreChart
                      type="doughnut"
                      labels={severityDist.labels}
                      data={severityDist.data}
                      colors={severityDist.colors}
                    />
                  </div>
                  <div className="chart-card">
                    <h3 className="chart-title">Scores by Evidence Type</h3>
                    <ThreatScoreChart
                      type="bar"
                      labels={["File", "Event Log", "Browser", "Network"]}
                      data={[72, 85, 63, 91]}
                      colors={["#6366f1", "#ef4444", "#f97316", "#14b8a6"]}
                    />
                  </div>
                </div>
              )}

              {selected && (
                <div className="report-meta-card">
                  <h3>Report — {selected.caseId}</h3>
                  <p>Generated by <strong>{selected.investigator}</strong> on{" "}
                    {selected.createdAt ? new Date(selected.createdAt).toLocaleString() : "—"}</p>
                  <p>Status: <span className={`badge badge-${selected.status}`}>{selected.status}</span></p>
                  <p>Blockchain hash: <code className="hash-code">{selected.reportHash || "—"}</code></p>
                </div>
              )}
            </>
          )}

          {/* ── Evidence Table ── */}
          {activeTab === "evidence" && (
            <EvidenceTable caseId={caseId} />
          )}

          {/* ── Timeline ── */}
          {activeTab === "timeline" && (
            <TimelineView timeline={selected?.timeline} />
          )}

          {/* ── Blockchain ── */}
          {activeTab === "blockchain" && (
            <BlockchainVerifier report={selected} />
          )}

          {/* ── Ingest ── */}
          {activeTab === "ingest" && (
            <IngestPanel
              caseId={caseId}
              onIngested={() => {
                setStatusMsg("Evidence ingested. Click Run Analysis.");
                setActiveTab("overview");
              }}
            />
          )}
        </div>
      </main>
    </div>
  );
}
