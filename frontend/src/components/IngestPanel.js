// src/components/IngestPanel.js
import React, { useState } from "react";
import { ingestEvidence, uploadForensicEvidence } from "../services/api";

const DEMO_ARTIFACTS = [
  { type: "file",            name: "mimikatz.exe",          rule_score: 98, features: { network_activity: 0.0,  session_time: 0.0, data_transfer: 0.01, connection_status: 2 } },
  { type: "event_log",       event_id: 1102,                rule_score: 80, features: { network_activity: 0.1,  session_time: 1.0, data_transfer: 0.0,  connection_status: 2 } },
  { type: "browser_history", url: "https://torproject.org", rule_score: 80, features: { network_activity: 0.12, session_time: 0.0, data_transfer: 0.0,  connection_status: 2 } },
  { type: "network_packet",  src_ip: "192.168.1.50", dst_ip: "185.220.101.1", dst_port: 4444, rule_score: 70, features: { network_activity: 0.5, session_time: 0.0, data_transfer: 0.01, connection_status: 2 } },
  { type: "event_log",       event_id: 4625,                rule_score: 60, features: { network_activity: 0.1,  session_time: 1.0, data_transfer: 0.0,  connection_status: 1 } },
];

export default function IngestPanel({ caseId, onIngested }) {
  const [mode, setMode]     = useState("forensic");
  const [paths, setPaths]   = useState({ fs: "", evtx: "", chrome: "", pcap: "" });
  const [forensic, setForensic] = useState({ 
    selectedFiles: [],
    detectedFormat: "",
    totalSize: "",
    validationStatus: "",
    imageType: "disk_image"
  });
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);

  const handleForensicFileSelect = (e) => {
    const files = Array.from(e.target.files);
    
    if (files.length === 0) return;
    
    // Sort files by name to ensure correct order (E01, E02, E03, etc.)
    files.sort((a, b) => a.name.localeCompare(b.name));
    
    // Detect format from first file extension
    const firstFile = files[0];
    const ext = firstFile.name.split('.').pop().toLowerCase();
    
    let format = "Unknown";
    if (ext.match(/e\d{2}/)) {
      format = "E01/EWF";
    } else if (ext === 'ex01' || ext.match(/ex\d{2}/)) {
      format = "E01/EWF (EnCase v7+)";
    } else if (['dd', 'raw', 'img'].includes(ext)) {
      format = "RAW/DD";
    }
    
    // Calculate total size
    const totalBytes = files.reduce((sum, file) => sum + file.size, 0);
    const totalGB = (totalBytes / (1024 ** 3)).toFixed(2);
    
    setForensic({
      selectedFiles: files,
      detectedFormat: format,
      totalSize: `${totalGB} GB`,
      validationStatus: "",
      imageType: "disk_image"
    });
    
    setStatus("");
  };

  const handleForensicFileClear = () => {
    setForensic({
      selectedFiles: [],
      detectedFormat: "",
      totalSize: "",
      validationStatus: "",
      imageType: "disk_image"
    });
    // Reset the file input
    const fileInput = document.getElementById('forensic-file-input');
    if (fileInput) fileInput.value = '';
    setStatus("");
  };

  const handleValidateEvidence = () => {
    if (forensic.selectedFiles.length === 0) {
      setStatus("No files selected for validation");
      return;
    }
    
    // Basic client-side validation
    const files = forensic.selectedFiles;
    
    // Check if all files have the same base name (for split images)
    if (files.length > 1) {
      const baseName = files[0].name.replace(/\.[^.]+$/, '').replace(/\d+$/, '');
      const allMatch = files.every(f => {
        const fBaseName = f.name.replace(/\.[^.]+$/, '').replace(/\d+$/, '');
        return fBaseName === baseName;
      });
      
      if (!allMatch) {
        setForensic(f => ({ ...f, validationStatus: "Invalid - segments don't match" }));
        setStatus("⚠️ Warning: Selected files don't appear to be from the same image");
        return;
      }
    }
    
    // Check for sequential numbering in split images
    if (files.length > 1 && forensic.detectedFormat.includes("E01")) {
      const extensions = files.map(f => {
        const ext = f.name.split('.').pop().toLowerCase();
        const match = ext.match(/e(\d{2})/);
        return match ? parseInt(match[1]) : 0;
      });
      
      const isSequential = extensions.every((num, idx) => idx === 0 || num === extensions[idx - 1] + 1);
      
      if (!isSequential || extensions[0] !== 1) {
        setForensic(f => ({ ...f, validationStatus: "Warning - non-sequential segments" }));
        setStatus("⚠️ Warning: Segments may not be in correct order or missing segments");
        return;
      }
    }
    
    setForensic(f => ({ ...f, validationStatus: "Valid" }));
    setStatus("✅ Evidence validation passed - ready for ingestion");
  };

  const handleIngest = async () => {
    setLoading(true);
    try {
      let artifacts;
      if (mode === "demo") {
        artifacts = DEMO_ARTIFACTS;
        await ingestEvidence(caseId, artifacts);
      } else if (mode === "forensic") {
        // Forensic disk image mode with file upload
        if (forensic.selectedFiles.length === 0) {
          setStatus("Please select forensic image file(s)");
          setLoading(false);
          return;
        }
        
        setStatus("Uploading forensic evidence... This may take several minutes for large files.");
        
        // Upload forensic images
        const result = await uploadForensicEvidence(caseId, forensic.selectedFiles, (progress) => {
          setStatus(`Uploading forensic evidence... ${progress}%`);
        });
        
        setStatus(`Upload complete. Processing forensic image...`);
        
        // The backend will automatically call forensic collector after upload
        // No need to send artifacts array
        
      } else {
        // System paths mode (existing)
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
        await ingestEvidence(caseId, artifacts);
      }
      
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
        {["demo", "paths", "forensic"].map((m) => (
          <button key={m} className={`mode-tab ${mode === m ? "active" : ""}`} onClick={() => setMode(m)}>
            {m === "demo" ? "Demo Data" : m === "paths" ? "System Paths" : "Forensic Image"}
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

      {mode === "forensic" && (
        <div className="forensic-form">
          <div className="info-box" style={{
            background: '#e3f2fd',
            border: '1px solid #2196f3',
            padding: '12px',
            borderRadius: '4px',
            marginBottom: '15px',
            fontSize: '14px',
            color: '#0d47a1'
          }}>
            <strong style={{color: '#0d47a1'}}>🔬 Forensic Disk Image Mode</strong>
            <ul style={{margin: '8px 0', paddingLeft: '20px', color: '#0d47a1'}}>
              <li>Supports E01/EWF forensic images (select all segments)</li>
              <li>Supports RAW/DD disk images</li>
              <li>Read-only access - evidence is never modified</li>
              <li>For split images: Select all segments (CASE.E01, CASE.E02, CASE.E03, etc.)</li>
              <li>Evidence is securely stored in controlled storage after validation</li>
            </ul>
          </div>

          <div className="forensic-file-picker">
            <label>Evidence Image</label>
            <div style={{
              border: '2px dashed #2196f3',
              borderRadius: '8px',
              padding: '20px',
              textAlign: 'center',
              background: '#f5f5f5',
              marginBottom: '15px'
            }}>
              {forensic.selectedFiles.length === 0 ? (
                <>
                  <div style={{ fontSize: '48px', marginBottom: '10px' }}>📦</div>
                  <div style={{ marginBottom: '15px', color: '#666' }}>
                    No forensic image selected
                  </div>
                  <label htmlFor="forensic-file-input" style={{
                    display: 'inline-block',
                    padding: '10px 20px',
                    background: '#2196f3',
                    color: 'white',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    fontSize: '14px',
                    fontWeight: '500'
                  }}>
                    Browse for Evidence
                  </label>
                  <input
                    id="forensic-file-input"
                    type="file"
                    multiple
                    accept=".e01,.e02,.e03,.e04,.e05,.e06,.e07,.e08,.e09,.ex01,.dd,.raw,.img"
                    style={{ display: 'none' }}
                    onChange={handleForensicFileSelect}
                  />
                  <div style={{ marginTop: '10px', fontSize: '12px', color: '#888' }}>
                    Accepted: .E01, .E02, .DD, .RAW
                  </div>
                </>
              ) : (
                <>
                  <div style={{ textAlign: 'left' }}>
                    <strong style={{ fontSize: '14px', color: '#333' }}>Selected Evidence:</strong>
                    <div style={{ maxHeight: '150px', overflowY: 'auto', marginTop: '10px' }}>
                      {forensic.selectedFiles.map((file, idx) => (
                        <div key={idx} style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          padding: '8px 12px',
                          background: 'white',
                          border: '1px solid #ddd',
                          borderRadius: '4px',
                          marginBottom: '8px',
                          fontSize: '13px'
                        }}>
                          <div>
                            <span style={{ fontWeight: '500' }}>📄 {file.name}</span>
                            <span style={{ marginLeft: '10px', color: '#666' }}>
                              ({(file.size / (1024 * 1024)).toFixed(2)} MB)
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                    {forensic.detectedFormat && (
                      <div style={{ marginTop: '15px', padding: '10px', background: '#e8f5e9', borderRadius: '4px' }}>
                        <div><strong>Format:</strong> {forensic.detectedFormat}</div>
                        <div><strong>Segments:</strong> {forensic.selectedFiles.length}</div>
                        <div><strong>Total Size:</strong> {forensic.totalSize}</div>
                        {forensic.validationStatus && (
                          <div style={{ color: forensic.validationStatus === 'Valid' ? '#2e7d32' : '#c62828' }}>
                            <strong>Status:</strong> {forensic.validationStatus}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={handleForensicFileClear}
                    style={{
                      marginTop: '15px',
                      padding: '8px 16px',
                      background: '#f44336',
                      color: 'white',
                      border: 'none',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      fontSize: '13px'
                    }}
                  >
                    Clear Selection
                  </button>
                  {forensic.selectedFiles.length > 0 && !forensic.validationStatus && (
                    <button
                      type="button"
                      onClick={handleValidateEvidence}
                      style={{
                        marginTop: '15px',
                        marginLeft: '10px',
                        padding: '8px 16px',
                        background: '#4caf50',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        fontSize: '13px'
                      }}
                    >
                      Validate Evidence
                    </button>
                  )}
                </>
              )}
            </div>
          </div>

          <div style={{
            background: '#fff3cd',
            border: '1px solid #ffc107',
            padding: '10px',
            borderRadius: '4px',
            marginTop: '10px',
            fontSize: '13px',
            color: '#856404'
          }}>
            <strong>Note:</strong> Requires Python dependencies (pyewf, pytsk3). See installation guide if errors occur.
          </div>
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
