// src/services/api.js
// Centralised Axios wrapper for all SPECTRA backend calls

import axios from "axios";

const BASE_URL = "http://localhost:8081/api";

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 120000, // 2 minutes for large evidence analysis
  headers: { "Content-Type": "application/json" },
});

// ── Request interceptor: attach JWT ──────────────────────────────────────────
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("spectra_token");
    if (token) config.headers.Authorization = `Bearer ${token}`;
    return config;
  },
  (error) => Promise.reject(error)
);

// ── Response interceptor: handle 401 ─────────────────────────────────────────
api.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem("spectra_token");
      localStorage.removeItem("spectra_user");
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

// ── Auth ─────────────────────────────────────────────────────────────────────
export const login = (username, password) =>
  api.post("/login", { username, password });

// ── Evidence ─────────────────────────────────────────────────────────────────
export const ingestEvidence = (caseId, artifacts) =>
  api.post("/ingest", { caseId, artifacts });

export const analyzeCase = (caseId) =>
  api.post("/ingest/analyze", { caseId });

// Upload forensic evidence files with progress tracking
export const uploadForensicEvidence = async (caseId, files, onProgress) => {
  const formData = new FormData();
  formData.append("caseId", caseId);
  
  // Append all files (for split images)
  files.forEach((file, index) => {
    formData.append("evidenceFiles", file);
  });
  
  try {
    const response = await api.post("/evidence/upload", formData, {
      headers: {
        "Content-Type": "multipart/form-data",
      },
      timeout: 600000, // 10 minutes for large files
      onUploadProgress: (progressEvent) => {
        if (progressEvent.total) {
          const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          if (onProgress) {
            onProgress(percentCompleted);
          }
        }
      },
    });
    
    return response.data;
  } catch (error) {
    console.error("Upload failed:", error);
    throw error;
  }
};

// ── Reports ──────────────────────────────────────────────────────────────────
export const getReports = () => api.get("/reports");

export const getReport = (id) => api.get(`/reports/${id}`);

export const generateReport = (caseId) =>
  api.post("/reports", { caseId });

// ── Feedback ─────────────────────────────────────────────────────────────────
export const submitFeedback = (evidenceId, correctedScore, correctedLabel, notes) =>
  api.post("/feedback", { evidenceId, correctedScore, correctedLabel, notes });

export const triggerRetrain = () => api.post("/feedback/trigger-retrain");

// ── Blockchain ────────────────────────────────────────────────────────────────
export const storeHashOnChain = (reportId, hash) =>
  api.post("/blockchain", { reportId, hash });

export const verifyOnChain = (reportId) =>
  api.get(`/blockchain/verify/${reportId}`);

export default api;
