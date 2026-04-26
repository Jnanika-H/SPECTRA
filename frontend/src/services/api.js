// src/services/api.js
// Centralised Axios wrapper for all SPECTRA backend calls

import axios from "axios";

const BASE_URL = process.env.REACT_APP_API_URL || "http://localhost:8080/api";

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
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
