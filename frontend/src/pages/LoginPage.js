// src/pages/LoginPage.js
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import "./LoginPage.css";

export default function LoginPage() {
  const { login, loading, error } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ username: "", password: "" });

  const handleChange = (e) =>
    setForm((prev) => ({ ...prev, [e.target.name]: e.target.value }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    const ok = await login(form.username, form.password);
    if (ok) navigate("/dashboard");
  };

  return (
    <div className="login-root">
      <div className="login-card">
        {/* Logo / Brand */}
        <div className="login-brand">
          <div className="login-logo">
            <span className="logo-s">S</span>
          </div>
          <h1 className="login-title">SPECTRA</h1>
          <p className="login-subtitle">
            AI-Powered Digital Forensics &amp; Cybercrime Investigation
          </p>
        </div>

        <form className="login-form" onSubmit={handleSubmit}>
          {error && <div className="login-error">{error}</div>}

          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              name="username"
              type="text"
              autoComplete="username"
              required
              value={form.username}
              onChange={handleChange}
              placeholder="investigator"
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={form.password}
              onChange={handleChange}
              placeholder="••••••••"
            />
          </div>

          <button
            type="submit"
            className="login-btn"
            disabled={loading}
          >
            {loading ? "Authenticating…" : "Sign In"}
          </button>
        </form>

        <p className="login-hint">
          Default: <code>admin / admin123</code>
        </p>
      </div>
    </div>
  );
}
