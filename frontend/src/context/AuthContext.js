// src/context/AuthContext.js
import React, { createContext, useContext, useState, useCallback } from "react";
import { login as apiLogin } from "../services/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser]   = useState(() => {
    const stored = localStorage.getItem("spectra_user");
    return stored ? JSON.parse(stored) : null;
  });
  const [token, setToken] = useState(() => localStorage.getItem("spectra_token"));
  const [loading, setLoading] = useState(false);
  const [error, setError]    = useState(null);

  const login = useCallback(async (username, password) => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiLogin(username, password);
      const { token: jwt, username: uname } = res.data;
      localStorage.setItem("spectra_token", jwt);
      localStorage.setItem("spectra_user", JSON.stringify({ username: uname }));
      setToken(jwt);
      setUser({ username: uname });
      return true;
    } catch (err) {
      setError(err.response?.data?.message || "Login failed");
      return false;
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem("spectra_token");
    localStorage.removeItem("spectra_user");
    setToken(null);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, token, loading, error, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
