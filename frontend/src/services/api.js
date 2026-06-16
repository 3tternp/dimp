import axios from 'axios';

const BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({ baseURL: `${BASE}/api/v1` });

// Attach JWT token to every request
api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('token');
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

// On 401, clear token and redirect to login
api.interceptors.response.use(
  r => r,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

// ── Auth ─────────────────────────────────────────────────────────────────────
export const login = (email, password) =>
  api.post('/auth/login', { email, password }).then(r => r.data);

export const getMe = () =>
  api.get('/auth/me').then(r => r.data);

// ── Dashboard ────────────────────────────────────────────────────────────────
export const getDashboardStats = () =>
  api.get('/dashboard/stats').then(r => r.data);

export const getFindingsBySeverity = () =>
  api.get('/dashboard/findings-by-severity').then(r => r.data);

export const getFindingsBySource = () =>
  api.get('/dashboard/findings-by-source').then(r => r.data);

export const getFindingsByTLD = () =>
  api.get('/dashboard/findings-by-tld').then(r => r.data);

export const getFindingsTrend = (days = 30) =>
  api.get(`/dashboard/findings-trend?days=${days}`).then(r => r.data);

// ── Assets ───────────────────────────────────────────────────────────────────
export const getAssets = (skip = 0, limit = 50) =>
  api.get(`/assets?skip=${skip}&limit=${limit}`).then(r => r.data);

export const createAsset = (data) =>
  api.post('/assets', data).then(r => r.data);

export const updateAsset = (id, data) =>
  api.patch(`/assets/${id}`, data).then(r => r.data);

export const deleteAsset = (id) =>
  api.delete(`/assets/${id}`);

export const getAssetKeywords = (assetId) =>
  api.get(`/assets/${assetId}/keywords`).then(r => r.data);

export const addKeyword = (assetId, keyword) =>
  api.post(`/assets/${assetId}/keywords`, { keyword }).then(r => r.data);

export const deleteKeyword = (assetId, kwId) =>
  api.delete(`/assets/${assetId}/keywords/${kwId}`);

export const getAllowlist = (assetId) =>
  api.get(`/assets/${assetId}/allowlist`).then(r => r.data);

export const addAllowlistDomain = (assetId, domain, reason) =>
  api.post(`/assets/${assetId}/allowlist`, { domain, reason }).then(r => r.data);

// ── Findings ─────────────────────────────────────────────────────────────────
export const getFindings = (params = {}) => {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v != null && v !== '') q.set(k, v); });
  return api.get(`/findings?${q}`).then(r => r.data);
};

export const getFinding = (id) =>
  api.get(`/findings/${id}`).then(r => r.data);

export const updateFindingStatus = (id, status, notes) =>
  api.patch(`/findings/${id}/status`, { status, notes }).then(r => r.data);

// ── Scans ────────────────────────────────────────────────────────────────────
export const triggerScan = (assetId) =>
  api.post('/scans', { asset_id: assetId }).then(r => r.data);

export const getScanJob = (id) =>
  api.get(`/scans/${id}`).then(r => r.data);

export const getScanJobs = (assetId, skip = 0, limit = 20) => {
  const q = assetId ? `?asset_id=${assetId}&skip=${skip}&limit=${limit}` : `?skip=${skip}&limit=${limit}`;
  return api.get(`/scans${q}`).then(r => r.data);
};

// ── Reports ──────────────────────────────────────────────────────────────────
export const getReports = () =>
  api.get('/reports').then(r => r.data);

export const createReport = (data) =>
  api.post('/reports', data).then(r => r.data);

export const downloadReport = (id) =>
  `${BASE}/api/v1/reports/${id}/download`;
