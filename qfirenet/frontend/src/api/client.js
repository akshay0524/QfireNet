/**
 * api/client.js — Axios instance with JWT authentication interceptor.
 *
 * All API calls go through this instance so we never have to manually
 * attach the Authorization header in every component.
 *
 * HOW IT WORKS:
 *   1. We create an Axios instance with the backend base URL.
 *   2. A request interceptor runs before every request and reads the
 *      JWT token from localStorage.  If it exists, it adds the
 *      "Authorization: Bearer <token>" header automatically.
 *   3. A response interceptor handles 401 errors globally — if any request
 *      returns 401, the user is logged out and redirected to /login.
 *
 * TOKEN STORAGE:
 *   We store the JWT in localStorage for simplicity (MVP approach).
 *   For production, httpOnly cookies are more secure (can't be read by JS,
 *   resistant to XSS attacks), but they require server-side cookie handling.
 */

import axios from 'axios';

// Base URL of the FastAPI backend.
// In development, Vite proxies /api → http://localhost:8000 (see vite.config.js).
// In Docker, this points directly to the backend service.
const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Create a custom Axios instance with the base URL pre-configured.
const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 60000,  // 60 seconds — scans can take a while (WHOIS lookups, etc.)
  headers: {
    'Content-Type': 'application/json',
  },
});


// ── Request interceptor — attach JWT token ────────────────────────────────
// This runs before EVERY request made through apiClient.
apiClient.interceptors.request.use(
  (config) => {
    // Read the stored token from localStorage.
    const token = localStorage.getItem('qfirenet_token');
    if (token) {
      // Attach to the Authorization header in Bearer format.
      // FastAPI's HTTPBearer dependency reads this header automatically.
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;  // Return the modified config to proceed with the request.
  },
  (error) => Promise.reject(error),
);


// ── Response interceptor — handle 401 globally ───────────────────────────
// This runs after EVERY response received through apiClient.
apiClient.interceptors.response.use(
  (response) => response,  // Pass through successful responses unchanged.
  (error) => {
    if (error.response?.status === 401) {
      // Token expired or invalid — clear stored credentials and redirect.
      localStorage.removeItem('qfirenet_token');
      localStorage.removeItem('qfirenet_user');
      // Only redirect if not already on an auth page (avoid redirect loops).
      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  },
);


// ── Auth API functions ────────────────────────────────────────────────────

export const authAPI = {
  register: (email, password) =>
    apiClient.post('/auth/register', { email, password }),

  login: (email, password) =>
    apiClient.post('/auth/login', { email, password }),
};


// ── Scan API functions ────────────────────────────────────────────────────

export const scanAPI = {
  scanWebsite: (url) =>
    apiClient.post('/scan/website', { url }),

  // Paste mode: structured JSON fields
  scanEmail: ({ senderEmail, subject, body }) =>
    apiClient.post('/scan/email', {
      sender_email: senderEmail,
      subject,
      body,
    }),

  // Screenshot mode: multipart/form-data image upload
  // OCR + LLM analysis on the backend — longer timeout needed
  scanEmailScreenshot: (imageFile) => {
    const formData = new FormData();
    formData.append('image', imageFile);
    return apiClient.post('/scan/email/screenshot', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 120000,  // OCR can take up to 30s; LLM adds more
    });
  },

  scanAPK: (file) => {
    // APK upload uses multipart/form-data — Axios handles this automatically
    // when we pass a FormData object.
    const formData = new FormData();
    formData.append('file', file);
    return apiClient.post('/scan/apk', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 120000,  // APK parsing can take up to 2 minutes for large files.
    });
  },
};


// ── History API functions ─────────────────────────────────────────────────

export const historyAPI = {
  getHistory: (page = 1, pageSize = 20, scanType = null) =>
    apiClient.get('/history', { params: { page, page_size: pageSize, ...(scanType && { scan_type: scanType }) } }),

  getHistoryItem: (id) =>
    apiClient.get(`/history/${id}`),
};


// ── Report API functions ──────────────────────────────────────────────────

export const reportAPI = {
  getReport: (id) =>
    apiClient.get(`/report/${id}`),
};


// ── Stats API functions ───────────────────────────────────────────────────

export const statsAPI = {
  getStats: () =>
    apiClient.get('/stats'),
};


// ── Threat Events API functions ───────────────────────────────────────────

export const threatAPI = {
  getRecentEvents: ({ hours = 48, limit = 200 } = {}) =>
    apiClient.get('/threat-events/recent', { params: { hours, limit } }),

  getStats: () =>
    apiClient.get('/threat-events/stats'),
};


// ── Token helpers (used by App.jsx for auth state) ────────────────────────

export const tokenHelper = {
  save: (token, user) => {
    localStorage.setItem('qfirenet_token', token);
    localStorage.setItem('qfirenet_user', JSON.stringify(user));
  },
  clear: () => {
    localStorage.removeItem('qfirenet_token');
    localStorage.removeItem('qfirenet_user');
  },
  getUser: () => {
    const stored = localStorage.getItem('qfirenet_user');
    return stored ? JSON.parse(stored) : null;
  },
  isLoggedIn: () => !!localStorage.getItem('qfirenet_token'),
};

export default apiClient;
