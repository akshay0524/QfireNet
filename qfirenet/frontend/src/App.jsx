/**
 * App.jsx — Root application component with routing.
 *
 * Deep-space dark theme:
 *   - Surface #0A0E14 base, #0D1117 navbar
 *   - Cyan accent #00D9FF for active states and interactive elements
 *   - Space Grotesk headings, Inter body
 */

import { useState, createContext, useContext } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link, useNavigate, useLocation } from 'react-router-dom';
import { tokenHelper } from './api/client';
import Landing from './pages/Landing';
import Dashboard from './pages/Dashboard';
import Results from './pages/Results';
import Login from './pages/Login';
import Register from './pages/Register';
import ScanHistory from './components/ScanHistory';

export const AuthContext = createContext(null);
export const useAuth = () => useContext(AuthContext);

function Navbar() {
  const { user, logout } = useAuth();
  const navigate  = useNavigate();
  const location  = useLocation();

  const handleLogout = () => { logout(); navigate('/login'); };
  const isActive = (p) => location.pathname === p || location.pathname.startsWith(p + '/');

  return (
    <nav style={{
      position: 'sticky', top: 0, zIndex: 50,
      background: 'var(--bg-raised)',
      borderBottom: '1px solid var(--border)',
      backdropFilter: 'blur(12px)',
    }}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14">

          {/* Logo */}
          <a href="/" className="flex items-center gap-2.5 group">
            <div className="w-7 h-7 rounded flex items-center justify-center flex-shrink-0"
              style={{ background: 'var(--accent-dim)', border: '1px solid var(--accent-border)' }}>
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}
                style={{ color: 'var(--accent)' }}>
                <path strokeLinecap="round" strokeLinejoin="round"
                  d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
            <span className="font-heading font-bold text-sm tracking-tight" style={{ color: 'var(--text-primary)' }}>
              QFireNet
            </span>
          </a>

          {/* Nav links */}
          <div className="hidden md:flex items-center gap-1">
            {[
              { to: '/dashboard', label: 'Dashboard' },
              ...(user ? [{ to: '/history', label: 'History' }] : []),
            ].map(({ to, label }) => (
              <Link
                key={to}
                to={to}
                className="px-3.5 py-1.5 rounded text-sm font-medium transition-all duration-150"
                style={{
                  color: isActive(to) ? 'var(--accent)' : 'var(--text-secondary)',
                  background: isActive(to) ? 'var(--accent-dim)' : 'transparent',
                  fontFamily: 'Inter, sans-serif',
                }}
              >
                {label}
              </Link>
            ))}
          </div>

          {/* Auth */}
          <div className="flex items-center gap-2">
            {user ? (
              <>
                <span className="hidden sm:block text-xs"
                  style={{ color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                  {user.email}
                </span>
                <div style={{ width: '1px', height: '20px', background: 'var(--border)', margin: '0 4px' }} />
                <button onClick={handleLogout} className="btn-ghost" style={{ padding: '0.35rem 0.75rem', fontSize: '13px' }}>
                  Sign out
                </button>
              </>
            ) : (
              <>
                <Link to="/login" className="btn-ghost hidden sm:inline-flex"
                  style={{ padding: '0.35rem 0.75rem', fontSize: '13px' }}>
                  Log in
                </Link>
                <Link to="/register" className="btn-primary"
                  style={{ padding: '0.35rem 0.875rem', fontSize: '13px' }}>
                  Register
                </Link>
              </>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
}

function ProtectedRoute({ children }) {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

function HistoryPage() {
  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 animate-fade-in">
      <div className="mb-8">
        <p className="section-label">Account</p>
        <h1 className="font-heading text-2xl font-bold mb-1" style={{ color: 'var(--text-primary)' }}>
          Scan History
        </h1>
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          Your past scans — most recent first
        </p>
      </div>
      <ScanHistory />
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState(() => tokenHelper.getUser());

  const login  = (userData) => setUser(userData);
  const logout = () => { tokenHelper.clear(); setUser(null); };

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <div className="min-h-screen flex flex-col" style={{ background: 'var(--bg-base)' }}>
          <Navbar />
          <main className="flex-1">
            <Routes>
              <Route path="/"               element={<Landing />} />
              <Route path="/dashboard"      element={<Dashboard />} />
              <Route path="/results/:scanId" element={<Results />} />
              <Route path="/login"          element={<Login />} />
              <Route path="/register"       element={<Register />} />
              <Route path="/history"        element={<ProtectedRoute><HistoryPage /></ProtectedRoute>} />
              <Route path="*"               element={<Navigate to="/" replace />} />
            </Routes>
          </main>

          {/* Footer */}
          <footer style={{ borderTop: '1px solid var(--border)', paddingBlock: '1.5rem' }}>
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
              <div className="flex items-center gap-2">
                <div className="w-5 h-5 rounded flex items-center justify-center"
                  style={{ background: 'var(--accent-dim)', border: '1px solid var(--accent-border)' }}>
                  <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}
                    style={{ color: 'var(--accent)' }}>
                    <path strokeLinecap="round" strokeLinejoin="round"
                      d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                  </svg>
                </div>
                <span className="text-xs font-medium font-heading" style={{ color: 'var(--text-secondary)' }}>
                  QFireNet v1.0
                </span>
              </div>
              <p className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                Groq + Llama 3.3 70B · FastAPI + React
              </p>
            </div>
          </footer>
        </div>
      </BrowserRouter>
    </AuthContext.Provider>
  );
}
