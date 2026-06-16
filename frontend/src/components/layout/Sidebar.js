import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import {
  LayoutDashboard, Shield, AlertTriangle, Radar, FileText,
  Settings, LogOut, Bell, Search
} from 'lucide-react';

const navItems = [
  { label: 'Dashboard', icon: LayoutDashboard, path: '/' },
  { label: 'Findings', icon: AlertTriangle, path: '/findings' },
  { label: 'Monitored assets', icon: Shield, path: '/assets' },
  { label: 'Scan history', icon: Radar, path: '/scans' },
  { label: 'Reports', icon: FileText, path: '/reports' },
];

export default function Sidebar({ criticalCount = 0 }) {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  return (
    <nav className="sidebar">
      <div className="sidebar-logo">
        <div className="brand">
          <div className="brand-icon">D</div>
          <div>
            <div className="brand-name">DIMP</div>
            <div className="brand-sub">Threat monitor</div>
          </div>
        </div>
      </div>

      <div className="sidebar-nav">
        <div className="nav-section-label">Monitor</div>
        {navItems.map(({ label, icon: Icon, path }) => (
          <button
            key={path}
            className={`nav-item${pathname === path ? ' active' : ''}`}
            onClick={() => navigate(path)}
          >
            <Icon />
            {label}
            {label === 'Findings' && criticalCount > 0 && (
              <span className="nav-badge">{criticalCount}</span>
            )}
          </button>
        ))}

        <div className="nav-section-label" style={{ marginTop: 8 }}>System</div>
        <button className="nav-item" onClick={() => navigate('/settings')}>
          <Settings /> Settings
        </button>
      </div>

      <div className="sidebar-footer">
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8, paddingLeft: 10 }}>
          {user?.email}
        </div>
        <button className="nav-item" onClick={logout}>
          <LogOut /> Sign out
        </button>
      </div>
    </nav>
  );
}
