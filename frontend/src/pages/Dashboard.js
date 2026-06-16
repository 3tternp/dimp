import { useEffect, useState } from 'react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import {
  getDashboardStats, getFindingsBySeverity, getFindingsBySource,
  getFindingsTrend, getFindingsByTLD
} from '../services/api';
import { Spinner } from '../components/ui';
import { timeAgo, fmtDate } from '../utils/format';

const SEVERITY_COLORS = {
  critical: '#E24B4A', high: '#EF9F27', medium: '#378ADD', low: '#3DAA6A'
};

function StatCard({ label, value, variant = 'neutral', sub }) {
  return (
    <div className={`stat-card ${variant}`}>
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${variant === 'critical' || variant === 'high' ? variant : ''}`}>
        {value ?? '—'}
      </div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'var(--surface-3)', border: '1px solid var(--border-strong)',
      borderRadius: 8, padding: '10px 14px', fontSize: 12
    }}>
      <div style={{ color: 'var(--text-muted)', marginBottom: 6 }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color || 'var(--text-primary)', display: 'flex', gap: 8 }}>
          <span>{p.name}:</span><strong>{p.value}</strong>
        </div>
      ))}
    </div>
  );
};

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [bySeverity, setBySeverity] = useState([]);
  const [bySource, setBySource] = useState([]);
  const [trend, setTrend] = useState([]);
  const [byTLD, setByTLD] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      getDashboardStats(),
      getFindingsBySeverity(),
      getFindingsBySource(),
      getFindingsTrend(30),
      getFindingsByTLD(),
    ]).then(([s, sev, src, tr, tld]) => {
      setStats(s);
      setBySeverity(sev.map(x => ({ name: x.severity, value: x.count, fill: SEVERITY_COLORS[x.severity] })));
      setBySource(src.slice(0, 8));
      setTrend(tr.map(x => ({ date: x.date.slice(5), count: x.count })));
      setByTLD(tld.slice(0, 10));
    }).catch(console.error).finally(() => setLoading(false));
  }, []);

  if (loading) return <Spinner />;

  return (
    <div className="page-body">
      <div className="page-header">
        <div>
          <div className="page-title">Threat overview</div>
          <div className="page-subtitle">
            {stats?.last_scan_at
              ? `Last scan ${timeAgo(stats.last_scan_at)}`
              : 'No scans yet — add a monitored asset to begin'}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div className="live-dot" />
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Live</span>
        </div>
      </div>

      {/* Stat cards */}
      <div className="stat-grid">
        <StatCard label="Monitored domains" value={stats?.total_monitored_domains} variant="neutral" />
        <StatCard label="Critical findings" value={stats?.critical_findings} variant="critical"
          sub="Require immediate action" />
        <StatCard label="High findings" value={stats?.high_findings} variant="high" />
        <StatCard label="Open findings" value={stats?.total_open_findings} variant="neutral" />
        <StatCard label="Confirmed clones" value={stats?.confirmed_clones} variant="critical"
          sub="Active cloned pages" />
        <StatCard label="Discovered today" value={stats?.newly_discovered_today} variant="neutral" />
        <StatCard label="Total discovered" value={stats?.total_discovered_domains} variant="neutral" />
      </div>

      {/* Charts row 1 */}
      <div className="chart-grid">
        <div className="card">
          <div className="card-header">
            <div className="card-title">Findings trend — 30 days</div>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={trend}>
              <defs>
                <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#F5A623" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#F5A623" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
                tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
                tickLine={false} axisLine={false} width={28} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="count" name="Findings"
                stroke="#F5A623" fill="url(#trendGrad)" strokeWidth={2} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">By severity</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
            <ResponsiveContainer width="50%" height={180}>
              <PieChart>
                <Pie data={bySeverity} cx="50%" cy="50%" innerRadius={50} outerRadius={76}
                  dataKey="value" strokeWidth={0}>
                  {bySeverity.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, flex: 1 }}>
              {bySeverity.map(s => (
                <div key={s.name} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13 }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: s.fill, display: 'inline-block' }} />
                    <span style={{ color: 'var(--text-secondary)', textTransform: 'capitalize' }}>{s.name}</span>
                  </span>
                  <strong style={{ color: s.fill }}>{s.value}</strong>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Charts row 2 */}
      <div className="chart-grid">
        <div className="card">
          <div className="card-header">
            <div className="card-title">By discovery source</div>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={bySource} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
                tickLine={false} axisLine={false} />
              <YAxis type="category" dataKey="source" tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
                tickLine={false} axisLine={false} width={110} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="count" name="Findings" fill="#378ADD" radius={[0, 3, 3, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">By TLD</div>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={byTLD}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="tld" tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
                tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
                tickLine={false} axisLine={false} width={28} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="count" name="Findings" fill="#7F77DD" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
