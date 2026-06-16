import { scoreColor, severityColor, capitalize } from '../../utils/format';

export function ScoreBar({ score }) {
  const color = scoreColor(score);
  return (
    <div className="score-bar">
      <div className="score-bar-track">
        <div className="score-bar-fill" style={{ width: `${score}%`, background: color }} />
      </div>
      <span className="score-num" style={{ color }}>{score}</span>
    </div>
  );
}

export function SeverityBadge({ severity }) {
  return (
    <span className={`badge ${severity}`}>
      {capitalize(severity)}
    </span>
  );
}

export function StatusPill({ status }) {
  return (
    <span className={`status-pill ${status}`}>
      {capitalize(status)}
    </span>
  );
}

export function Spinner() {
  return (
    <div className="loading-spinner">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
        style={{ animation: 'spin 1s linear infinite' }}>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        <path d="M21 12a9 9 0 11-6.219-8.56" />
      </svg>
      Loading…
    </div>
  );
}

export function EmptyState({ icon, title, message, action }) {
  return (
    <div className="empty-state">
      {icon && <div style={{ marginBottom: 12, opacity: 0.4 }}>{icon}</div>}
      <h3>{title}</h3>
      <p style={{ fontSize: 13, marginTop: 6 }}>{message}</p>
      {action && <div style={{ marginTop: 16 }}>{action}</div>}
    </div>
  );
}

export function DetectionTypeBadge({ type }) {
  const colors = {
    typosquatting: { bg: 'rgba(127,119,221,0.12)', c: '#A09AE8' },
    homoglyph: { bg: 'rgba(245,166,35,0.12)', c: '#F5A623' },
    cloned_page: { bg: 'rgba(226,75,74,0.12)', c: '#F07777' },
    phishing_feed: { bg: 'rgba(226,75,74,0.15)', c: '#F07777' },
    cert_transparency: { bg: 'rgba(55,138,221,0.12)', c: '#67A9E8' },
    extra_word: { bg: 'rgba(61,170,106,0.12)', c: '#5DC98A' },
    tld_variation: { bg: 'rgba(82,97,128,0.12)', c: '#8A9BBB' },
    urlscan: { bg: 'rgba(239,159,39,0.12)', c: '#F0B85A' },
  };
  const { bg = 'rgba(82,97,128,0.12)', c = '#8A9BBB' } = colors[type] || {};
  return (
    <span style={{
      background: bg, color: c,
      fontSize: 11, fontWeight: 600, padding: '2px 7px',
      borderRadius: 4, letterSpacing: '0.3px', textTransform: 'uppercase'
    }}>
      {capitalize(type)}
    </span>
  );
}
