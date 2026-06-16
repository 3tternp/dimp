import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, RefreshCw, Download } from 'lucide-react';
import { getFindings, getAssets, createReport } from '../services/api';
import { ScoreBar, SeverityBadge, StatusPill, DetectionTypeBadge, Spinner, EmptyState } from '../components/ui';
import { timeAgo, truncate } from '../utils/format';

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low'];
const STATUSES = ['', 'new', 'under_review', 'confirmed', 'false_positive', 'takedown_requested', 'resolved'];
const DET_TYPES = ['', 'typosquatting', 'homoglyph', 'lookalike', 'extra_word', 'tld_variation',
  'cert_transparency', 'phishing_feed', 'cloned_page', 'brand_keyword', 'urlscan'];

export default function Findings() {
  const navigate = useNavigate();
  const [findings, setFindings] = useState([]);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);

  const [filters, setFilters] = useState({
    asset_id: '', severity: '', status: '', detection_type: '', skip: 0, limit: 50
  });

  const load = useCallback(() => {
    setLoading(true);
    const params = Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== ''));
    getFindings(params)
      .then(setFindings)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [filters]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    getAssets().then(setAssets).catch(console.error);
  }, []);

  const setFilter = (k, v) => setFilters(f => ({ ...f, [k]: v, skip: 0 }));

  const exportCSV = async () => {
    setExporting(true);
    try {
      const r = await createReport({ title: 'Findings export', format: 'csv' });
      setTimeout(() => {
        window.open(`/api/v1/reports/${r.id}/download`, '_blank');
      }, 2000);
    } catch (e) { console.error(e); }
    finally { setExporting(false); }
  };

  return (
    <div className="page-body">
      <div className="page-header">
        <div>
          <div className="page-title">Findings</div>
          <div className="page-subtitle">{findings.length} results · filter to narrow</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-ghost" onClick={load}>
            <RefreshCw size={14} /> Refresh
          </button>
          <button className="btn btn-secondary" onClick={exportCSV} disabled={exporting}>
            <Download size={14} /> Export CSV
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="filter-bar">
        <select className="input" value={filters.asset_id} onChange={e => setFilter('asset_id', e.target.value)}>
          <option value="">All assets</option>
          {assets.map(a => <option key={a.id} value={a.id}>{a.domain}</option>)}
        </select>

        <select className="input" value={filters.severity} onChange={e => setFilter('severity', e.target.value)}>
          {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All severities'}</option>)}
        </select>

        <select className="input" value={filters.status} onChange={e => setFilter('status', e.target.value)}>
          {STATUSES.map(s => <option key={s} value={s}>{s || 'All statuses'}</option>)}
        </select>

        <select className="input" value={filters.detection_type}
          onChange={e => setFilter('detection_type', e.target.value)}>
          {DET_TYPES.map(d => <option key={d} value={d}>{d || 'All types'}</option>)}
        </select>
      </div>

      {loading ? <Spinner /> : findings.length === 0 ? (
        <EmptyState title="No findings" message="Adjust filters or trigger a scan to discover suspicious domains." />
      ) : (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Suspicious domain</th>
                  <th>Severity</th>
                  <th style={{ width: 140 }}>Risk score</th>
                  <th>Type</th>
                  <th>Source</th>
                  <th>Status</th>
                  <th>First seen</th>
                </tr>
              </thead>
              <tbody>
                {findings.map(f => (
                  <tr key={f.id} onClick={() => navigate(`/findings/${f.id}`)}>
                    <td>
                      <span className="mono">{truncate(f.domain_id, 45)}</span>
                      {f.summary && (
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                          {truncate(f.summary, 60)}
                        </div>
                      )}
                    </td>
                    <td><SeverityBadge severity={f.severity} /></td>
                    <td><ScoreBar score={f.risk_score} /></td>
                    <td><DetectionTypeBadge type={f.detection_type} /></td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{f.discovery_source}</td>
                    <td><StatusPill status={f.status} /></td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{timeAgo(f.first_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 12 }}>
            <button className="btn btn-ghost" disabled={filters.skip === 0}
              onClick={() => setFilters(f => ({ ...f, skip: Math.max(0, f.skip - f.limit) }))}>
              ← Previous
            </button>
            <span style={{ lineHeight: '36px', fontSize: 13, color: 'var(--text-muted)' }}>
              {filters.skip + 1}–{filters.skip + findings.length}
            </span>
            <button className="btn btn-ghost" disabled={findings.length < filters.limit}
              onClick={() => setFilters(f => ({ ...f, skip: f.skip + f.limit }))}>
              Next →
            </button>
          </div>
        </>
      )}
    </div>
  );
}
