import { useEffect, useState, useCallback } from 'react';
import { RefreshCw, Radar, CheckCircle, XCircle, Clock, Loader } from 'lucide-react';
import { getScanJobs, getAssets, triggerScan } from '../services/api';
import { Spinner, EmptyState } from '../components/ui';
import { fmtDateTime, timeAgo } from '../utils/format';

const STATUS_META = {
  queued:    { color: 'var(--text-muted)', icon: Clock, label: 'Queued' },
  running:   { color: 'var(--amber)',      icon: Loader, label: 'Running' },
  completed: { color: 'var(--green)',      icon: CheckCircle, label: 'Completed' },
  failed:    { color: 'var(--red)',        icon: XCircle, label: 'Failed' },
  cancelled: { color: 'var(--text-muted)', icon: XCircle, label: 'Cancelled' },
};

function StatusIcon({ status }) {
  const meta = STATUS_META[status] || STATUS_META.queued;
  const Icon = meta.icon;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5,
      fontSize: 12, color: meta.color }}>
      <Icon size={13} style={status === 'running' ? { animation: 'spin 1.2s linear infinite' } : {}} />
      {meta.label}
    </span>
  );
}

function ProgressBar({ done, total }) {
  if (!total) return null;
  const pct = Math.round((done / total) * 100);
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 4, background: 'var(--surface-3)', borderRadius: 2 }}>
        <div style={{ width: `${pct}%`, height: '100%', background: 'var(--amber)', borderRadius: 2,
          transition: 'width 0.3s' }} />
      </div>
      <span style={{ fontSize: 11, color: 'var(--text-muted)', minWidth: 30 }}>{pct}%</span>
    </div>
  );
}

export default function Scans() {
  const [jobs, setJobs] = useState([]);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [assetId, setAssetId] = useState('');
  const [scanning, setScanning] = useState(false);
  const [toast, setToast] = useState('');

  const notify = (msg) => { setToast(msg); setTimeout(() => setToast(''), 3000); };

  const load = useCallback(() => {
    getScanJobs(assetId || undefined)
      .then(setJobs)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [assetId]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { getAssets().then(setAssets); }, []);

  // Auto-refresh when any job is running
  useEffect(() => {
    const hasRunning = jobs.some(j => j.status === 'running' || j.status === 'queued');
    if (!hasRunning) return;
    const t = setTimeout(load, 4000);
    return () => clearTimeout(t);
  }, [jobs, load]);

  const handleTrigger = async () => {
    if (!assetId) return notify('Select an asset first');
    setScanning(true);
    try {
      await triggerScan(assetId);
      notify('Scan queued');
      setTimeout(load, 800);
    } catch { notify('Failed to trigger scan'); }
    finally { setScanning(false); }
  };

  return (
    <div className="page-body">
      <div className="page-header">
        <div>
          <div className="page-title">Scan history</div>
          <div className="page-subtitle">{jobs.length} jobs · auto-refreshes while running</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-ghost" onClick={load}><RefreshCw size={14} /> Refresh</button>
        </div>
      </div>

      {/* Trigger panel */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-title" style={{ marginBottom: 12 }}>Trigger manual scan</div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end' }}>
          <div className="form-field" style={{ flex: 1, margin: 0 }}>
            <label className="label">Asset</label>
            <select className="input" value={assetId} onChange={e => setAssetId(e.target.value)}>
              <option value="">Select a monitored domain…</option>
              {assets.map(a => <option key={a.id} value={a.id}>{a.domain}</option>)}
            </select>
          </div>
          <button className="btn btn-primary" onClick={handleTrigger} disabled={scanning || !assetId}>
            <Radar size={14} /> {scanning ? 'Queuing…' : 'Start scan'}
          </button>
        </div>
      </div>

      {loading ? <Spinner /> : jobs.length === 0 ? (
        <EmptyState title="No scan jobs" icon={<Radar size={32} />}
          message="Trigger a manual scan or wait for the scheduler to run." />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Asset</th>
                <th>Status</th>
                <th>Type</th>
                <th>Discovered</th>
                <th>Analysed</th>
                <th>Findings</th>
                <th>Queued</th>
                <th>Duration</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map(j => {
                const asset = assets.find(a => a.id === j.asset_id);
                const duration = j.completed_at && j.started_at
                  ? Math.round((new Date(j.completed_at) - new Date(j.started_at)) / 1000)
                  : null;
                return (
                  <tr key={j.id}>
                    <td>
                      <span className="mono" style={{ fontSize: 13 }}>
                        {asset?.domain || j.asset_id.slice(0, 8) + '…'}
                      </span>
                    </td>
                    <td>
                      <StatusIcon status={j.status} />
                      {j.status === 'running' && j.domains_discovered > 0 && (
                        <div style={{ marginTop: 4, width: 140 }}>
                          <ProgressBar done={j.domains_analysed} total={j.domains_discovered} />
                        </div>
                      )}
                      {j.error_message && (
                        <div style={{ fontSize: 11, color: 'var(--red)', marginTop: 4,
                          maxWidth: 240, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {j.error_message}
                        </div>
                      )}
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                      {j.is_manual ? 'Manual' : 'Scheduled'}
                    </td>
                    <td style={{ color: 'var(--amber)', fontWeight: 500 }}>{j.domains_discovered}</td>
                    <td style={{ color: 'var(--text-secondary)' }}>{j.domains_analysed}</td>
                    <td style={{ color: j.findings_created > 0 ? 'var(--red)' : 'var(--text-muted)' }}>
                      {j.findings_created > 0
                        ? <strong>{j.findings_created} new</strong>
                        : j.findings_created}
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{timeAgo(j.queued_at)}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                      {duration != null ? `${duration}s` : j.started_at ? 'Running…' : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {toast && <div className="toast"><span style={{ color: 'var(--green)' }}>✓</span> {toast}</div>}
    </div>
  );
}
