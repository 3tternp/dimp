import { useEffect, useState } from 'react';
import { Download, FileText, Plus, RefreshCw } from 'lucide-react';
import { getReports, createReport, getAssets, downloadReport } from '../services/api';
import { Spinner, EmptyState } from '../components/ui';
import { fmtDateTime, timeAgo } from '../utils/format';

const FORMAT_META = {
  html: { color: '#378ADD', label: 'HTML' },
  pdf:  { color: '#E24B4A', label: 'PDF' },
  csv:  { color: '#3DAA6A', label: 'CSV' },
  json: { color: '#EF9F27', label: 'JSON' },
};

function FormatBadge({ format }) {
  const meta = FORMAT_META[format] || { color: '#526180', label: format?.toUpperCase() };
  return (
    <span style={{ background: `${meta.color}18`, color: meta.color,
      fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 4,
      letterSpacing: '0.3px' }}>
      {meta.label}
    </span>
  );
}

function fmtBytes(n) {
  if (!n) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export default function Reports() {
  const [reports, setReports] = useState([]);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [toast, setToast] = useState('');
  const [form, setForm] = useState({ title: '', format: 'html', asset_id: '' });

  const notify = (msg) => { setToast(msg); setTimeout(() => setToast(''), 3500); };

  const load = () => {
    getReports().then(setReports).catch(console.error).finally(() => setLoading(false));
  };

  useEffect(() => { load(); getAssets().then(setAssets); }, []);

  // Poll if any report is pending (no file yet)
  useEffect(() => {
    const hasPending = reports.some(r => !r.file_path && r.findings_count === 0);
    if (!hasPending) return;
    const t = setTimeout(load, 4000);
    return () => clearTimeout(t);
  }, [reports]);

  const handleGenerate = async () => {
    if (!form.title.trim()) return notify('Enter a report title');
    setGenerating(true);
    try {
      const payload = { ...form, asset_id: form.asset_id || undefined };
      await createReport(payload);
      notify('Report queued — will be ready shortly');
      setShowForm(false);
      setForm({ title: '', format: 'html', asset_id: '' });
      setTimeout(load, 1500);
    } catch (e) {
      notify(e.response?.data?.detail || 'Failed to generate report');
    } finally { setGenerating(false); }
  };

  return (
    <div className="page-body">
      <div className="page-header">
        <div>
          <div className="page-title">Reports</div>
          <div className="page-subtitle">{reports.length} reports generated</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-ghost" onClick={load}><RefreshCw size={14} /> Refresh</button>
          <button className="btn btn-primary" onClick={() => setShowForm(s => !s)}>
            <Plus size={14} /> New report
          </button>
        </div>
      </div>

      {showForm && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="card-title" style={{ marginBottom: 14 }}>Generate report</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="form-field">
              <label className="label">Title</label>
              <input className="input" placeholder="Monthly impersonation report"
                value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
            </div>
            <div className="form-field">
              <label className="label">Format</label>
              <select className="input" value={form.format} onChange={e => setForm(f => ({ ...f, format: e.target.value }))}>
                <option value="html">HTML report</option>
                <option value="csv">CSV spreadsheet</option>
                <option value="json">JSON export</option>
                <option value="pdf">PDF report</option>
              </select>
            </div>
            <div className="form-field">
              <label className="label">Asset (optional — leave blank for all)</label>
              <select className="input" value={form.asset_id} onChange={e => setForm(f => ({ ...f, asset_id: e.target.value }))}>
                <option value="">All monitored assets</option>
                {assets.map(a => <option key={a.id} value={a.id}>{a.domain}</option>)}
              </select>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
            <button className="btn btn-primary" onClick={handleGenerate} disabled={generating}>
              {generating ? 'Queuing…' : 'Generate'}
            </button>
            <button className="btn btn-ghost" onClick={() => setShowForm(false)}>Cancel</button>
          </div>
        </div>
      )}

      {loading ? <Spinner /> : reports.length === 0 ? (
        <EmptyState title="No reports yet" icon={<FileText size={32} />}
          message="Generate a report to get an exportable summary of all findings." />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Title</th>
                <th>Format</th>
                <th>Asset</th>
                <th>Findings</th>
                <th>Size</th>
                <th>Created</th>
                <th>Download</th>
              </tr>
            </thead>
            <tbody>
              {reports.map(r => {
                const asset = assets.find(a => a.id === r.asset_id);
                const dlUrl = downloadReport(r.id);
                return (
                  <tr key={r.id}>
                    <td style={{ fontWeight: 500 }}>{r.title}</td>
                    <td><FormatBadge format={r.format} /></td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }} className="mono">
                      {asset?.domain || 'All assets'}
                    </td>
                    <td style={{ color: 'var(--amber)', fontWeight: 500 }}>{r.findings_count}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{fmtBytes(r.file_size_bytes)}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{timeAgo(r.created_at)}</td>
                    <td>
                      {r.file_size_bytes ? (
                        <a href={dlUrl} target="_blank" rel="noopener noreferrer"
                          className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12 }}>
                          <Download size={13} /> Download
                        </a>
                      ) : (
                        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Generating…</span>
                      )}
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
