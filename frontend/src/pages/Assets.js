import { useEffect, useState } from 'react';
import { Plus, Trash2, Play, ChevronDown, ChevronUp, Globe } from 'lucide-react';
import { getAssets, createAsset, deleteAsset, triggerScan,
         getAssetKeywords, addKeyword, deleteKeyword } from '../services/api';
import { StatusPill, Spinner, EmptyState } from '../components/ui';
import { timeAgo, fmtDate } from '../utils/format';

function AssetRow({ asset, onDelete, onScan, onExpand, expanded }) {
  return (
    <>
      <tr onClick={onExpand} style={{ cursor: 'pointer' }}>
        <td>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Globe size={14} style={{ color: 'var(--amber)', flexShrink: 0 }} />
            <span className="mono">{asset.domain}</span>
          </div>
          {asset.display_name && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, marginLeft: 22 }}>
              {asset.display_name}
            </div>
          )}
        </td>
        <td>
          <span style={{ fontSize: 12, padding: '2px 8px', borderRadius: 4,
            background: 'var(--surface-3)', color: 'var(--text-secondary)' }}>
            {asset.scan_frequency}
          </span>
        </td>
        <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>
          {asset.last_scanned_at ? timeAgo(asset.last_scanned_at) : 'Never'}
        </td>
        <td>
          <span style={{ color: asset.is_active ? 'var(--green)' : 'var(--text-muted)', fontSize: 12 }}>
            {asset.is_active ? '● Active' : '○ Paused'}
          </span>
        </td>
        <td>
          <div style={{ display: 'flex', gap: 6 }} onClick={e => e.stopPropagation()}>
            <button className="btn btn-primary" style={{ padding: '5px 10px', fontSize: 12 }}
              onClick={() => onScan(asset.id)}>
              <Play size={12} /> Scan
            </button>
            <button className="btn btn-danger" style={{ padding: '5px 10px', fontSize: 12 }}
              onClick={() => onDelete(asset.id)}>
              <Trash2 size={12} />
            </button>
          </div>
        </td>
        <td style={{ color: 'var(--text-muted)' }}>
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </td>
      </tr>
      {expanded && <AssetExpanded assetId={asset.id} />}
    </>
  );
}

function AssetExpanded({ assetId }) {
  const [keywords, setKeywords] = useState([]);
  const [newKw, setNewKw] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAssetKeywords(assetId).then(setKeywords).finally(() => setLoading(false));
  }, [assetId]);

  const addKw = async () => {
    if (!newKw.trim()) return;
    const kw = await addKeyword(assetId, newKw.trim());
    setKeywords(k => [...k, kw]);
    setNewKw('');
  };

  const delKw = async (id) => {
    await deleteKeyword(assetId, id);
    setKeywords(k => k.filter(x => x.id !== id));
  };

  return (
    <tr>
      <td colSpan={6} style={{ background: 'var(--surface-3)', padding: '16px 20px' }}>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8,
          textTransform: 'uppercase', letterSpacing: '0.4px' }}>Brand keywords</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 10 }}>
          {loading ? <span style={{ color: 'var(--text-muted)' }}>Loading…</span> :
            keywords.length === 0 ? <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>No keywords yet</span> :
            keywords.map(kw => (
              <span key={kw.id} style={{ display: 'inline-flex', alignItems: 'center', gap: 6,
                background: 'var(--amber-glow)', color: 'var(--amber)',
                fontSize: 12, padding: '3px 10px', borderRadius: 20 }}>
                {kw.keyword}
                <button onClick={() => delKw(kw.id)}
                  style={{ background: 'none', border: 'none', color: 'inherit',
                    cursor: 'pointer', padding: 0, lineHeight: 1 }}>×</button>
              </span>
            ))
          }
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <input className="input" style={{ maxWidth: 220 }} value={newKw}
            onChange={e => setNewKw(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && addKw()}
            placeholder="Add keyword…" />
          <button className="btn btn-secondary" onClick={addKw}><Plus size={13} /> Add</button>
        </div>
      </td>
    </tr>
  );
}

export default function Assets() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [toast, setToast] = useState('');
  const [form, setForm] = useState({ domain: '', display_name: '', scan_frequency: 'daily', risk_threshold: 50 });

  useEffect(() => {
    getAssets().then(setAssets).catch(console.error).finally(() => setLoading(false));
  }, []);

  const notify = (msg) => { setToast(msg); setTimeout(() => setToast(''), 3000); };

  const handleCreate = async () => {
    if (!form.domain.trim()) return;
    try {
      const a = await createAsset(form);
      setAssets(prev => [a, ...prev]);
      setShowAdd(false);
      setForm({ domain: '', display_name: '', scan_frequency: 'daily', risk_threshold: 50 });
      notify(`${a.domain} added`);
    } catch (e) {
      notify(e.response?.data?.detail || 'Failed to add asset');
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Remove this monitored asset and all its findings?')) return;
    await deleteAsset(id);
    setAssets(a => a.filter(x => x.id !== id));
    notify('Asset removed');
  };

  const handleScan = async (assetId) => {
    try {
      await triggerScan(assetId);
      notify('Scan queued — check Scan history for progress');
    } catch (e) { notify('Failed to trigger scan'); }
  };

  return (
    <div className="page-body">
      <div className="page-header">
        <div>
          <div className="page-title">Monitored assets</div>
          <div className="page-subtitle">{assets.length} domain{assets.length !== 1 ? 's' : ''} under watch</div>
        </div>
        <button className="btn btn-primary" onClick={() => setShowAdd(s => !s)}>
          <Plus size={14} /> Add domain
        </button>
      </div>

      {showAdd && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="card-title" style={{ marginBottom: 16 }}>Add monitored domain</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="form-field">
              <label className="label">Domain *</label>
              <input className="input" placeholder="examplebank.com"
                value={form.domain} onChange={e => setForm(f => ({ ...f, domain: e.target.value }))} />
            </div>
            <div className="form-field">
              <label className="label">Display name</label>
              <input className="input" placeholder="Example Bank"
                value={form.display_name} onChange={e => setForm(f => ({ ...f, display_name: e.target.value }))} />
            </div>
            <div className="form-field">
              <label className="label">Scan frequency</label>
              <select className="input" value={form.scan_frequency}
                onChange={e => setForm(f => ({ ...f, scan_frequency: e.target.value }))}>
                <option value="hourly">Hourly</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
              </select>
            </div>
            <div className="form-field">
              <label className="label">Risk threshold (0–100)</label>
              <input className="input" type="number" min={0} max={100}
                value={form.risk_threshold}
                onChange={e => setForm(f => ({ ...f, risk_threshold: Number(e.target.value) }))} />
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
            <button className="btn btn-primary" onClick={handleCreate}>Add asset</button>
            <button className="btn btn-ghost" onClick={() => setShowAdd(false)}>Cancel</button>
          </div>
        </div>
      )}

      {loading ? <Spinner /> : assets.length === 0 ? (
        <EmptyState title="No monitored assets" message="Add a domain to start monitoring for impersonation threats." />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Frequency</th>
                <th>Last scanned</th>
                <th>Status</th>
                <th>Actions</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {assets.map(a => (
                <AssetRow key={a.id} asset={a}
                  onDelete={handleDelete} onScan={handleScan}
                  onExpand={() => setExpanded(e => e === a.id ? null : a.id)}
                  expanded={expanded === a.id} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {toast && (
        <div className="toast">
          <span style={{ color: 'var(--green)' }}>✓</span> {toast}
        </div>
      )}
    </div>
  );
}
