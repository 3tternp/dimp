import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, ExternalLink, Globe, Shield, AlertTriangle, FileText } from 'lucide-react';
import { getFinding, updateFindingStatus } from '../services/api';
import { ScoreBar, SeverityBadge, StatusPill, DetectionTypeBadge, Spinner } from '../components/ui';
import { fmtDateTime, timeAgo, capitalize } from '../utils/format';

const STATUSES = ['new', 'under_review', 'confirmed', 'false_positive', 'takedown_requested', 'resolved'];

function Section({ title, icon: Icon, children }) {
  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <div className="card-header" style={{ marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {Icon && <Icon size={15} style={{ color: 'var(--text-muted)' }} />}
          <div className="card-title">{title}</div>
        </div>
      </div>
      {children}
    </div>
  );
}

function Row({ label, value, mono }) {
  return (
    <div className="detail-row">
      <span className="detail-key">{label}</span>
      <span className={`detail-val${mono ? '' : ''}`}
        style={{ fontFamily: mono ? 'var(--font-mono)' : 'inherit', fontSize: mono ? 12 : 13 }}>
        {value ?? '—'}
      </span>
    </div>
  );
}

function DNSTable({ records }) {
  if (!records?.length) return <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No DNS records collected.</p>;
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Type</th><th>Value</th><th>TTL</th><th>Priority</th></tr></thead>
        <tbody>
          {records.map((r, i) => (
            <tr key={i}>
              <td><span className="badge medium">{r.record_type}</span></td>
              <td className="mono">{r.value}</td>
              <td style={{ color: 'var(--text-muted)' }}>{r.ttl ?? '—'}</td>
              <td style={{ color: 'var(--text-muted)' }}>{r.priority ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function FindingDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [finding, setFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState('');
  const [notes, setNotes] = useState('');
  const [toast, setToast] = useState('');

  useEffect(() => {
    getFinding(id)
      .then(f => { setFinding(f); setStatus(f.status); setNotes(f.notes || ''); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [id]);

  const saveStatus = async () => {
    setSaving(true);
    try {
      const updated = await updateFindingStatus(id, status, notes);
      setFinding(f => ({ ...f, ...updated }));
      setToast('Status updated');
      setTimeout(() => setToast(''), 3000);
    } catch (e) { console.error(e); }
    finally { setSaving(false); }
  };

  if (loading) return <Spinner />;
  if (!finding) return <div className="page-body"><p>Finding not found.</p></div>;

  const domain = finding.domain_entry;
  const whois = domain?.whois_record;
  const ssl = domain?.ssl_certificate;
  const snap = domain?.snapshots?.[0];
  const sim = domain?.similarity_results?.[0];
  const tiMatches = domain?.threat_intel_matches || [];

  return (
    <div className="page-body">
      <div style={{ marginBottom: 20 }}>
        <button className="btn btn-ghost" onClick={() => navigate('/findings')} style={{ marginBottom: 16 }}>
          <ArrowLeft size={14} /> Back to findings
        </button>

        <div className="page-header" style={{ alignItems: 'flex-start' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <SeverityBadge severity={finding.severity} />
              <StatusPill status={finding.status} />
              <DetectionTypeBadge type={finding.detection_type} />
            </div>
            <div className="page-title" style={{ fontFamily: 'var(--font-mono)', fontSize: 18 }}>
              {domain?.domain || 'Unknown domain'}
            </div>
            <div className="page-subtitle" style={{ marginTop: 6 }}>
              First seen {timeAgo(finding.first_seen_at)} · Source: {finding.discovery_source}
            </div>
          </div>
          <a href={`https://${domain?.domain}`} target="_blank" rel="noopener noreferrer"
            className="btn btn-ghost">
            <ExternalLink size={14} /> Open domain
          </a>
        </div>
      </div>

      <div className="detail-grid">
        {/* Left column */}
        <div>
          {/* Risk summary */}
          <Section title="Risk assessment" icon={AlertTriangle}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 16 }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>Risk score</div>
                <ScoreBar score={finding.risk_score} />
              </div>
            </div>
            {finding.summary && (
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6,
                background: 'var(--surface-3)', borderRadius: 8, padding: '10px 14px',
                borderLeft: '3px solid var(--amber)' }}>
                {finding.summary}
              </div>
            )}
            {finding.recommended_action && (
              <div style={{ marginTop: 12, fontSize: 13 }}>
                <div style={{ color: 'var(--text-muted)', marginBottom: 4, fontSize: 11,
                  textTransform: 'uppercase', letterSpacing: '0.4px' }}>Recommended action</div>
                <div style={{ color: 'var(--text-secondary)' }}>{finding.recommended_action}</div>
              </div>
            )}
          </Section>

          {/* Domain metadata */}
          <Section title="Domain metadata" icon={Globe}>
            <Row label="Domain" value={domain?.domain} mono />
            <Row label="IP address" value={domain?.ip_address} mono />
            <Row label="ASN" value={domain?.asn ? `${domain.asn} (${domain.asn_org})` : null} mono />
            <Row label="Hosting" value={domain?.hosting_provider} />
            <Row label="Country" value={domain?.country_name ? `${domain.country_name} (${domain.country_code})` : null} />
            <Row label="HTTP status" value={domain?.http_status_code} />
            <Row label="Active website" value={domain?.is_active_website ? 'Yes' : 'No'} />
            <Row label="Page title" value={domain?.page_title} />
            {domain?.redirect_chain?.length > 1 && (
              <div className="detail-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 4 }}>
                <span className="detail-key">Redirect chain</span>
                {domain.redirect_chain.map((url, i) => (
                  <span key={i} style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
                    color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                    {i > 0 && '→ '}{url}
                  </span>
                ))}
              </div>
            )}
          </Section>

          {/* WHOIS */}
          <Section title="WHOIS / registration">
            <Row label="Registrar" value={whois?.registrar} />
            <Row label="Created" value={whois?.creation_date ? fmtDateTime(whois.creation_date) : null} />
            <Row label="Expires" value={whois?.expiry_date ? fmtDateTime(whois.expiry_date) : null} />
            <Row label="Name servers" value={whois?.name_servers?.join(', ')} mono />
            <Row label="Registrant org" value={whois?.registrant_org} />
            <Row label="Registrant country" value={whois?.registrant_country} />
            <Row label="Privacy protected" value={whois?.privacy_protected ? 'Yes' : 'No'} />
          </Section>
        </div>

        {/* Right column */}
        <div>
          {/* Status workflow */}
          <Section title="Workflow" icon={Shield}>
            <div className="form-field">
              <label className="label">Status</label>
              <select className="input" value={status} onChange={e => setStatus(e.target.value)}>
                {STATUSES.map(s => <option key={s} value={s}>{capitalize(s)}</option>)}
              </select>
            </div>
            <div className="form-field">
              <label className="label">Notes</label>
              <textarea className="input" rows={3} value={notes}
                onChange={e => setNotes(e.target.value)}
                placeholder="Add investigation notes…"
                style={{ resize: 'vertical' }} />
            </div>
            <button className="btn btn-primary" onClick={saveStatus} disabled={saving}>
              {saving ? 'Saving…' : 'Update status'}
            </button>
            <div style={{ marginTop: 12, fontSize: 12, color: 'var(--text-muted)' }}>
              Last updated {timeAgo(finding.last_updated_at)}
            </div>
          </Section>

          {/* SSL certificate */}
          <Section title="SSL certificate">
            <Row label="Issuer" value={ssl?.issuer_org || ssl?.issuer_cn} />
            <Row label="Subject CN" value={ssl?.subject_cn} mono />
            <Row label="Valid from" value={ssl?.not_before ? fmtDateTime(ssl.not_before) : null} />
            <Row label="Valid to" value={ssl?.not_after ? fmtDateTime(ssl.not_after) : null} />
            <Row label="Expired" value={ssl?.is_expired ? '⚠ Yes' : 'No'} />
            <Row label="Self-signed" value={ssl?.is_self_signed ? '⚠ Yes' : 'No'} />
            <Row label="TLS version" value={ssl?.tls_version} />
            {ssl?.subject_alt_names?.length > 0 && (
              <div className="detail-row" style={{ flexDirection: 'column', gap: 4, alignItems: 'flex-start' }}>
                <span className="detail-key">SANs ({ssl.subject_alt_names.length})</span>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)',
                  maxHeight: 80, overflowY: 'auto', lineHeight: 1.8 }}>
                  {ssl.subject_alt_names.slice(0, 20).join(', ')}
                  {ssl.subject_alt_names.length > 20 && ` +${ssl.subject_alt_names.length - 20} more`}
                </div>
              </div>
            )}
          </Section>

          {/* Similarity */}
          {sim && (
            <Section title="Similarity analysis">
              {[
                ['Visual (pHash)', sim.visual_similarity_score],
                ['Content (TF-IDF)', sim.tfidf_score],
                ['DOM structure', sim.dom_similarity_score],
                ['Overall', sim.overall_similarity_score],
              ].map(([label, val]) => val != null && (
                <div className="detail-row" key={label}>
                  <span className="detail-key">{label}</span>
                  <div style={{ width: 140 }}>
                    <ScoreBar score={Math.round(val * 100)} />
                  </div>
                </div>
              ))}
              <Row label="Favicon match" value={sim.favicon_hash_match ? '✓ Match' : 'No match'} />
            </Section>
          )}

          {/* Threat intel */}
          {tiMatches.length > 0 && (
            <Section title={`Threat intel (${tiMatches.length} hits)`}>
              {tiMatches.map((ti, i) => (
                <div key={i} style={{ marginBottom: 10, paddingBottom: 10,
                  borderBottom: i < tiMatches.length - 1 ? '1px solid var(--border)' : 'none' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontWeight: 500, color: 'var(--text-primary)', fontSize: 13 }}>
                      {ti.feed_name}
                    </span>
                    {ti.confidence && (
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {Math.round(ti.confidence * 100)}% confidence
                      </span>
                    )}
                  </div>
                  {ti.threat_type && (
                    <span className="badge critical" style={{ fontSize: 10 }}>{ti.threat_type}</span>
                  )}
                </div>
              ))}
            </Section>
          )}
        </div>
      </div>

      {/* Web form detection */}
      {snap && (
        <Section title="Page analysis" icon={FileText}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
            {[
              { label: 'Login form', value: snap.has_login_form, danger: snap.has_login_form },
              { label: 'Credential fields', value: snap.has_credential_fields, danger: snap.has_credential_fields },
              { label: 'External form action', value: snap.external_form_action, danger: snap.external_form_action },
            ].map(({ label, value, danger }) => (
              <div key={label} style={{
                background: danger ? 'rgba(226,75,74,0.08)' : 'var(--surface-3)',
                borderRadius: 8, padding: '12px 16px',
                border: `1px solid ${danger ? 'rgba(226,75,74,0.2)' : 'var(--border)'}`
              }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>{label}</div>
                <div style={{ fontWeight: 600, color: danger ? 'var(--red)' : 'var(--green)' }}>
                  {value ? '⚠ Detected' : '✓ Not detected'}
                </div>
              </div>
            ))}
          </div>
          {snap.brand_keywords_found?.length > 0 && (
            <div style={{ marginTop: 14 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6,
                textTransform: 'uppercase', letterSpacing: '0.4px' }}>
                Brand keywords found on page
              </div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {snap.brand_keywords_found.map(k => (
                  <span key={k} style={{ background: 'rgba(245,166,35,0.12)', color: 'var(--amber)',
                    fontSize: 12, padding: '2px 8px', borderRadius: 4 }}>{k}</span>
                ))}
              </div>
            </div>
          )}
        </Section>
      )}

      {/* DNS records */}
      <Section title={`DNS records (${domain?.dns_records?.length || 0})`} icon={Globe}>
        <DNSTable records={domain?.dns_records} />
      </Section>

      {toast && (
        <div className="toast">
          <span style={{ color: 'var(--green)' }}>✓</span> {toast}
        </div>
      )}
    </div>
  );

  function DNSTable({ records }) {
    if (!records?.length) return <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No DNS records collected.</p>;
    return (
      <div className="table-wrap">
        <table>
          <thead><tr><th>Type</th><th>Value</th><th>TTL</th></tr></thead>
          <tbody>
            {records.map((r, i) => (
              <tr key={i}>
                <td><span className="badge medium">{r.record_type}</span></td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--amber)' }}>{r.value}</td>
                <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{r.ttl ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
}
