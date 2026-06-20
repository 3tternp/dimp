import { useEffect, useState } from 'react';
import { User, Shield, Key, Users, Info, Trash2, Plus, Check, X } from 'lucide-react';
import {
  getProfile, updateProfile, changePassword,
  getUsers, createUser, updateUser, deleteUser, getPlatformInfo
} from '../services/api';
import { useAuth } from '../context/AuthContext';
import { Spinner } from '../components/ui';
import { fmtDateTime } from '../utils/format';

function ProfileSection() {
  const [profile, setProfile] = useState(null);
  const [editing, setEditing] = useState(false);
  const [fullName, setFullName] = useState('');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    getProfile().then(p => { setProfile(p); setFullName(p.full_name); }).catch(console.error);
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      const updated = await updateProfile({ full_name: fullName });
      setProfile(updated);
      setEditing(false);
      setMsg('Profile updated');
      setTimeout(() => setMsg(''), 3000);
    } catch { setMsg('Failed to update'); }
    finally { setSaving(false); }
  };

  if (!profile) return <Spinner />;

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <User size={16} /> Profile
        </div>
      </div>
      <div style={{ padding: '0 20px 20px' }}>
        <div className="settings-row">
          <label>Email</label>
          <span className="mono" style={{ color: 'var(--text-secondary)' }}>{profile.email}</span>
        </div>
        <div className="settings-row">
          <label>Full name</label>
          {editing ? (
            <div style={{ display: 'flex', gap: 8 }}>
              <input className="input" value={fullName} onChange={e => setFullName(e.target.value)}
                style={{ width: 220 }} />
              <button className="btn btn-primary btn-sm" onClick={save} disabled={saving}>
                <Check size={14} />
              </button>
              <button className="btn btn-ghost btn-sm" onClick={() => { setEditing(false); setFullName(profile.full_name); }}>
                <X size={14} />
              </button>
            </div>
          ) : (
            <span style={{ cursor: 'pointer', color: 'var(--text-secondary)' }} onClick={() => setEditing(true)}>
              {profile.full_name} <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>(click to edit)</span>
            </span>
          )}
        </div>
        <div className="settings-row">
          <label>Role</label>
          <span className="badge" style={{ textTransform: 'capitalize' }}>{profile.role}</span>
        </div>
        <div className="settings-row">
          <label>Last login</label>
          <span style={{ color: 'var(--text-muted)' }}>{fmtDateTime(profile.last_login_at)}</span>
        </div>
        {msg && <div style={{ fontSize: 12, color: 'var(--accent)', marginTop: 8 }}>{msg}</div>}
      </div>
    </div>
  );
}

function PasswordSection() {
  const [current, setCurrent] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [confirm, setConfirm] = useState('');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState({ text: '', error: false });

  const submit = async (e) => {
    e.preventDefault();
    if (newPwd !== confirm) { setMsg({ text: 'Passwords do not match', error: true }); return; }
    if (newPwd.length < 8) { setMsg({ text: 'Password must be at least 8 characters', error: true }); return; }
    setSaving(true);
    try {
      await changePassword(current, newPwd);
      setCurrent(''); setNewPwd(''); setConfirm('');
      setMsg({ text: 'Password changed successfully', error: false });
      setTimeout(() => setMsg({ text: '', error: false }), 3000);
    } catch (err) {
      setMsg({ text: err.response?.data?.detail || 'Failed to change password', error: true });
    } finally { setSaving(false); }
  };

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Key size={16} /> Change password
        </div>
      </div>
      <form onSubmit={submit} style={{ padding: '0 20px 20px' }}>
        <div className="settings-row">
          <label>Current password</label>
          <input className="input" type="password" value={current} onChange={e => setCurrent(e.target.value)}
            required style={{ width: 260 }} />
        </div>
        <div className="settings-row">
          <label>New password</label>
          <input className="input" type="password" value={newPwd} onChange={e => setNewPwd(e.target.value)}
            required minLength={8} style={{ width: 260 }} />
        </div>
        <div className="settings-row">
          <label>Confirm password</label>
          <input className="input" type="password" value={confirm} onChange={e => setConfirm(e.target.value)}
            required style={{ width: 260 }} />
        </div>
        <button className="btn btn-primary" type="submit" disabled={saving} style={{ marginTop: 8 }}>
          {saving ? 'Changing...' : 'Change password'}
        </button>
        {msg.text && (
          <div style={{ fontSize: 12, marginTop: 8, color: msg.error ? '#E24B4A' : 'var(--accent)' }}>
            {msg.text}
          </div>
        )}
      </form>
    </div>
  );
}

function UserManagement() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ email: '', full_name: '', password: '', role: 'analyst' });
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');

  const load = () => {
    setLoading(true);
    getUsers().then(setUsers).catch(() => setUsers([])).finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const addUser = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await createUser(form);
      setForm({ email: '', full_name: '', password: '', role: 'analyst' });
      setShowAdd(false);
      load();
      setMsg('User created');
      setTimeout(() => setMsg(''), 3000);
    } catch (err) {
      setMsg(err.response?.data?.detail || 'Failed to create user');
    } finally { setSaving(false); }
  };

  const toggleActive = async (u) => {
    try {
      await updateUser(u.id, { is_active: !u.is_active });
      load();
    } catch { /* ignore */ }
  };

  const removeUser = async (u) => {
    if (!window.confirm(`Delete user ${u.email}?`)) return;
    try {
      await deleteUser(u.id);
      load();
    } catch (err) {
      setMsg(err.response?.data?.detail || 'Failed to delete user');
    }
  };

  if (currentUser?.role !== 'admin') return null;

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Users size={16} /> User management
        </div>
        <button className="btn btn-primary btn-sm" onClick={() => setShowAdd(!showAdd)}>
          <Plus size={14} /> Add user
        </button>
      </div>

      {showAdd && (
        <form onSubmit={addUser} style={{ padding: '0 20px 16px', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <input className="input" placeholder="Email" type="email" required value={form.email}
            onChange={e => setForm(f => ({ ...f, email: e.target.value }))} style={{ width: 220 }} />
          <input className="input" placeholder="Full name" required value={form.full_name}
            onChange={e => setForm(f => ({ ...f, full_name: e.target.value }))} style={{ width: 160 }} />
          <input className="input" placeholder="Password" type="password" required minLength={8}
            value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} style={{ width: 160 }} />
          <select className="input" value={form.role}
            onChange={e => setForm(f => ({ ...f, role: e.target.value }))}>
            <option value="admin">Admin</option>
            <option value="analyst">Analyst</option>
            <option value="viewer">Viewer</option>
          </select>
          <button className="btn btn-primary btn-sm" type="submit" disabled={saving}>
            {saving ? 'Creating...' : 'Create'}
          </button>
          <button className="btn btn-ghost btn-sm" type="button" onClick={() => setShowAdd(false)}>Cancel</button>
        </form>
      )}

      {loading ? <Spinner /> : (
        <div className="table-wrap" style={{ margin: '0 0 12px' }}>
          <table>
            <thead>
              <tr>
                <th>Email</th>
                <th>Name</th>
                <th>Role</th>
                <th>Status</th>
                <th>Created</th>
                <th>Last login</th>
                <th style={{ width: 100 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td><span className="mono">{u.email}</span></td>
                  <td>{u.full_name}</td>
                  <td><span className="badge" style={{ textTransform: 'capitalize' }}>{u.role}</span></td>
                  <td>
                    <span style={{ color: u.is_active ? '#3DAA6A' : '#E24B4A', fontSize: 12 }}>
                      {u.is_active ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{fmtDateTime(u.created_at)}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{fmtDateTime(u.last_login_at)}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 4 }}>
                      <button className="btn btn-ghost btn-sm" onClick={() => toggleActive(u)}
                        title={u.is_active ? 'Disable' : 'Enable'}>
                        <Shield size={13} />
                      </button>
                      {String(u.id) !== String(currentUser.id) && (
                        <button className="btn btn-ghost btn-sm" onClick={() => removeUser(u)}
                          style={{ color: '#E24B4A' }} title="Delete">
                          <Trash2 size={13} />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {msg && <div style={{ fontSize: 12, color: 'var(--accent)', padding: '0 20px 12px' }}>{msg}</div>}
    </div>
  );
}

function PlatformSection() {
  const [info, setInfo] = useState(null);

  useEffect(() => {
    getPlatformInfo().then(setInfo).catch(console.error);
  }, []);

  if (!info) return null;

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Info size={16} /> Platform
        </div>
      </div>
      <div style={{ padding: '0 20px 20px' }}>
        <div className="settings-row">
          <label>Application</label>
          <span style={{ color: 'var(--text-secondary)' }}>{info.app_name}</span>
        </div>
        <div className="settings-row">
          <label>Version</label>
          <span className="mono" style={{ color: 'var(--text-secondary)' }}>{info.app_version}</span>
        </div>
        <div className="settings-row">
          <label>Threat intel feeds</label>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {info.threat_feeds.map(f => (
              <span key={f} className="badge">{f}</span>
            ))}
          </div>
        </div>
        <div className="settings-row">
          <label>Scan capabilities</label>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {info.scan_features.map(f => (
              <span key={f} className="badge">{f}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function Settings() {
  return (
    <div className="page-body">
      <div className="page-header">
        <div>
          <div className="page-title">Settings</div>
          <div className="page-subtitle">Manage your account, users, and platform configuration</div>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 1100 }}>
        <ProfileSection />
        <PasswordSection />
        <UserManagement />
        <PlatformSection />
      </div>
    </div>
  );
}
