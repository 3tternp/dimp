import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Shield } from 'lucide-react';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(email, password);
      navigate('/');
    } catch {
      setError('Invalid email or password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-shell">
      <div className="login-card">
        <div className="login-brand">
          <div className="brand-icon" style={{ width: 44, height: 44, fontSize: 20 }}>D</div>
          <div>
            <div style={{ fontWeight: 600, fontSize: 18, letterSpacing: '-0.3px' }}>DIMP</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 1 }}>Domain Impersonation Monitor</div>
          </div>
        </div>

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div className="form-field">
            <label className="label">Email</label>
            <input className="input" type="email" autoFocus required
              value={email} onChange={e => setEmail(e.target.value)}
              placeholder="analyst@yourdomain.com" />
          </div>
          <div className="form-field">
            <label className="label">Password</label>
            <input className="input" type="password" required
              value={password} onChange={e => setPassword(e.target.value)}
              placeholder="••••••••" />
          </div>
          {error && (
            <div style={{ fontSize: 13, color: 'var(--red)', background: 'rgba(226,75,74,0.08)',
              padding: '8px 12px', borderRadius: 6, border: '1px solid rgba(226,75,74,0.2)' }}>
              {error}
            </div>
          )}
          <button className="btn btn-primary" type="submit" disabled={loading}
            style={{ marginTop: 4, padding: '10px 0', justifyContent: 'center' }}>
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <div style={{ marginTop: 20, fontSize: 12, color: 'var(--text-muted)', textAlign: 'center', lineHeight: 1.6 }}>
          First time? Run <code style={{ color: 'var(--amber)' }}>POST /api/v1/auth/register</code><br />
          to create the initial admin account.
        </div>
      </div>
    </div>
  );
}
