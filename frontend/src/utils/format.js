import { formatDistanceToNow, format } from 'date-fns';

export function severityColor(s) {
  return { critical: '#E24B4A', high: '#EF9F27', medium: '#378ADD', low: '#3DAA6A' }[s] || '#526180';
}

export function scoreColor(n) {
  if (n >= 81) return '#E24B4A';
  if (n >= 61) return '#EF9F27';
  if (n >= 31) return '#378ADD';
  return '#3DAA6A';
}

export function timeAgo(d) {
  if (!d) return '—';
  return formatDistanceToNow(new Date(d), { addSuffix: true });
}

export function fmtDate(d) {
  if (!d) return '—';
  return format(new Date(d), 'dd MMM yyyy');
}

export function fmtDateTime(d) {
  if (!d) return '—';
  return format(new Date(d), 'dd MMM yyyy HH:mm');
}

export function capitalize(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1).replace(/_/g, ' ') : '';
}

export function truncate(s, n = 40) {
  if (!s) return '—';
  return s.length > n ? s.slice(0, n) + '…' : s;
}
