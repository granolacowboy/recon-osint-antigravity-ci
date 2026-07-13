import { humanize } from '../utils/display';

export default function StatusBadge({ state }) {
  const normalized = state || 'queued';
  return <span className={`status-badge status-badge--${normalized}`}>{humanize(normalized)}</span>;
}
