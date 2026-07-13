export const TERMINAL_SCAN_STATES = new Set(['succeeded', 'partial', 'failed', 'cancelled']);

export function humanize(value = '') {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function formatDate(value) {
  if (!value) return 'Not yet';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date);
}

export function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return '—';
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  return `${seconds.toFixed(1)} s`;
}

export function enabledAdapters(capabilities) {
  const adapters = capabilities?.adapters || capabilities?.capabilities || [];
  return adapters.filter((adapter) => adapter.enabled ?? adapter.available);
}

export function dependencyEntries(capabilities) {
  return Object.entries(capabilities?.dependencies || capabilities?.health || {});
}
