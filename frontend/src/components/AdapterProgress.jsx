import { CircleCheck, CircleDashed, CircleMinus, CircleX, TimerReset } from 'lucide-react';

import { formatDuration, humanize } from '../utils/display';
import StatusBadge from './StatusBadge';

const STATE_ICONS = {
  succeeded: CircleCheck,
  no_results: CircleMinus,
  unavailable: CircleMinus,
  retryable_failure: TimerReset,
  failed: CircleX,
};

export default function AdapterProgress({
  runs = [],
  selectedAdapters = [],
  scanState,
  outcomeCode,
}) {
  const items = outcomeCode === 'no_adapters_available'
    ? []
    : runs.length > 0
      ? runs
      : selectedAdapters.map((id) => ({ adapter_id: id, state: 'queued', finding_count: 0 }));

  return (
    <section className="adapter-progress" aria-labelledby="adapter-progress-title">
      <div className="section-heading-row">
        <div><h2 id="adapter-progress-title">Adapter progress</h2><p>{runs.length} outcome {runs.length === 1 ? 'record' : 'records'}</p></div>
      </div>
      {items.length === 0 ? (
        <p className="muted-copy">
          {outcomeCode === 'no_adapters_available'
            ? 'No enabled adapter was available for these targets.'
            : ['succeeded', 'partial', 'failed', 'cancelled'].includes(scanState)
              ? 'No adapter outcome records were produced.'
              : 'Adapter jobs have not started yet.'}
        </p>
      ) : (
        <ul className="adapter-run-list">
          {items.map((run, index) => {
            const Icon = STATE_ICONS[run.state] || CircleDashed;
            const sourceTarget = run.source_target;
            return (
              <li key={run.id || `${run.adapter_id}-${sourceTarget?.target_type || 'pending'}-${sourceTarget?.target_value || index}`}>
                <span className={`adapter-icon adapter-icon--${run.state}`}><Icon aria-hidden="true" /></span>
                <span className="adapter-run-main">
                  <strong>{run.name || humanize(run.adapter_id)}</strong>
                  <span>{run.finding_count || 0} {run.finding_count === 1 ? 'finding' : 'findings'} · {formatDuration(run.latency_seconds)}</span>
                  {sourceTarget ? (
                    <span>Target: {humanize(sourceTarget.target_type)} · {sourceTarget.target_value}</span>
                  ) : null}
                  {run.outcome_code ? <span>Outcome: {humanize(run.outcome_code)}</span> : null}
                </span>
                <StatusBadge state={run.state} />
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
