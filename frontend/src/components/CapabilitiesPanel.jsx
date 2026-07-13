import { CheckCircle2, CircleAlert, ServerCog } from 'lucide-react';

import { dependencyEntries, enabledAdapters, humanize } from '../utils/display';

export default function CapabilitiesPanel({ capabilities, compact = false }) {
  const adapters = capabilities?.adapters || capabilities?.capabilities || [];
  const enabled = enabledAdapters(capabilities);
  const dependencies = dependencyEntries(capabilities);

  return (
    <section className={`capabilities${compact ? ' capabilities--compact' : ''}`} aria-labelledby="capabilities-title">
      <div className="section-heading-row">
        <div>
          <h2 id="capabilities-title">Collection readiness</h2>
          <p>{enabled.length} of {adapters.length} adapters available</p>
        </div>
        <ServerCog aria-hidden="true" />
      </div>
      {dependencies.length > 0 ? (
        <ul className="dependency-list" aria-label="Dependency health">
          {dependencies.map(([name, health]) => {
            const healthy = typeof health === 'boolean' ? health : health?.healthy ?? health?.status === 'healthy';
            return (
              <li key={name} className={healthy ? 'health-ok' : 'health-error'}>
                {healthy ? <CheckCircle2 aria-hidden="true" /> : <CircleAlert aria-hidden="true" />}
                <span>{humanize(name)}</span>
                <strong>{healthy ? 'Ready' : 'Unavailable'}</strong>
              </li>
            );
          })}
        </ul>
      ) : null}
      {!compact && adapters.some((adapter) => !(adapter.enabled ?? adapter.available)) ? (
        <details className="capability-details">
          <summary>Unavailable adapters</summary>
          <ul>
            {adapters.filter((adapter) => !(adapter.enabled ?? adapter.available)).map((adapter) => (
              <li key={adapter.id}>
                <strong>{adapter.name || humanize(adapter.id)}</strong>
                <span>{adapter.reason || adapter.availability_reason || 'This adapter did not pass its capability check.'}</span>
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </section>
  );
}
