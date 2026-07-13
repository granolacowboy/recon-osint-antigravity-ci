import { Fingerprint } from 'lucide-react';

import { formatDate, humanize } from '../utils/display';

export default function NodeDetails({ node, provenance = [] }) {
  if (!node) {
    return (
      <section className="node-details" aria-label="Finding details">
        <Fingerprint aria-hidden="true" />
        <strong>Select a finding</strong>
        <p>Choose a graph node or table value to inspect metadata and provenance.</p>
      </section>
    );
  }
  const observations = provenance.filter((record) => record.node_id === node.id);
  return (
    <section className="node-details" aria-labelledby="node-details-title">
      <div>
        <span className={`entity-type entity-type--${node.entity_type}`}>{humanize(node.entity_type)}</span>
        <h3 id="node-details-title">{node.value}</h3>
        <span className="mono-label">{node.id}</span>
      </div>
      {Object.keys(node.metadata || {}).length > 0 ? (
        <dl className="metadata-list">
          {Object.entries(node.metadata).map(([key, value]) => (
            <div key={key}><dt>{humanize(key)}</dt><dd>{String(value)}</dd></div>
          ))}
        </dl>
      ) : null}
      <div className="provenance-block">
        <h4>Provenance</h4>
        {observations.length === 0 ? <p>No provenance was returned for this finding.</p> : observations.map((record) => (
          <article className="provenance-record" key={record.id}>
            <div><strong>{humanize(record.source_adapter_id)}</strong><span>{Math.round(record.confidence * 100)}% confidence</span></div>
            <dl>
              <div><dt>Observed</dt><dd>{formatDate(record.observed_at)}</dd></div>
              <div><dt>Adapter version</dt><dd>{record.adapter_version}</dd></div>
              <div><dt>Source</dt><dd>{record.source_target?.target_type}: {record.source_target?.target_value}</dd></div>
            </dl>
          </article>
        ))}
      </div>
    </section>
  );
}
