import { useMemo, useState } from 'react';
import { ArrowDown, ArrowUp, ChevronsUpDown } from 'lucide-react';

import { humanize } from '../utils/display';

function SortIcon({ direction }) {
  if (direction === 'ascending') return <ArrowUp aria-hidden="true" size={14} />;
  if (direction === 'descending') return <ArrowDown aria-hidden="true" size={14} />;
  return <ChevronsUpDown aria-hidden="true" size={14} />;
}

export default function RelationshipTable({ nodes = [], edges = [], onSelect }) {
  const [sort, setSort] = useState({ key: 'source', direction: 'none' });
  const rows = useMemo(() => {
    const byId = new Map(nodes.map((node) => [node.id, node]));
    return edges.map((edge) => ({
      ...edge,
      sourceNode: byId.get(edge.source_node_id),
      targetNode: byId.get(edge.target_node_id),
      source: byId.get(edge.source_node_id)?.value || edge.source_node_id,
      target: byId.get(edge.target_node_id)?.value || edge.target_node_id,
    }));
  }, [edges, nodes]);
  const sorted = useMemo(() => {
    if (sort.direction === 'none') return rows;
    const multiplier = sort.direction === 'ascending' ? 1 : -1;
    return [...rows].sort((left, right) => String(left[sort.key] || '').localeCompare(String(right[sort.key] || '')) * multiplier);
  }, [rows, sort]);

  function toggle(key) {
    setSort((current) => ({
      key,
      direction: current.key !== key || current.direction === 'none'
        ? 'ascending'
        : current.direction === 'ascending' ? 'descending' : 'none',
    }));
  }

  const header = (key, label) => (
    <th aria-sort={sort.key === key ? sort.direction : 'none'} scope="col">
      <button aria-label={`Sort by ${label}`} className="sort-button" onClick={() => toggle(key)} type="button">
        {label}<SortIcon direction={sort.key === key ? sort.direction : 'none'} />
      </button>
    </th>
  );

  return (
    <div aria-label="Relationships" className="table-scroll" role="region" tabIndex="0">
      <table className="data-table relationship-table">
        <caption className="sr-only">Keyboard-accessible relationships equivalent to the visual graph</caption>
        <thead><tr>{header('source', 'source')}{header('relationship', 'relationship')}{header('target', 'target')}</tr></thead>
        <tbody>
          {sorted.map((row) => (
            <tr key={row.id}>
              <td>{row.sourceNode && onSelect ? <button className="table-link" onClick={() => onSelect(row.sourceNode)} type="button">{row.source}</button> : row.source}</td>
              <td>{humanize(row.relationship).toLowerCase()}</td>
              <td>{row.targetNode && onSelect ? <button className="table-link" onClick={() => onSelect(row.targetNode)} type="button">{row.target}</button> : row.target}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
