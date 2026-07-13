import { useMemo, useState } from 'react';
import { ArrowDown, ArrowUp, ChevronsUpDown } from 'lucide-react';

import { humanize } from '../utils/display';

function SortIcon({ direction }) {
  if (direction === 'ascending') return <ArrowUp aria-hidden="true" size={14} />;
  if (direction === 'descending') return <ArrowDown aria-hidden="true" size={14} />;
  return <ChevronsUpDown aria-hidden="true" size={14} />;
}

export default function EntityTable({ nodes = [], onSelect }) {
  const [sort, setSort] = useState({ key: 'entity_type', direction: 'none' });
  const sorted = useMemo(() => {
    if (sort.direction === 'none') return nodes;
    const multiplier = sort.direction === 'ascending' ? 1 : -1;
    return [...nodes].sort((left, right) => String(left[sort.key] || '').localeCompare(String(right[sort.key] || '')) * multiplier);
  }, [nodes, sort]);

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
    <div aria-label="Canonical entities" className="table-scroll" role="region" tabIndex="0">
      <table className="data-table">
        <caption className="sr-only">Canonical entities found in this scan</caption>
        <thead><tr>{header('entity_type', 'entity type')}{header('value', 'value')}<th scope="col">Node ID</th></tr></thead>
        <tbody>
          {sorted.map((node) => (
            <tr key={node.id}>
              <td><span className={`entity-type entity-type--${node.entity_type}`}>{humanize(node.entity_type)}</span></td>
              <td>{onSelect ? <button className="table-link" onClick={() => onSelect(node)} type="button">{node.value}</button> : node.value}</td>
              <td className="mono-label">{node.id}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
