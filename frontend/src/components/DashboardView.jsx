import { useMemo } from 'react';
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';

import { humanize } from '../utils/display';

const COLORS = ['#818cf8', '#34d399', '#fbbf24', '#fb7185', '#22d3ee', '#c084fc', '#60a5fa'];

export default function DashboardView({ graphData }) {
  const stats = useMemo(() => {
    const counts = new Map();
    for (const node of graphData.nodes || []) counts.set(node.entity_type, (counts.get(node.entity_type) || 0) + 1);
    return [...counts].map(([name, value]) => ({ name, value }));
  }, [graphData.nodes]);

  return (
    <div className="dashboard-grid">
      <section className="dashboard-card" aria-labelledby="entity-distribution-title">
        <h3 id="entity-distribution-title">Entity distribution</h3>
        <div aria-hidden="true" className="chart-container">
          <ResponsiveContainer height="100%" width="100%">
            <PieChart>
              <Pie data={stats} dataKey="value" innerRadius={62} nameKey="name" outerRadius={100}>
                {stats.map((entry, index) => <Cell fill={COLORS[index % COLORS.length]} key={entry.name} />)}
              </Pie>
              <Tooltip formatter={(value, name) => [value, humanize(name)]} />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <ul className="chart-legend">
          {stats.map((entry, index) => <li key={entry.name}><span style={{ background: COLORS[index % COLORS.length] }} />{humanize(entry.name)} <strong>{entry.value}</strong></li>)}
        </ul>
      </section>
      <section className="dashboard-card">
        <h3>Collection totals</h3>
        <dl className="totals-list"><div><dt>Entities</dt><dd>{graphData.nodes?.length || 0}</dd></div><div><dt>Relationships</dt><dd>{graphData.edges?.length || 0}</dd></div></dl>
      </section>
    </div>
  );
}
