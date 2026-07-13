import { useEffect, useMemo, useRef, useState } from 'react';
import { SlidersHorizontal, X } from 'lucide-react';

import GraphViewer from './GraphViewer';
import { humanize } from '../utils/display';

const MOBILE_FILTER_QUERY = '(max-width: 767px)';

export default function GraphWorkspace({ nodes = [], edges = [], onSelect }) {
  const entityTypes = useMemo(() => [...new Set(nodes.map((node) => node.entity_type))].sort(), [nodes]);
  const [hiddenTypes, setHiddenTypes] = useState(() => new Set());
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [mobileFilters, setMobileFilters] = useState(() => (
    typeof window !== 'undefined' && window.matchMedia?.(MOBILE_FILTER_QUERY).matches === true
  ));
  const filterToggleRef = useRef(null);
  const filterPanelRef = useRef(null);
  const closeFiltersRef = useRef(null);
  const filtered = useMemo(() => {
    const visibleNodes = nodes.filter((node) => !hiddenTypes.has(node.entity_type));
    const visibleIds = new Set(visibleNodes.map((node) => node.id));
    return {
      nodes: visibleNodes,
      edges: edges.filter((edge) => visibleIds.has(edge.source_node_id) && visibleIds.has(edge.target_node_id)),
    };
  }, [edges, hiddenTypes, nodes]);

  useEffect(() => {
    const media = window.matchMedia?.(MOBILE_FILTER_QUERY);
    if (!media) return undefined;
    const update = (event) => setMobileFilters(event.matches);
    setMobileFilters(media.matches);
    media.addEventListener?.('change', update);
    return () => media.removeEventListener?.('change', update);
  }, []);

  useEffect(() => {
    if (!filtersOpen) return undefined;
    closeFiltersRef.current?.focus();
    const onKeyDown = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        setFiltersOpen(false);
        requestAnimationFrame(() => filterToggleRef.current?.focus());
        return;
      }
      if (event.key !== 'Tab' || !mobileFilters) return;
      const focusable = [...(filterPanelRef.current?.querySelectorAll(
        'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [href]',
      ) || [])].filter((element) => element.getAttribute('aria-hidden') !== 'true');
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [filtersOpen, mobileFilters]);

  function closeFilters() {
    setFiltersOpen(false);
    requestAnimationFrame(() => filterToggleRef.current?.focus());
  }

  function toggleType(type) {
    setHiddenTypes((current) => {
      const next = new Set(current);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }

  return (
    <div className="graph-workspace">
      <button
        aria-expanded={filtersOpen}
        aria-controls="graph-filters"
        className="button button--secondary filter-toggle"
        onClick={() => setFiltersOpen((current) => !current)}
        ref={filterToggleRef}
        type="button"
      >
        <SlidersHorizontal aria-hidden="true" size={16} /> Filters
      </button>
      {filtersOpen ? <button aria-label="Close filters" className="drawer-scrim" onClick={closeFilters} type="button" /> : null}
      <aside
        aria-hidden={mobileFilters && !filtersOpen ? 'true' : undefined}
        className={`graph-filters${filtersOpen ? ' graph-filters--open' : ''}`}
        id="graph-filters"
        inert={mobileFilters && !filtersOpen}
        ref={filterPanelRef}
      >
        <div className="graph-filters__heading"><h3>Node filters</h3><button aria-label="Close filters" onClick={closeFilters} ref={closeFiltersRef} type="button"><X aria-hidden="true" /></button></div>
        <fieldset>
          <legend className="sr-only">Visible entity types</legend>
          {entityTypes.map((type) => (
            <label key={type}>
              <input checked={!hiddenTypes.has(type)} onChange={() => toggleType(type)} type="checkbox" />
              <span className={`entity-type entity-type--${type}`}>{humanize(type)}</span>
            </label>
          ))}
        </fieldset>
      </aside>
      <div className="graph-canvas">
        <GraphViewer edges={filtered.edges} nodes={filtered.nodes} onSelect={onSelect} />
      </div>
    </div>
  );
}
