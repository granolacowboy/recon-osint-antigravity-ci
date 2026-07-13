import { lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react';
import { ArrowLeft, Ban, BarChart3, Network, RotateCcw, Table2 } from 'lucide-react';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';

import { createIdempotencyKey, formatApiError } from '../api/client';
import { useApi } from '../api/useApi';
import AdapterProgress from '../components/AdapterProgress';
import EntityTable from '../components/EntityTable';
import { EmptyState, ErrorState, LoadingState } from '../components/Feedback';
import NodeDetails from '../components/NodeDetails';
import RelationshipTable from '../components/RelationshipTable';
import StatusBadge from '../components/StatusBadge';
import { formatDate, humanize, TERMINAL_SCAN_STATES } from '../utils/display';

const GraphWorkspace = lazy(() => import('../components/GraphWorkspace'));
const DashboardView = lazy(() => import('../components/DashboardView'));

const TABS = [
  { id: 'relationships', label: 'Relationships', icon: Table2 },
  { id: 'graph', label: 'Graph', icon: Network },
  { id: 'entities', label: 'Entities', icon: Table2 },
  { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
];

export default function ScanDetailPage() {
  const { scanId } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const api = useApi();
  const [scan, setScan] = useState(location.state?.initialScan || null);
  const [graph, setGraph] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [activeTab, setActiveTab] = useState('relationships');
  const [scanError, setScanError] = useState('');
  const [graphError, setGraphError] = useState('');
  const [actionError, setActionError] = useState('');
  const [loading, setLoading] = useState(!location.state?.initialScan);
  const [graphLoading, setGraphLoading] = useState(true);
  const [connectionState, setConnectionState] = useState('Connecting to live progress…');
  const [actionPending, setActionPending] = useState(false);
  const [activeRetryConfirmed, setActiveRetryConfirmed] = useState(false);
  const tabRefs = useRef([]);
  const retrySubmissionRef = useRef(null);
  const scanRequestVersion = useRef(0);
  const graphRequestVersion = useRef(0);
  const scanState = scan?.state;

  function handleTabKeyDown(event, currentIndex) {
    let nextIndex = currentIndex;
    if (event.key === 'ArrowRight') nextIndex = (currentIndex + 1) % TABS.length;
    else if (event.key === 'ArrowLeft') nextIndex = (currentIndex - 1 + TABS.length) % TABS.length;
    else if (event.key === 'Home') nextIndex = 0;
    else if (event.key === 'End') nextIndex = TABS.length - 1;
    else return;
    event.preventDefault();
    setActiveTab(TABS[nextIndex].id);
    tabRefs.current[nextIndex]?.focus();
  }

  const refreshScan = useCallback(async () => {
    const requestVersion = ++scanRequestVersion.current;
    try {
      const record = await api.getScan(scanId);
      if (requestVersion === scanRequestVersion.current) {
        setScan((current) => ({
          ...record,
          cancellation_requested: Boolean(
            record?.cancellation_requested || current?.cancellation_requested,
          ),
        }));
        setScanError('');
      }
      return record;
    } catch (error) {
      if (requestVersion === scanRequestVersion.current) {
        setScanError(formatApiError(error, 'scan'));
      }
      return null;
    } finally {
      if (requestVersion === scanRequestVersion.current) setLoading(false);
    }
  }, [api, scanId]);

  const refreshGraph = useCallback(async () => {
    const requestVersion = ++graphRequestVersion.current;
    setGraphLoading(true);
    try {
      const page = await api.getGraph(scanId, { limit: 100 });
      if (requestVersion === graphRequestVersion.current) {
        setGraph(page);
        setGraphError('');
      }
    } catch (error) {
      if (requestVersion === graphRequestVersion.current) {
        setGraph(null);
        setGraphError(formatApiError(error, 'graph'));
      }
    } finally {
      if (requestVersion === graphRequestVersion.current) setGraphLoading(false);
    }
  }, [api, scanId]);

  async function loadMoreGraph() {
    if (!graph?.next_cursor) return;
    graphRequestVersion.current += 1;
    setGraphLoading(true);
    try {
      const page = await api.getGraph(scanId, { cursor: graph.next_cursor, limit: 100 });
      setGraph((current) => ({
        nodes: mergeById(current.nodes, page.nodes),
        edges: mergeById(current.edges || current.links || [], page.edges || page.links || []),
        provenance: mergeById(current.provenance || [], page.provenance || []),
        next_cursor: page.next_cursor,
      }));
      setGraphError('');
    } catch (error) {
      setGraphError(formatApiError(error, 'graph'));
    } finally {
      setGraphLoading(false);
    }
  }

  useEffect(() => {
    void refreshScan();
    void refreshGraph();
  }, [refreshGraph, refreshScan]);

  useEffect(() => {
    if (!scanState || TERMINAL_SCAN_STATES.has(scanState)) {
      if (scanState) setConnectionState(`Scan ${humanize(scanState).toLowerCase()}.`);
      return undefined;
    }
    const unsubscribe = api.subscribeScanEvents(scanId, {
      onOpen: () => setConnectionState('Live progress connected.'),
      onEvent: () => {
        setConnectionState('Progress received.');
        void refreshScan();
        void refreshGraph();
      },
      onError: () => setConnectionState('Live updates reconnecting; durable status polling remains active.'),
    });
    const poll = window.setInterval(() => {
      void Promise.allSettled([refreshScan(), refreshGraph()]);
    }, 5000);
    return () => {
      window.clearInterval(poll);
      unsubscribe?.();
    };
  }, [api, refreshGraph, refreshScan, scanId, scanState]);

  async function cancelScan() {
    setActionPending(true);
    setActionError('');
    try {
      const cancellation = await api.cancelScan(scanId);
      setScan((current) => ({
        ...current,
        ...cancellation,
        adapter_runs: cancellation?.adapter_runs ?? current?.adapter_runs ?? [],
      }));
      await Promise.allSettled([refreshScan(), refreshGraph()]);
    } catch (error) {
      setActionError(formatApiError(error, 'cancellation'));
    } finally {
      setActionPending(false);
    }
  }

  async function retryScan() {
    setActionPending(true);
    setActionError('');
    try {
      const payload = {
        targets: scan.targets,
        mode: scan.mode,
        adapter_ids: scan.adapter_ids || null,
        active_scan_confirmed: scan.mode === 'active' && activeRetryConfirmed,
      };
      const fingerprint = JSON.stringify(payload);
      if (retrySubmissionRef.current?.fingerprint !== fingerprint) {
        retrySubmissionRef.current = { fingerprint, idempotencyKey: createIdempotencyKey() };
      }
      const created = await api.createScan(scan.case_id, payload, {
        idempotencyKey: retrySubmissionRef.current.idempotencyKey,
      });
      retrySubmissionRef.current = null;
      navigate(`/scans/${created.id}`, { state: { initialScan: created } });
    } catch (error) {
      setActionError(formatApiError(error, 'retry'));
      setActionPending(false);
    }
  }

  if (loading && !scan) return <div className="page-shell"><LoadingState label="Loading scan…" /></div>;
  if (scanError && !scan) return <div className="page-shell"><ErrorState message={scanError} onRetry={refreshScan} title="Scan unavailable" /></div>;

  const isTerminal = TERMINAL_SCAN_STATES.has(scan.state);
  const cancellationPending = !isTerminal && scan.cancellation_requested === true;
  const nodes = graph?.nodes || [];
  const edges = graph?.edges || graph?.links || [];
  const provenance = graph?.provenance || [];
  const hasGraphData = nodes.length > 0 || edges.length > 0;

  return (
    <div className="page-shell scan-detail-page">
      <Link className="back-link" to={`/cases/${scan.case_id}`}><ArrowLeft aria-hidden="true" size={16} /> Case</Link>
      <section className="scan-header">
        <div>
          <div className="scan-title-row"><h1>Scan {scan.id}</h1><StatusBadge state={scan.state} /></div>
          <p>{scan.targets.length} {scan.targets.length === 1 ? 'target' : 'targets'} · {humanize(scan.mode)} collection</p>
        </div>
        <div className="scan-actions">
          {!isTerminal ? (
            <button
              className="button button--danger"
              disabled={actionPending || cancellationPending}
              onClick={cancelScan}
              type="button"
            >
              <Ban aria-hidden="true" size={16} />
              {cancellationPending ? 'Cancellation requested' : 'Cancel scan'}
            </button>
          ) : scan.state !== 'succeeded' ? (
            <>
              {scan.mode === 'active' ? (
                <label className="retry-consent">
                  <input
                    checked={activeRetryConfirmed}
                    onChange={(event) => setActiveRetryConfirmed(event.target.checked)}
                    type="checkbox"
                  />
                  <span>Confirm this active retry is authorized and in scope.</span>
                </label>
              ) : null}
              <button
                className="button button--secondary"
                disabled={actionPending || (scan.mode === 'active' && !activeRetryConfirmed)}
                onClick={retryScan}
                type="button"
              ><RotateCcw aria-hidden="true" size={16} /> Retry scan</button>
            </>
          ) : null}
        </div>
      </section>

      <div aria-atomic="true" aria-live="polite" className="scan-live-status" role="status">
        <span className={`live-dot${isTerminal ? ` live-dot--terminal live-dot--${scan.state}` : ''}`} aria-hidden="true" />
        {connectionState}
      </div>
      {scan.outcome_code ? (
        <p className="outcome-summary"><strong>Outcome:</strong> {humanize(scan.outcome_code)}</p>
      ) : null}
      {scanError ? <ErrorState message={scanError} onRetry={refreshScan} title="Status refresh failed" /> : null}
      {actionError ? <p className="form-error" role="alert">{actionError}</p> : null}

      <dl className="scan-metadata">
        <div><dt>Created</dt><dd>{formatDate(scan.created_at)}</dd></div>
        <div><dt>Started</dt><dd>{formatDate(scan.started_at)}</dd></div>
        <div><dt>Completed</dt><dd>{formatDate(scan.finished_at)}</dd></div>
        <div><dt>Queue job</dt><dd className="mono-label">{scan.job_id || 'Pending'}</dd></div>
      </dl>

      <AdapterProgress
        outcomeCode={scan.outcome_code}
        runs={scan.adapter_runs || []}
        scanState={scan.state}
        selectedAdapters={scan.adapter_ids || []}
      />

      <section className="findings-panel" aria-labelledby="findings-title">
        <div className="section-heading-row">
          <div><h2 id="findings-title">Findings</h2><p>{nodes.length} entities · {edges.length} relationships</p></div>
          <button className="button button--secondary button--compact" disabled={graphLoading} onClick={refreshGraph} type="button"><RotateCcw aria-hidden="true" size={14} /> Refresh</button>
        </div>
        <div className="tabs-list" role="tablist" aria-label="Finding views">
          {TABS.map(({ id, label, icon: Icon }, index) => (
            <button
              aria-controls={`panel-${id}`}
              aria-selected={activeTab === id}
              className="tab-button"
              id={`tab-${id}`}
              key={id}
              onClick={() => setActiveTab(id)}
              onKeyDown={(event) => handleTabKeyDown(event, index)}
              ref={(element) => { tabRefs.current[index] = element; }}
              role="tab"
              tabIndex={activeTab === id ? 0 : -1}
              type="button"
            >
              <Icon aria-hidden="true" size={16} /> {label}
            </button>
          ))}
        </div>

        <div aria-labelledby={`tab-${activeTab}`} className="finding-view" id={`panel-${activeTab}`} role="tabpanel" tabIndex="0">
          {graphLoading && !graph ? <LoadingState label="Loading scan findings…" /> : null}
          {!graphLoading && graphError ? <ErrorState message={graphError} onRetry={refreshGraph} title="Findings unavailable" /> : null}
          {!graphLoading && !graphError && !hasGraphData ? (
            <EmptyState
              title={scan.outcome_code === 'no_adapters_available'
                ? 'No collection capability available'
                : isTerminal ? 'No findings returned' : 'Waiting for findings'}
              message={scan.outcome_code === 'no_adapters_available'
                ? 'Configure an enabled adapter that supports this target type, then retry the scan.'
                : isTerminal ? 'The completed adapter runs produced no canonical entities for this scan.' : 'Findings will appear as adapter runs finish.'}
            />
          ) : null}
          {!graphError && hasGraphData ? (
            <div className="findings-layout">
              <div className="findings-primary">
                {activeTab === 'relationships' ? <RelationshipTable edges={edges} nodes={nodes} onSelect={setSelectedNode} /> : null}
                {activeTab === 'entities' ? <EntityTable nodes={nodes} onSelect={setSelectedNode} /> : null}
                {activeTab === 'graph' ? (
                  <Suspense fallback={<LoadingState label="Loading graph renderer…" />}>
                    <GraphWorkspace edges={edges} nodes={nodes} onSelect={setSelectedNode} />
                  </Suspense>
                ) : null}
                {activeTab === 'dashboard' ? (
                  <Suspense fallback={<LoadingState label="Loading dashboard…" />}>
                    <DashboardView graphData={{ nodes, edges }} loading={false} />
                  </Suspense>
                ) : null}
              </div>
              <NodeDetails node={selectedNode} provenance={provenance} />
            </div>
          ) : null}
          {!graphError && graph?.next_cursor ? (
            <button className="button button--secondary load-more" disabled={graphLoading} onClick={loadMoreGraph} type="button">
              {graphLoading ? 'Loading…' : 'Load more findings'}
            </button>
          ) : null}
        </div>
      </section>
    </div>
  );
}

function mergeById(existing = [], incoming = []) {
  const merged = new Map(existing.map((record) => [record.id, record]));
  for (const record of incoming) merged.set(record.id, record);
  return [...merged.values()];
}
