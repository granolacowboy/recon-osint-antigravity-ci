import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ArrowLeft, Play, ShieldAlert } from 'lucide-react';
import { Link, useNavigate, useParams } from 'react-router-dom';

import { createIdempotencyKey, formatApiError } from '../api/client';
import { useApi } from '../api/useApi';
import CapabilitiesPanel from '../components/CapabilitiesPanel';
import { EmptyState, ErrorState, LoadingState } from '../components/Feedback';
import StatusBadge from '../components/StatusBadge';
import { enabledAdapters, formatDate, humanize } from '../utils/display';

const TARGET_TYPES = ['username', 'email', 'domain', 'ip', 'url', 'phone', 'company'];
const SCAN_PAGE_SIZE = 50;

function parseTargets(value) {
  return [...new Set(value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean))];
}

export default function CaseDetailPage() {
  const { caseId } = useParams();
  const navigate = useNavigate();
  const api = useApi();
  const [caseRecord, setCaseRecord] = useState(null);
  const [scans, setScans] = useState([]);
  const [capabilities, setCapabilities] = useState(null);
  const [targetType, setTargetType] = useState('username');
  const [mode, setMode] = useState('passive');
  const [confirmed, setConfirmed] = useState(false);
  const [selectedAdapters, setSelectedAdapters] = useState([]);
  const [loading, setLoading] = useState(true);
  const [capabilityLoading, setCapabilityLoading] = useState(true);
  const [error, setError] = useState('');
  const [capabilityError, setCapabilityError] = useState('');
  const [historyError, setHistoryError] = useState('');
  const [loadMoreHistoryError, setLoadMoreHistoryError] = useState('');
  const [loadingMoreScans, setLoadingMoreScans] = useState(false);
  const [hasMoreScans, setHasMoreScans] = useState(false);
  const [formError, setFormError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const submissionRef = useRef(null);

  const applyCapabilities = useCallback((record) => {
    setCapabilities(record);
    setCapabilityError('');
    const adapters = enabledAdapters(record);
    const firstSupportedType = TARGET_TYPES.find((type) => adapters.some((adapter) => adapter.target_types?.includes(type)));
    if (firstSupportedType) setTargetType(firstSupportedType);
  }, []);

  const retryCapabilities = useCallback(async () => {
    setCapabilityLoading(true);
    setCapabilities(null);
    setCapabilityError('');
    try {
      applyCapabilities(await api.getCapabilities());
    } catch (loadError) {
      setCapabilities(null);
      setCapabilityError(formatApiError(loadError, 'collection readiness'));
    } finally {
      setCapabilityLoading(false);
    }
  }, [api, applyCapabilities]);

  const retryHistory = useCallback(async () => {
    setHistoryError('');
    setLoadMoreHistoryError('');
    try {
      const page = await api.listCaseScans(caseId, { offset: 0, limit: SCAN_PAGE_SIZE });
      setScans(page);
      setHasMoreScans(page.length === SCAN_PAGE_SIZE);
    } catch (loadError) {
      setHasMoreScans(false);
      setHistoryError(formatApiError(loadError, 'scan history'));
    }
  }, [api, caseId]);

  const loadMoreScans = useCallback(async () => {
    if (loadingMoreScans || !hasMoreScans) return;
    setLoadingMoreScans(true);
    setLoadMoreHistoryError('');
    try {
      const page = await api.listCaseScans(caseId, {
        offset: scans.length,
        limit: SCAN_PAGE_SIZE,
      });
      setScans((current) => {
        const known = new Set(current.map((scan) => scan.id));
        return [...current, ...page.filter((scan) => !known.has(scan.id))];
      });
      setHasMoreScans(page.length === SCAN_PAGE_SIZE);
    } catch (loadError) {
      setLoadMoreHistoryError(formatApiError(loadError, 'additional scan history'));
    } finally {
      setLoadingMoreScans(false);
    }
  }, [api, caseId, hasMoreScans, loadingMoreScans, scans.length]);

  useEffect(() => {
    let ignore = false;
    async function load() {
      try {
        const [caseResult, capabilityResult, historyResult] = await Promise.allSettled([
          api.getCase(caseId),
          api.getCapabilities(),
          api.listCaseScans(caseId, { offset: 0, limit: SCAN_PAGE_SIZE }),
        ]);
        if (ignore) return;
        if (caseResult.status === 'rejected') throw caseResult.reason;
        setCaseRecord(caseResult.value);
        if (capabilityResult.status === 'rejected') {
          setCapabilities(null);
          setCapabilityError(formatApiError(capabilityResult.reason, 'collection readiness'));
        } else {
          applyCapabilities(capabilityResult.value);
        }
        setCapabilityLoading(false);
        if (historyResult.status === 'fulfilled') {
          setScans(historyResult.value);
          setHasMoreScans(historyResult.value.length === SCAN_PAGE_SIZE);
          setHistoryError('');
        } else {
          setHasMoreScans(false);
          setHistoryError(formatApiError(historyResult.reason, 'scan history'));
        }
      } catch (loadError) {
        if (!ignore) setError(formatApiError(loadError, 'case'));
      } finally {
        if (!ignore) setLoading(false);
      }
    }
    void load();
    return () => {
      ignore = true;
    };
  }, [api, applyCapabilities, caseId]);

  const compatibleAdapters = useMemo(
    () => enabledAdapters(capabilities).filter((adapter) => !adapter.target_types?.length || adapter.target_types.includes(targetType)),
    [capabilities, targetType],
  );
  const activePolicyEnabled = capabilities?.policy?.active_scanning_enabled === true;
  const activeScanningAuthorized = capabilities?.policy?.active_scanning_authorized === true;
  const activeScopeConfigured = capabilities?.policy?.active_scope_configured === true;
  const activeScanningEnabled = activePolicyEnabled
    && activeScanningAuthorized
    && activeScopeConfigured;
  const activeUnavailableReason = !activePolicyEnabled
    ? 'Active collection is disabled by deployment policy.'
    : !activeScanningAuthorized
      ? 'Active collection requires an administrator role.'
      : !activeScopeConfigured
        ? 'Active collection requires an approved target scope in deployment configuration.'
        : '';

  useEffect(() => {
    setSelectedAdapters(compatibleAdapters.map((adapter) => adapter.id));
  }, [compatibleAdapters]);

  useEffect(() => {
    if (!activeScanningEnabled && mode === 'active') {
      setMode('passive');
      setConfirmed(false);
    }
  }, [activeScanningEnabled, mode]);

  async function submitScan(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const values = parseTargets(form.get('targets') || '');
    if (values.length === 0) {
      setFormError('Enter at least one target.');
      return;
    }
    if (capabilityError) {
      setFormError('Collection dependencies are unavailable. Restore readiness before queueing a scan.');
      return;
    }
    if (compatibleAdapters.length === 0 || selectedAdapters.length === 0) {
      setFormError(`No available adapter supports ${humanize(targetType).toLowerCase()} targets.`);
      return;
    }
    if (mode === 'active' && !confirmed) {
      setFormError('Confirm authorization and scope before queueing an active scan.');
      return;
    }
    setSubmitting(true);
    setFormError('');
    try {
      const payload = {
        targets: values.map((target_value) => ({ target_type: targetType, target_value })),
        mode,
        adapter_ids: selectedAdapters,
        active_scan_confirmed: mode === 'active' && confirmed,
      };
      const fingerprint = JSON.stringify(payload);
      if (submissionRef.current?.fingerprint !== fingerprint) {
        submissionRef.current = { fingerprint, idempotencyKey: createIdempotencyKey() };
      }
      const scan = await api.createScan(caseId, payload, {
        idempotencyKey: submissionRef.current.idempotencyKey,
      });
      submissionRef.current = null;
      navigate(`/scans/${scan.id}`, { state: { initialScan: scan, caseRecord } });
    } catch (submitError) {
      setFormError(formatApiError(submitError, 'scan'));
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) return <div className="page-shell"><LoadingState label="Loading case…" /></div>;
  if (error) return <div className="page-shell"><ErrorState message={error} title="Case unavailable" /></div>;

  return (
    <div className="page-shell">
      <Link className="back-link" to="/cases"><ArrowLeft aria-hidden="true" size={16} /> Case history</Link>
      <section className="page-intro page-intro--compact">
        <div>
          <h1>{caseRecord.name}</h1>
          <p>{caseRecord.description || 'No case description provided.'}</p>
        </div>
        <span className="mono-label">{caseRecord.id}</span>
      </section>

      <div className="scan-compose-grid">
        <section className="panel" aria-labelledby="new-scan-title">
          <div className="section-heading-row">
            <div>
              <h2 id="new-scan-title">New scoped scan</h2>
              <p>Passive collection is the safe default.</p>
            </div>
            <Play aria-hidden="true" />
          </div>
          <form className="stacked-form" onSubmit={submitScan}>
            <div className="form-row">
              <div>
                <label htmlFor="target-type">Target type</label>
                <select id="target-type" value={targetType} onChange={(event) => setTargetType(event.target.value)}>
                  {TARGET_TYPES.map((type) => <option key={type} value={type}>{humanize(type)}</option>)}
                </select>
              </div>
              <div>
                <label htmlFor="scan-mode">Collection mode</label>
                <select id="scan-mode" value={mode} onChange={(event) => setMode(event.target.value)}>
                  <option value="passive">Passive</option>
                  <option disabled={!activeScanningEnabled} value="active">Active — authorized only</option>
                </select>
              </div>
            </div>
            {!activeScanningEnabled ? (
              <p className="field-hint">{activeUnavailableReason}</p>
            ) : null}
            <label htmlFor="scan-targets">Targets</label>
            <textarea
              aria-describedby="target-hint"
              id="scan-targets"
              name="targets"
              placeholder="One target per line"
              required
              rows="5"
            />
            <p className="field-hint" id="target-hint">Separate multiple targets with a new line or comma.</p>

            <fieldset className="adapter-picker">
              <legend>Adapters</legend>
              {compatibleAdapters.length > 0 ? compatibleAdapters.map((adapter) => (
                <label key={adapter.id}>
                  <input
                    checked={selectedAdapters.includes(adapter.id)}
                    onChange={(event) => setSelectedAdapters((current) => event.target.checked
                      ? [...current, adapter.id]
                      : current.filter((id) => id !== adapter.id))}
                    type="checkbox"
                  />
                  <span><strong>{adapter.name || humanize(adapter.id)}</strong><small>{adapter.description || 'Capability check passed'}</small></span>
                </label>
              )) : <p className="form-warning">No enabled adapter supports this target type.</p>}
            </fieldset>

            {mode === 'active' ? (
              <label className="consent-check">
                <input checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} type="checkbox" />
                <ShieldAlert aria-hidden="true" />
                <span>I confirm this active scan is authorized and targets are within the approved scope.</span>
              </label>
            ) : null}

            {formError ? <p className="form-error" role="alert">{formError}</p> : null}
            <button className="button button--primary" disabled={submitting || compatibleAdapters.length === 0 || Boolean(capabilityError)} type="submit">
              <Play aria-hidden="true" size={17} />
              {submitting ? 'Queueing…' : `Queue ${mode} scan`}
            </button>
          </form>
        </section>
        <div className="capability-column">
          {capabilityError ? <ErrorState message={capabilityError} onRetry={retryCapabilities} title="Collection is not ready" /> : null}
          {!capabilityError && capabilities ? <CapabilitiesPanel capabilities={capabilities} /> : null}
          {!capabilityError && capabilityLoading ? (
            <section className="panel"><LoadingState label="Checking collection readiness…" /></section>
          ) : null}
        </div>
      </div>

      <section className="case-history" aria-labelledby="case-scan-history-title">
        <div className="section-heading-row">
          <div>
            <h2 id="case-scan-history-title">Scan history</h2>
            <p>Durable scans for this case, newest first.</p>
          </div>
          <span className="count-pill">{scans.length}</span>
        </div>
        {historyError ? (
          <ErrorState message={historyError} onRetry={retryHistory} title="Scan history unavailable" />
        ) : scans.length === 0 ? (
          <EmptyState message="Queue the first truthful collection run for this case." title="No scans yet" />
        ) : (
          <div className="scan-history-list" id="scan-history-list">
            {scans.map((scan) => (
              <Link className="scan-history-row" key={scan.id} to={`/scans/${scan.id}`}>
                <span>
                  <strong>{scan.targets?.map((target) => target.target_value).join(', ') || scan.id}</strong>
                  <small>{humanize(scan.mode)} · {formatDate(scan.created_at)}</small>
                </span>
                <StatusBadge state={scan.state} />
              </Link>
            ))}
          </div>
        )}
        {!historyError && scans.length > 0 && loadMoreHistoryError ? (
          <ErrorState
            message={loadMoreHistoryError}
            onRetry={loadMoreScans}
            title="More scans could not be loaded"
          />
        ) : null}
        {!historyError && scans.length > 0 && hasMoreScans && !loadMoreHistoryError ? (
          <button
            aria-controls="scan-history-list"
            className="button button--secondary load-more"
            disabled={loadingMoreScans}
            onClick={loadMoreScans}
            type="button"
          >
            {loadingMoreScans ? 'Loading more scans...' : 'Load more scans'}
          </button>
        ) : null}
      </section>
    </div>
  );
}
