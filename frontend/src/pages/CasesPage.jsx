import { useCallback, useEffect, useState } from 'react';
import { ArrowRight, BriefcaseBusiness, Plus } from 'lucide-react';
import { Link } from 'react-router-dom';

import { formatApiError } from '../api/client';
import { useApi } from '../api/useApi';
import CapabilitiesPanel from '../components/CapabilitiesPanel';
import { EmptyState, ErrorState, LoadingState } from '../components/Feedback';
import { formatDate } from '../utils/display';

const CASE_PAGE_SIZE = 50;

export default function CasesPage() {
  const api = useApi();
  const [cases, setCases] = useState([]);
  const [capabilities, setCapabilities] = useState(null);
  const [loading, setLoading] = useState(true);
  const [capabilityLoading, setCapabilityLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [loadMoreError, setLoadMoreError] = useState('');
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMoreCases, setHasMoreCases] = useState(false);
  const [capabilityError, setCapabilityError] = useState('');
  const [formError, setFormError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setCapabilityLoading(true);
    setCapabilities(null);
    setCapabilityError('');
    setLoadError('');
    setLoadMoreError('');
    const [caseResult, capabilityResult] = await Promise.allSettled([
      api.listCases({ offset: 0, limit: CASE_PAGE_SIZE }),
      api.getCapabilities(),
    ]);
    if (caseResult.status === 'fulfilled') {
      setCases(caseResult.value);
      setHasMoreCases(caseResult.value.length === CASE_PAGE_SIZE);
    } else {
      setHasMoreCases(false);
      setLoadError(formatApiError(caseResult.reason, 'case history'));
    }
    if (capabilityResult.status === 'fulfilled') {
      setCapabilities(capabilityResult.value);
      setCapabilityError('');
    } else {
      setCapabilities(null);
      setCapabilityError(formatApiError(capabilityResult.reason, 'collection readiness'));
    }
    setCapabilityLoading(false);
    setLoading(false);
  }, [api]);

  useEffect(() => {
    void load();
  }, [load]);

  const loadMoreCases = useCallback(async () => {
    if (loadingMore || !hasMoreCases) return;
    setLoadingMore(true);
    setLoadMoreError('');
    try {
      const page = await api.listCases({ offset: cases.length, limit: CASE_PAGE_SIZE });
      setCases((current) => {
        const known = new Set(current.map((record) => record.id));
        return [...current, ...page.filter((record) => !known.has(record.id))];
      });
      setHasMoreCases(page.length === CASE_PAGE_SIZE);
    } catch (error) {
      setLoadMoreError(formatApiError(error, 'additional case history'));
    } finally {
      setLoadingMore(false);
    }
  }, [api, cases.length, hasMoreCases, loadingMore]);

  async function createCase(event) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const name = form.get('name')?.trim();
    const description = form.get('description')?.trim();
    if (!name) return;
    setSubmitting(true);
    setFormError('');
    try {
      const created = await api.createCase({ name, description });
      setCases((current) => [created, ...current]);
      formElement.reset();
    } catch (error) {
      setFormError(formatApiError(error, 'case'));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="page-shell cases-page">
      <section className="page-intro">
        <div>
          <h1>Investigation cases</h1>
          <p>Keep every target, scan, and finding inside an authorized case boundary.</p>
        </div>
      </section>

      <div className="two-column-grid">
        <section className="panel" aria-labelledby="new-case-title">
          <div className="section-heading-row">
            <div>
              <h2 id="new-case-title">Create a case</h2>
              <p>Record purpose and scope before collecting.</p>
            </div>
            <Plus aria-hidden="true" />
          </div>
          <form className="stacked-form" onSubmit={createCase}>
            <label htmlFor="case-name">Case name</label>
            <input id="case-name" name="name" maxLength="200" required />
            <label htmlFor="case-description">Description</label>
            <textarea id="case-description" name="description" maxLength="2000" rows="4" />
            {formError ? <p className="form-error" role="alert">{formError}</p> : null}
            <button className="button button--primary" disabled={submitting} type="submit">
              <BriefcaseBusiness aria-hidden="true" size={17} />
              {submitting ? 'Creating…' : 'Create case'}
            </button>
          </form>
        </section>
        <div className="capability-column">
          {capabilityError ? <ErrorState message={capabilityError} onRetry={load} title="Collection is not ready" /> : null}
          {!capabilityError && capabilities ? <CapabilitiesPanel capabilities={capabilities} /> : null}
          {!capabilityError && capabilityLoading ? (
            <section className="panel"><LoadingState label="Checking collection readiness…" /></section>
          ) : null}
        </div>
      </div>

      <section className="case-history" aria-labelledby="case-history-title">
        <div className="section-heading-row">
          <div>
            <h2 id="case-history-title">Case history</h2>
            <p>{cases.length} authorized {cases.length === 1 ? 'case' : 'cases'}</p>
          </div>
        </div>
        {loading ? <LoadingState label="Loading cases…" /> : null}
        {!loading && loadError ? <ErrorState message={loadError} onRetry={load} title="Cases could not be loaded" /> : null}
        {!loading && !loadError && cases.length === 0 ? (
          <EmptyState title="No cases yet" message="Create the first case to begin a scoped investigation." />
        ) : null}
        {!loadError && cases.length > 0 ? (
          <div className="case-list" id="case-history-list">
            {cases.map((record) => (
              <Link className="case-row" key={record.id} state={{ caseRecord: record }} to={`/cases/${record.id}`}>
                <span className="case-row__icon"><BriefcaseBusiness aria-hidden="true" /></span>
                <span className="case-row__content">
                  <strong>{record.name}</strong>
                  <span>{record.description || 'No description provided'}</span>
                </span>
                <span className="case-row__date">Updated {formatDate(record.updated_at)}</span>
                <ArrowRight aria-hidden="true" />
              </Link>
            ))}
          </div>
        ) : null}
        {!loadError && cases.length > 0 && loadMoreError ? (
          <ErrorState
            message={loadMoreError}
            onRetry={loadMoreCases}
            title="More cases could not be loaded"
          />
        ) : null}
        {!loadError && cases.length > 0 && hasMoreCases && !loadMoreError ? (
          <button
            aria-controls="case-history-list"
            className="button button--secondary load-more"
            disabled={loadingMore}
            onClick={loadMoreCases}
            type="button"
          >
            {loadingMore ? 'Loading more cases...' : 'Load more cases'}
          </button>
        ) : null}
      </section>
    </div>
  );
}
