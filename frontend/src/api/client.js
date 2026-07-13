const DEFAULT_API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export class ApiError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = options.status ?? 0;
    this.code = options.code ?? 'request_failed';
    this.correlationId = options.correlationId ?? null;
    this.details = options.details ?? null;
  }
}

function trimTrailingSlash(value) {
  return value.replace(/\/$/, '');
}

function defaultTokenProvider() {
  if (typeof window === 'undefined') return null;
  return window.sessionStorage.getItem('recon_access_token');
}

export function createIdempotencyKey() {
  return globalThis.crypto?.randomUUID?.()
    || `scan-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function formatValidationDetail(detail) {
  if (!Array.isArray(detail)) return null;
  const messages = detail.slice(0, 5).map((issue) => {
    const location = (issue?.loc || [])
      .filter((part) => part !== 'body')
      .map((part) => (typeof part === 'number'
        ? `item ${part + 1}`
        : String(part).replace(/[_-]+/g, ' ')))
      .join(' / ');
    const message = issue?.msg || 'Invalid value.';
    return location ? `${location}: ${message}` : message;
  });
  if (detail.length > messages.length) messages.push(`${detail.length - messages.length} more validation errors.`);
  return messages.join(' ');
}

function normalizeCollection(payload, key) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.[key])) return payload[key];
  if (Array.isArray(payload?.items)) return payload.items;
  return [];
}

function normalizeScan(payload) {
  if (!payload?.scan) return payload;
  return {
    ...payload.scan,
    adapter_runs: payload.adapter_runs || payload.runs || payload.scan.adapter_runs || [],
  };
}

function paginationQuery({ offset = 0, limit = 50 } = {}) {
  const query = new URLSearchParams();
  query.set('offset', String(offset));
  query.set('limit', String(limit));
  return query.toString();
}

const CAPABILITY_REASON_MESSAGES = {
  missing_credentials: 'Required provider credentials are not configured.',
  unfinished_adapter: 'Adapter implementation is incomplete.',
  v1_policy_disabled: 'Disabled by the current product policy.',
  cli_adapter_disabled: 'Provider executable is unavailable in this deployment.',
  active_adapter_disabled: 'Active collection adapter is disabled.',
  fabricated_adapter: 'Disabled because this adapter does not return verified provider data.',
};

function normalizeCapabilities(payload) {
  if (!payload) return payload;
  const adapters = payload.adapters || payload.capabilities || [];
  return {
    ...payload,
    adapters: adapters.map((adapter) => ({
      ...adapter,
      id: adapter.id || adapter.adapter_id,
      name: adapter.name || adapter.display_name,
      reason: adapter.reason
        || CAPABILITY_REASON_MESSAGES[adapter.unavailable_reason]
        || adapter.unavailable_reason,
    })),
  };
}

function eventFromBlock(block) {
  const event = { id: '', event: 'message', data: null };
  const data = [];
  for (const line of block.split(/\r?\n/)) {
    if (!line || line.startsWith(':')) continue;
    const separator = line.indexOf(':');
    const field = separator === -1 ? line : line.slice(0, separator);
    const value = separator === -1 ? '' : line.slice(separator + 1).replace(/^ /, '');
    if (field === 'data') data.push(value);
    if (field === 'event') event.event = value || 'message';
    if (field === 'id') event.id = value;
  }
  if (data.length === 0) return null;
  const serialized = data.join('\n');
  try {
    event.data = JSON.parse(serialized);
  } catch {
    event.data = serialized;
  }
  return event;
}

export function parseEventStream(chunks) {
  return chunks
    .join('')
    .split(/\r?\n\r?\n/)
    .map(eventFromBlock)
    .filter(Boolean);
}

export function formatApiError(error, resource = 'request') {
  if (error?.status === 401) return 'Your session is missing or expired. Sign in again, then retry.';
  if (error?.status === 403 && /active scanning/i.test(error.message || '')) {
    return `${error.message[0].toUpperCase()}${error.message.slice(1)}.`;
  }
  if (error?.status === 403) return 'You do not have permission to perform this action.';
  if (error?.status === 404) return `This ${resource} is unavailable or you no longer have access to it.`;
  if (error?.status === 429) return 'Request limit reached. Wait a moment, then retry.';
  if (error?.status === 503) return `${resource[0].toUpperCase()}${resource.slice(1)} service is unavailable. Check system readiness and retry.`;
  return error?.message || `Unable to complete the ${resource}.`;
}

export function createApiClient({
  baseUrl = DEFAULT_API_BASE,
  fetchImpl = globalThis.fetch,
  tokenProvider = defaultTokenProvider,
  reconnectDelay = 1200,
  reconnectMaxDelay = 15_000,
  reconnectJitter = 0.2,
  maxReconnectAttempts = 8,
} = {}) {
  const root = trimTrailingSlash(baseUrl);

  async function request(path, options = {}) {
    const token = await tokenProvider();
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    headers.set('X-Request-ID', globalThis.crypto?.randomUUID?.() || `${Date.now()}`);
    if (token) headers.set('Authorization', `Bearer ${token}`);
    if (options.body !== undefined) headers.set('Content-Type', 'application/json');

    let response;
    try {
      response = await fetchImpl(`${root}${path}`, {
        ...options,
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
      });
    } catch (error) {
      throw new ApiError('Unable to reach the RECON API.', { details: error });
    }

    const correlationId = response.headers.get('x-request-id');
    const contentType = response.headers.get('content-type') || '';
    const payload = response.status === 204
      ? null
      : contentType.includes('application/json')
        ? await response.json()
        : await response.text();
    if (!response.ok) {
      const detail = payload?.detail;
      const message = typeof detail === 'string'
        ? detail
        : formatValidationDetail(detail)
          || detail?.message
          || payload?.message
          || `Request failed with status ${response.status}.`;
      throw new ApiError(message, {
        status: response.status,
        code: detail?.code || payload?.code,
        correlationId,
        details: payload,
      });
    }
    return payload;
  }

  function subscribeScanEvents(scanId, handlers = {}) {
    const controller = new AbortController();
    let active = true;
    let reconnectAttempts = 0;
    let lastEventId = '';

    const wait = () => new Promise((resolve) => {
      const exponential = Math.min(
        reconnectMaxDelay,
        reconnectDelay * (2 ** Math.max(0, reconnectAttempts - 1)),
      );
      const jitter = exponential * reconnectJitter * Math.random();
      const timer = setTimeout(resolve, exponential + jitter);
      controller.signal.addEventListener('abort', () => {
        clearTimeout(timer);
        resolve();
      }, { once: true });
    });

    async function consume() {
      while (active && !controller.signal.aborted) {
        try {
          const token = await tokenProvider();
          const headers = new Headers({ Accept: 'text/event-stream' });
          if (token) headers.set('Authorization', `Bearer ${token}`);
          if (lastEventId) headers.set('Last-Event-ID', lastEventId);
          const response = await fetchImpl(`${root}/v1/scans/${encodeURIComponent(scanId)}/events`, {
            headers,
            signal: controller.signal,
          });
          if (!response.ok || !response.body) {
            throw new ApiError('Progress stream is unavailable.', { status: response.status });
          }
          handlers.onOpen?.();
          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          let buffer = '';
          while (active) {
            const { value, done } = await reader.read();
            buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
            const blocks = buffer.split(/\r?\n\r?\n/);
            buffer = blocks.pop() || '';
            for (const block of blocks) {
              const event = eventFromBlock(block);
              if (!event) continue;
              reconnectAttempts = 0;
              if (event.id) lastEventId = event.id;
              handlers.onEvent?.(event);
              if (['succeeded', 'partial', 'failed', 'cancelled'].includes(event.data?.state)) {
                active = false;
              }
            }
            if (done) break;
          }
          if (active) reconnectAttempts += 1;
        } catch (error) {
          if (!controller.signal.aborted) {
            reconnectAttempts += 1;
            handlers.onError?.(error);
            const permanent = error instanceof ApiError
              && [400, 401, 403, 404, 405, 410, 422].includes(error.status);
            if (permanent || reconnectAttempts >= maxReconnectAttempts) active = false;
          }
        }
        if (active && !controller.signal.aborted) await wait();
      }
    }

    void consume();
    return () => {
      active = false;
      controller.abort();
    };
  }

  return {
    listCases: async (options) => normalizeCollection(
      await request(`/v1/cases?${paginationQuery(options)}`),
      'cases',
    ),
    getCase: (caseId) => request(`/v1/cases/${encodeURIComponent(caseId)}`),
    listCaseScans: async (caseId, options) => normalizeCollection(
      await request(`/v1/cases/${encodeURIComponent(caseId)}/scans?${paginationQuery(options)}`),
      'scans',
    ).map(normalizeScan),
    createCase: (input) => request('/v1/cases', { method: 'POST', body: input }),
    createScan: async (caseId, input, { idempotencyKey = createIdempotencyKey() } = {}) => normalizeScan(await request(`/v1/cases/${encodeURIComponent(caseId)}/scans`, {
      method: 'POST',
      body: input,
      headers: { 'Idempotency-Key': idempotencyKey },
    })),
    getScan: async (scanId) => normalizeScan(await request(`/v1/scans/${encodeURIComponent(scanId)}`)),
    cancelScan: async (scanId) => normalizeScan(await request(`/v1/scans/${encodeURIComponent(scanId)}/cancel`, { method: 'POST' })),
    getGraph: (scanId, { cursor, limit = 100 } = {}) => {
      const query = new URLSearchParams();
      if (cursor) query.set('cursor', cursor);
      query.set('limit', String(limit));
      return request(`/v1/scans/${encodeURIComponent(scanId)}/graph?${query}`);
    },
    getCapabilities: async () => {
      try {
        return normalizeCapabilities(await request('/v1/capabilities'));
      } catch (error) {
        if (error instanceof ApiError && error.details) {
          error.details = normalizeCapabilities(error.details);
        }
        throw error;
      }
    },
    subscribeScanEvents,
  };
}

export const apiClient = createApiClient();
