import { describe, expect, it, vi } from 'vitest';

import { createApiClient, parseEventStream } from './client';

describe('API client', () => {
  it('uses the scoped v1 case and scan contract', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify([]), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 'scan-1' }), { status: 202 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ nodes: [] }), { status: 200 }));
    const api = createApiClient({ baseUrl: 'https://recon.test', fetchImpl });

    await api.listCases({ offset: 50, limit: 25 });
    await api.createScan('case-1', { targets: [] }, { idempotencyKey: 'submission-1' });
    await api.getGraph('scan-1', { cursor: '20', limit: 50 });

    expect(fetchImpl.mock.calls[0][0]).toBe('https://recon.test/v1/cases?offset=50&limit=25');
    expect(fetchImpl.mock.calls[1][0]).toBe('https://recon.test/v1/cases/case-1/scans');
    expect(fetchImpl.mock.calls[1][1]).toMatchObject({ method: 'POST' });
    expect(fetchImpl.mock.calls[1][1].headers.get('idempotency-key')).toBe('submission-1');
    expect(fetchImpl.mock.calls[2][0]).toBe('https://recon.test/v1/scans/scan-1/graph?cursor=20&limit=50');
  });

  it('turns FastAPI validation arrays into actionable field messages', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({
      detail: [{ loc: ['body', 'targets', 0, 'target_value'], msg: 'Field required', type: 'missing' }],
    }), { status: 422, headers: { 'content-type': 'application/json' } }));
    const api = createApiClient({ baseUrl: 'https://recon.test', fetchImpl });

    await expect(api.createScan('case-1', { targets: [{}] }))
      .rejects.toMatchObject({
        status: 422,
        message: 'targets / item 1 / target value: Field required',
      });
  });

  it('lists durable scans within a case scope', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify([{ id: 'scan-1' }]), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));
    const api = createApiClient({ baseUrl: 'https://recon.test', fetchImpl });

    await expect(api.listCaseScans('case/one', { offset: 50, limit: 20 })).resolves.toEqual([{ id: 'scan-1' }]);
    expect(fetchImpl.mock.calls[0][0]).toBe('https://recon.test/v1/cases/case%2Fone/scans?offset=50&limit=20');
  });

  it('gets a single owned case without depending on a capped case list', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ id: 'case-1' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));
    const api = createApiClient({ baseUrl: 'https://recon.test', fetchImpl });

    await expect(api.getCase('case/one')).resolves.toEqual({ id: 'case-1' });
    expect(fetchImpl.mock.calls[0][0]).toBe('https://recon.test/v1/cases/case%2Fone');
  });

  it('parses named SSE events across stream chunks', () => {
    const events = parseEventStream([
      'id: 1\nevent: status\ndata: {"state":"run',
      'ning"}\n\nid: 2\ndata: {"state":"succeeded"}\n\n',
    ]);

    expect(events).toEqual([
      { id: '1', event: 'status', data: { state: 'running' } },
      { id: '2', event: 'message', data: { state: 'succeeded' } },
    ]);
  });

  it('normalizes backend capability metadata for the UI', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({
      adapters: [{
        adapter_id: 'shodan',
        display_name: 'Shodan Host API',
        enabled: false,
        unavailable_reason: 'missing_credentials',
        target_types: ['ip'],
      }],
      dependencies: { store: true, queue: true },
    }), { status: 200, headers: { 'content-type': 'application/json' } }));
    const api = createApiClient({ baseUrl: 'https://recon.test', fetchImpl });

    const result = await api.getCapabilities();

    expect(result.adapters[0]).toMatchObject({
      id: 'shodan',
      name: 'Shodan Host API',
      reason: 'Required provider credentials are not configured.',
    });
  });

  it('consumes authenticated SSE progress without putting credentials in the URL', async () => {
    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode('event: scan_status\ndata: {"state":"succeeded"}\n\n'));
        controller.close();
      },
    });
    const fetchImpl = vi.fn(async () => new Response(stream, {
      status: 200,
      headers: { 'content-type': 'text/event-stream' },
    }));
    const api = createApiClient({
      baseUrl: 'https://recon.test',
      fetchImpl,
      tokenProvider: () => 'secret-token',
    });

    const event = await new Promise((resolve) => {
      api.subscribeScanEvents('scan-1', { onEvent: resolve });
    });

    expect(event.data.state).toBe('succeeded');
    expect(fetchImpl.mock.calls[0][0]).toBe('https://recon.test/v1/scans/scan-1/events');
    expect(fetchImpl.mock.calls[0][1].headers.get('authorization')).toBe('Bearer secret-token');
  });

  it('does not reconnect SSE after a permanent authorization failure', async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 401 }));
    const api = createApiClient({
      baseUrl: 'https://recon.test',
      fetchImpl,
      reconnectDelay: 0,
      reconnectJitter: 0,
    });

    const error = await new Promise((resolve) => {
      api.subscribeScanEvents('scan-1', { onError: resolve });
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(error.status).toBe(401);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('caps consecutive transient SSE reconnect attempts', async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 503 }));
    const api = createApiClient({
      baseUrl: 'https://recon.test',
      fetchImpl,
      reconnectDelay: 0,
      reconnectJitter: 0,
      maxReconnectAttempts: 2,
    });

    await new Promise((resolve) => {
      let errors = 0;
      api.subscribeScanEvents('scan-1', {
        onError: () => {
          errors += 1;
          if (errors === 2) resolve();
        },
      });
    });

    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('resets consecutive retry counting after valid SSE traffic and resumes from its event id', async () => {
    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode('id: event-2\nevent: scan_status\ndata: {"state":"running"}\n\n'));
        controller.close();
      },
    });
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(new Response(null, { status: 503 }))
      .mockResolvedValueOnce(new Response(stream, { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 503 }));
    const api = createApiClient({
      baseUrl: 'https://recon.test',
      fetchImpl,
      reconnectDelay: 0,
      reconnectJitter: 0,
      maxReconnectAttempts: 2,
    });

    const stop = api.subscribeScanEvents('scan-1');
    while (fetchImpl.mock.calls.length < 3) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    stop();

    expect(fetchImpl.mock.calls[2][1].headers.get('last-event-id')).toBe('event-2');
  });
});
