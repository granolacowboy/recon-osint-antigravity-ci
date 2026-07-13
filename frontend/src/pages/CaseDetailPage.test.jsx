import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ApiProvider } from '../api/context';
import { AppRoutes } from '../App';
import { capabilities, createMockApi, scanRecord } from '../test/fixtures';

it('preflights capabilities and creates a passive scan', async () => {
  const createScan = vi.fn(async () => scanRecord);
  const api = createMockApi({ createScan });
  render(
    <ApiProvider value={api}>
      <MemoryRouter initialEntries={['/cases/case-1']}>
        <AppRoutes />
      </MemoryRouter>
    </ApiProvider>,
  );
  const user = userEvent.setup();

  expect(await screen.findByRole('heading', { name: 'Acme inquiry' })).toBeInTheDocument();
  expect(screen.getByText(/1 of 2 adapters available/i)).toBeInTheDocument();
  expect(screen.getByText(/provider executable is unavailable/i)).toBeInTheDocument();

  await user.selectOptions(screen.getByLabelText(/target type/i), 'ip');
  await user.type(screen.getByLabelText(/targets/i), '203.0.113.10');
  await user.click(screen.getByRole('button', { name: /queue passive scan/i }));

  expect(createScan).toHaveBeenCalledWith(
    'case-1',
    {
      targets: [{ target_type: 'ip', target_value: '203.0.113.10' }],
      mode: 'passive',
      adapter_ids: ['shodan'],
      active_scan_confirmed: false,
    },
    { idempotencyKey: expect.any(String) },
  );
  expect(await screen.findByRole('heading', { name: /scan scan-1/i })).toBeInTheDocument();
});

it('does not advertise active collection when deployment policy disables it', async () => {
  render(
    <ApiProvider value={createMockApi()}>
      <MemoryRouter initialEntries={['/cases/case-1']}>
        <AppRoutes />
      </MemoryRouter>
    </ApiProvider>,
  );

  await screen.findByRole('heading', { name: 'Acme inquiry' });

  expect(screen.getByRole('option', { name: /active/i })).toBeDisabled();
  expect(screen.getByText(/active collection is disabled by deployment policy/i)).toBeInTheDocument();
});

it('does not advertise active collection to an investigator without the active role', async () => {
  const investigatorCapabilities = {
    ...capabilities,
    policy: {
      ...capabilities.policy,
      active_scanning_enabled: true,
      active_scanning_authorized: false,
      active_scope_configured: true,
    },
  };
  render(
    <ApiProvider value={createMockApi({ getCapabilities: async () => investigatorCapabilities })}>
      <MemoryRouter initialEntries={['/cases/case-1']}>
        <AppRoutes />
      </MemoryRouter>
    </ApiProvider>,
  );

  await screen.findByRole('heading', { name: 'Acme inquiry' });

  expect(screen.getByRole('option', { name: /active/i })).toBeDisabled();
  expect(screen.getByText(/requires an administrator role/i)).toBeInTheDocument();
});

it('loads complete scan detail instead of hydrating history summaries', async () => {
  const { adapter_runs: _adapterRuns, ...historySummary } = scanRecord;
  const getScan = vi.fn(async () => scanRecord);
  render(
    <ApiProvider value={createMockApi({
      getScan,
      listCaseScans: async () => [historySummary],
    })}>
      <MemoryRouter initialEntries={['/cases/case-1']}>
        <AppRoutes />
      </MemoryRouter>
    </ApiProvider>,
  );

  expect(await screen.findByRole('heading', { name: /scan history/i })).toBeInTheDocument();
  const previousScan = screen.getByRole('link', { name: /203\.0\.113\.10/i });
  expect(previousScan).toHaveAttribute('href', '/scans/scan-1');
  expect(previousScan).toHaveTextContent(/succeeded/i);

  await userEvent.click(previousScan);

  expect(await screen.findByRole('heading', { name: /scan scan-1/i })).toBeInTheDocument();
  expect(getScan).toHaveBeenCalledWith('scan-1');
  expect(screen.getByText('Shodan')).toBeInTheDocument();
});

it('resolves the case directly and loads additional scan-history pages', async () => {
  const firstPage = Array.from({ length: 50 }, (_, index) => ({
    ...scanRecord,
    id: `scan-${index}`,
    targets: [{ target_type: 'domain', target_value: `host-${index}.example` }],
  }));
  const getCase = vi.fn(async () => ({
    id: 'case-1',
    owner_id: 'investigator-1',
    name: 'Acme inquiry',
    description: 'Authorized scope',
    created_at: '2026-07-10T10:00:00Z',
    updated_at: '2026-07-10T10:00:00Z',
  }));
  const listCaseScans = vi.fn(async (_caseId, { offset }) => (offset === 0
    ? firstPage
    : [{
      ...scanRecord,
      id: 'scan-50',
      targets: [{ target_type: 'domain', target_value: 'final.example' }],
    }]));
  render(
    <ApiProvider value={createMockApi({ getCase, listCaseScans })}>
      <MemoryRouter initialEntries={['/cases/case-1']}>
        <AppRoutes />
      </MemoryRouter>
    </ApiProvider>,
  );
  const user = userEvent.setup();

  const loadMore = await screen.findByRole('button', { name: /load more scans/i });
  await user.click(loadMore);

  expect(await screen.findByRole('link', { name: /final\.example/i })).toBeInTheDocument();
  expect(screen.getByRole('link', { name: /host-0\.example/i })).toBeInTheDocument();
  expect(getCase).toHaveBeenCalledWith('case-1');
  expect(listCaseScans).toHaveBeenNthCalledWith(1, 'case-1', { offset: 0, limit: 50 });
  expect(listCaseScans).toHaveBeenNthCalledWith(2, 'case-1', { offset: 50, limit: 50 });
  expect(screen.queryByRole('button', { name: /load more scans/i })).not.toBeInTheDocument();
});

it('retries capability preflight and clears the stale readiness error after recovery', async () => {
  const unavailable = new Error('queue unavailable');
  unavailable.status = 503;
  unavailable.details = { adapters: [], dependencies: { queue: { healthy: false } } };
  const getCapabilities = vi.fn()
    .mockRejectedValueOnce(unavailable)
    .mockResolvedValueOnce(capabilities);
  render(
    <ApiProvider value={createMockApi({ getCapabilities })}>
      <MemoryRouter initialEntries={['/cases/case-1']}>
        <AppRoutes />
      </MemoryRouter>
    </ApiProvider>,
  );
  const user = userEvent.setup();

  expect(await screen.findByText(/collection readiness service is unavailable/i)).toBeInTheDocument();
  expect(screen.queryByText(/0 of 0 adapters available/i)).not.toBeInTheDocument();
  expect(screen.queryByText(/checking collection readiness/i)).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: /retry/i }));

  expect(await screen.findByText(/1 of 2 adapters available/i)).toBeInTheDocument();
  expect(screen.queryByText(/collection readiness service is unavailable/i)).not.toBeInTheDocument();
});

it('reuses the idempotency key when the same ambiguous submission is retried', async () => {
  const createScan = vi.fn()
    .mockRejectedValueOnce(new Error('connection dropped'))
    .mockResolvedValueOnce(scanRecord);
  render(
    <ApiProvider value={createMockApi({ createScan })}>
      <MemoryRouter initialEntries={['/cases/case-1']}>
        <AppRoutes />
      </MemoryRouter>
    </ApiProvider>,
  );
  const user = userEvent.setup();

  await screen.findByRole('heading', { name: 'Acme inquiry' });
  await user.selectOptions(screen.getByLabelText(/target type/i), 'ip');
  await user.type(screen.getByLabelText(/targets/i), '203.0.113.10');
  await user.click(screen.getByRole('button', { name: /queue passive scan/i }));
  expect(await screen.findByText(/connection dropped/i)).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: /queue passive scan/i }));

  const firstKey = createScan.mock.calls[0][2].idempotencyKey;
  expect(createScan.mock.calls[1][2].idempotencyKey).toBe(firstKey);
});
