import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'jest-axe';

import { ApiProvider } from '../api/context';
import { AppRoutes } from '../App';
import { createMockApi, scanRecord } from '../test/fixtures';

function renderScan(api, initialScan = null) {
  return render(
    <ApiProvider value={api}>
      <MemoryRouter initialEntries={[initialScan
        ? { pathname: '/scans/scan-1', state: { initialScan } }
        : '/scans/scan-1']}>
        <AppRoutes />
      </MemoryRouter>
    </ApiProvider>,
  );
}

describe('scan detail', () => {
  it('does not let an older status response overwrite a newer terminal state', async () => {
    const running = { ...scanRecord, state: 'running', finished_at: null };
    const succeeded = { ...scanRecord, state: 'succeeded' };
    const pending = [];
    let progressHandlers;
    const getScan = vi.fn(() => new Promise((resolve) => pending.push(resolve)));
    const api = createMockApi({
      getScan,
      subscribeScanEvents: (_scanId, handlers) => {
        progressHandlers = handlers;
        return () => {};
      },
    });
    renderScan(api, running);

    await waitFor(() => expect(getScan).toHaveBeenCalledTimes(1));
    await act(async () => progressHandlers.onEvent({ data: { state: 'running' } }));
    await waitFor(() => expect(getScan).toHaveBeenCalledTimes(2));
    await act(async () => pending[1](succeeded));
    expect(await screen.findByText('Scan succeeded.')).toBeInTheDocument();
    await act(async () => pending[0](running));

    expect(screen.getByText('Scan succeeded.')).toBeInTheDocument();
  });

  it('shows durable completion, adapter outcomes, and an equivalent relationship table', async () => {
    const { container } = renderScan(createMockApi());

    expect(await screen.findByRole('heading', { name: /scan scan-1/i })).toBeInTheDocument();
    expect(screen.getAllByText('Succeeded')).toHaveLength(2);
    expect(screen.getByText('Shodan')).toBeInTheDocument();
    expect(screen.getByText(/1 finding/i)).toBeInTheDocument();
    expect(await screen.findByRole('cell', { name: 'resolves to' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /sort by source/i }).closest('th')).toHaveAttribute('aria-sort', 'none');
    expect(await axe(container)).toHaveNoViolations();
  });

  it('shows a dependency error without also claiming the graph is empty', async () => {
    const api = createMockApi({
      getGraph: vi.fn(async () => {
        const error = new Error('graph unavailable');
        error.status = 503;
        error.code = 'dependency_unavailable';
        throw error;
      }),
    });
    renderScan(api);

    expect(await screen.findByText(/graph service is unavailable/i)).toBeInTheDocument();
    expect(screen.queryByText(/no findings/i)).not.toBeInTheDocument();
  });

  it('cancels a running scan and exposes retry after terminal failure', async () => {
    const running = { ...scanRecord, state: 'running', finished_at: null };
    const cancelled = { ...scanRecord, state: 'cancelled' };
    const cancelScan = vi.fn(async () => ({
      id: running.id,
      case_id: running.case_id,
      state: 'running',
      cancellation_requested: true,
    }));
    const getScan = vi.fn()
      .mockResolvedValueOnce(running)
      .mockResolvedValue(cancelled);
    const api = createMockApi({ getScan, cancelScan });
    renderScan(api);
    const user = userEvent.setup();

    await user.click(await screen.findByRole('button', { name: /cancel scan/i }));
    expect(cancelScan).toHaveBeenCalledWith('scan-1');
    expect(await screen.findByText('Cancelled')).toBeInTheDocument();
    expect(screen.getByText('Shodan')).toBeInTheDocument();
    expect(getScan).toHaveBeenCalledTimes(2);
    expect(screen.getByRole('button', { name: /retry scan/i })).toBeInTheDocument();
  });

  it('keeps an acknowledged cancellation disabled while durable polling continues', async () => {
    const running = {
      ...scanRecord,
      state: 'running',
      finished_at: null,
      cancellation_requested: false,
    };
    const cancelScan = vi.fn(async () => ({
      id: running.id,
      case_id: running.case_id,
      state: 'running',
      cancellation_requested: true,
    }));
    const getScan = vi.fn(async () => running);
    renderScan(createMockApi({ getScan, cancelScan }), running);
    const user = userEvent.setup();

    await user.click(await screen.findByRole('button', { name: /cancel scan/i }));

    const acknowledged = await screen.findByRole('button', { name: /cancellation requested/i });
    expect(acknowledged).toBeDisabled();
    expect(cancelScan).toHaveBeenCalledOnce();
    expect(screen.queryByRole('button', { name: /^cancel scan$/i })).not.toBeInTheDocument();
  });

  it('supports arrow-key navigation across the finding tabs', async () => {
    renderScan(createMockApi());
    const user = userEvent.setup();
    const relationships = await screen.findByRole('tab', { name: /relationships/i });

    relationships.focus();
    await user.keyboard('{ArrowRight}');

    const graph = screen.getByRole('tab', { name: /^graph$/i });
    expect(graph).toHaveFocus();
    expect(graph).toHaveAttribute('aria-selected', 'true');
  });

  it('requires fresh authorization confirmation before retrying an active scan', async () => {
    const activeFailure = { ...scanRecord, mode: 'active', state: 'failed' };
    const createScan = vi.fn(async () => ({ ...scanRecord, id: 'scan-retry' }));
    renderScan(createMockApi({ getScan: async () => activeFailure, createScan }));
    const user = userEvent.setup();

    const retry = await screen.findByRole('button', { name: /retry scan/i });
    expect(retry).toBeDisabled();

    await user.click(screen.getByLabelText(/confirm this active retry is authorized/i));
    await user.click(retry);

    expect(createScan).toHaveBeenCalledWith(
      'case-1',
      expect.objectContaining({
        mode: 'active',
        active_scan_confirmed: true,
      }),
      { idempotencyKey: expect.any(String) },
    );
  }, 10_000);

  it('explains a terminal scan with no available adapters without contradictory progress copy', async () => {
    const unavailable = {
      ...scanRecord,
      state: 'failed',
      outcome_code: 'no_adapters_available',
      adapter_runs: [],
    };
    renderScan(createMockApi({ getScan: async () => unavailable, getGraph: async () => ({ nodes: [], edges: [], provenance: [] }) }));

    expect(await screen.findByText(/no enabled adapter was available/i)).toBeInTheDocument();
    expect(screen.getByText(/no adapters available/i)).toBeInTheDocument();
    expect(screen.getByText(/configure an enabled adapter/i)).toBeInTheDocument();
    expect(screen.queryByText(/adapter jobs have not started/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/adapters completed/i)).not.toBeInTheDocument();
  });

  it('refreshes findings during the durable polling fallback', async () => {
    const running = { ...scanRecord, state: 'running', finished_at: null };
    const getGraph = vi.fn(async () => ({ nodes: [], edges: [], provenance: [] }));
    let poll;
    const originalSetInterval = window.setInterval.bind(window);
    const interval = vi.spyOn(window, 'setInterval').mockImplementation((callback, delay, ...args) => {
      if (delay === 5000) {
        poll = callback;
        return 1;
      }
      return originalSetInterval(callback, delay, ...args);
    });
    renderScan(createMockApi({ getScan: async () => running, getGraph }), running);

    await waitFor(() => expect(getGraph).toHaveBeenCalledTimes(1));
    await act(async () => poll());

    await waitFor(() => expect(getGraph).toHaveBeenCalledTimes(2));
    interval.mockRestore();
  });

  it('uses the terminal scan outcome to color the live status indicator', async () => {
    const failed = { ...scanRecord, state: 'failed' };
    const { container } = renderScan(createMockApi({ getScan: async () => failed }), failed);

    await screen.findByText('Scan failed.');
    expect(container.querySelector('.live-dot')).toHaveClass('live-dot--terminal', 'live-dot--failed');
  });
});
