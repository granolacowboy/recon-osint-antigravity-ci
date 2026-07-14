import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'jest-axe';

import { ApiProvider } from '../api/context';
import { AppRoutes } from '../App';
import { createMockApi } from '../test/fixtures';

function renderRoute(api, route = '/cases') {
  return render(
    <ApiProvider value={api}>
      <MemoryRouter initialEntries={[route]}>
        <AppRoutes />
      </MemoryRouter>
    </ApiProvider>,
  );
}

describe('case history', () => {
  it('lists cases and creates a new case from a labelled form', async () => {
    const createCase = vi.fn(async (input) => ({
      id: 'case-new',
      owner_id: 'investigator-1',
      created_at: '2026-07-10T11:00:00Z',
      updated_at: '2026-07-10T11:00:00Z',
      ...input,
    }));
    const api = createMockApi({ createCase });
    renderRoute(api);
    const user = userEvent.setup();

    expect(await screen.findByRole('heading', { name: /investigation cases/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /acme inquiry/i })).toBeInTheDocument();

    await user.type(screen.getByLabelText(/case name/i), 'New inquiry');
    await user.type(screen.getByLabelText(/description/i), 'Scope notes');
    await user.click(screen.getByRole('button', { name: /create case/i }));

    expect(createCase).toHaveBeenCalledWith({ name: 'New inquiry', description: 'Scope notes' });
    expect(await screen.findByRole('link', { name: /new inquiry/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/case name/i)).toHaveValue('');
    expect(screen.getByLabelText(/description/i)).toHaveValue('');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('has no obvious automated accessibility violations', async () => {
    const { container } = renderRoute(createMockApi());
    await screen.findByText('Acme inquiry');
    expect(await axe(container)).toHaveNoViolations();
  });

  it('keeps case history available when collection dependencies are down', async () => {
    const dependencyError = new Error('service dependency unavailable');
    dependencyError.status = 503;
    dependencyError.details = {
      adapters: [],
      dependencies: { queue: { healthy: false } },
    };
    const api = createMockApi({ getCapabilities: async () => { throw dependencyError; } });
    renderRoute(api);

    expect(await screen.findByText('Acme inquiry')).toBeInTheDocument();
    expect(screen.getByText(/collection readiness service is unavailable/i)).toBeInTheDocument();
    expect(screen.queryByText(/cases could not be loaded/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/0 of 0 adapters available/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/checking collection readiness/i)).not.toBeInTheDocument();
  });

  it('loads additional case-history pages without replacing existing rows', async () => {
    const firstPage = Array.from({ length: 50 }, (_, index) => ({
      id: `case-${index}`,
      name: `Case ${index}`,
      description: '',
      updated_at: '2026-07-10T11:00:00Z',
    }));
    const listCases = vi.fn(async ({ offset }) => (offset === 0
      ? firstPage
      : [{
        id: 'case-50',
        name: 'Case 50',
        description: '',
        updated_at: '2026-07-10T11:00:00Z',
      }]));
    renderRoute(createMockApi({ listCases }));
    const user = userEvent.setup();

    const loadMore = await screen.findByText(/^load more cases$/i, { selector: 'button' });
    await user.click(loadMore);

    const appendedCase = await screen.findByText(/^case 50$/i, { selector: 'strong' });
    const existingCase = screen.getByText(/^case 0$/i, { selector: 'strong' });
    const appendedCaseLink = appendedCase.closest('a');
    const existingCaseLink = existingCase.closest('a');
    expect(appendedCaseLink).toBeInTheDocument();
    expect(appendedCaseLink).toHaveRole('link');
    expect(appendedCaseLink).toHaveAccessibleName(/case 50/i);
    expect(appendedCaseLink).toHaveAttribute('href', '/cases/case-50');
    expect(existingCaseLink).toBeInTheDocument();
    expect(existingCaseLink).toHaveRole('link');
    expect(existingCaseLink).toHaveAccessibleName(/case 0/i);
    expect(existingCaseLink).toHaveAttribute('href', '/cases/case-0');
    expect(listCases).toHaveBeenNthCalledWith(1, { offset: 0, limit: 50 });
    expect(listCases).toHaveBeenNthCalledWith(2, { offset: 50, limit: 50 });
    expect(screen.queryByText(/^load more cases$/i, { selector: 'button' })).not.toBeInTheDocument();
  });
});
