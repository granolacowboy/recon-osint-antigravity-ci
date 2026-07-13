import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';

import GraphWorkspace from './GraphWorkspace';

vi.mock('./GraphViewer', () => ({
  default: () => <div>Graph renderer</div>,
}));

beforeEach(() => {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    value: vi.fn(() => ({
      matches: true,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    })),
  });
});

it('keeps the closed mobile filter drawer inert and restores focus after Escape', async () => {
  render(<GraphWorkspace edges={[]} nodes={[{ id: 'node-1', entity_type: 'ip' }]} />);
  const user = userEvent.setup();
  const toggle = screen.getByRole('button', { name: /filters/i });
  const drawer = document.getElementById('graph-filters');

  expect(drawer).toHaveAttribute('aria-hidden', 'true');
  expect(drawer).toHaveAttribute('inert');
  await user.click(toggle);

  expect(drawer).not.toHaveAttribute('aria-hidden');
  const close = within(drawer).getByRole('button', { name: /close filters/i });
  expect(close).toHaveFocus();
  await user.tab({ shift: true });
  expect(within(drawer).getByRole('checkbox', { name: /ip/i })).toHaveFocus();
  await user.tab();
  expect(close).toHaveFocus();
  await user.keyboard('{Escape}');

  await waitFor(() => expect(toggle).toHaveFocus());
  expect(drawer).toHaveAttribute('aria-hidden', 'true');
  expect(toggle).toHaveAttribute('aria-expanded', 'false');
});
