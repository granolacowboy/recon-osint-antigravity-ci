import { expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import EntityTable from './EntityTable';

it('uses keyboard-operable sort buttons and aria-sort', async () => {
  render(<EntityTable nodes={[
    { id: '2', entity_type: 'ip', value: '203.0.113.10' },
    { id: '1', entity_type: 'domain', value: 'example.com' },
  ]} />);
  const user = userEvent.setup();
  const sort = screen.getByRole('button', { name: /sort by entity type/i });
  const column = sort.closest('th');

  expect(column).toHaveAttribute('aria-sort', 'none');
  await user.click(sort);
  expect(column).toHaveAttribute('aria-sort', 'ascending');
  expect(screen.getAllByRole('row')[1]).toHaveTextContent(/domain/i);
});
