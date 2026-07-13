import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';

import AdapterProgress from './AdapterProgress';

it('renders each target run independently with its outcome provenance', () => {
  render(<AdapterProgress
    runs={[
      {
        id: 'run-1',
        adapter_id: 'shodan',
        state: 'succeeded',
        finding_count: 1,
        latency_seconds: 0.2,
        outcome_code: 'provider_response_parsed',
        source_target: { target_type: 'ip', target_value: '203.0.113.10' },
      },
      {
        id: 'run-2',
        adapter_id: 'shodan',
        state: 'no_results',
        finding_count: 0,
        latency_seconds: 0.3,
        outcome_code: 'provider_not_found',
        source_target: { target_type: 'ip', target_value: '203.0.113.11' },
      },
    ]}
    scanState="partial"
    selectedAdapters={['shodan']}
  />);

  expect(screen.getAllByText('Shodan')).toHaveLength(2);
  expect(screen.getByText(/203\.0\.113\.10/)).toBeInTheDocument();
  expect(screen.getByText(/203\.0\.113\.11/)).toBeInTheDocument();
  expect(screen.getByText(/provider response parsed/i)).toBeInTheDocument();
  expect(screen.getByText(/provider not found/i)).toBeInTheDocument();
});
