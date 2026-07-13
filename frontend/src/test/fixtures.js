export const caseRecord = {
  id: 'case-1',
  owner_id: 'investigator-1',
  name: 'Acme inquiry',
  description: 'External exposure review',
  created_at: '2026-07-10T10:00:00Z',
  updated_at: '2026-07-10T10:00:00Z',
};

export const capabilities = {
  adapters: [
    {
      id: 'shodan',
      name: 'Shodan',
      description: 'Passive public internet observations',
      target_types: ['ip'],
      enabled: true,
      passive: true,
      version: '1',
    },
    {
      id: 'whois',
      name: 'WHOIS',
      target_types: ['domain'],
      enabled: false,
      passive: true,
      reason: 'Provider executable is unavailable.',
    },
  ],
  dependencies: {
    queue: { healthy: true },
    graph: { healthy: true },
  },
  policy: {
    passive_default: true,
    active_scanning_enabled: false,
    active_scanning_authorized: false,
    active_scope_configured: false,
    max_batch_size: 25,
  },
};

export const scanRecord = {
  id: 'scan-1',
  case_id: 'case-1',
  owner_id: 'investigator-1',
  targets: [{ target_type: 'ip', target_value: '203.0.113.10' }],
  mode: 'passive',
  adapter_ids: ['shodan'],
  state: 'succeeded',
  job_id: 'job-1',
  created_at: '2026-07-10T10:05:00Z',
  finished_at: '2026-07-10T10:06:00Z',
  adapter_runs: [
    {
      id: 'run-1',
      adapter_id: 'shodan',
      adapter_version: '1',
      state: 'succeeded',
      finding_count: 1,
      attempts: 1,
      latency_seconds: 0.4,
    },
  ],
};

export const graphPage = {
  nodes: [
    {
      id: 'node-1',
      entity_type: 'ip',
      value: '203.0.113.10',
      metadata: { country: 'US' },
    },
    {
      id: 'node-2',
      entity_type: 'domain',
      value: 'example.com',
      metadata: {},
    },
  ],
  edges: [
    {
      id: 'edge-1',
      source_node_id: 'node-2',
      target_node_id: 'node-1',
      relationship: 'resolves_to',
    },
  ],
  provenance: [
    {
      id: 'prov-1',
      node_id: 'node-1',
      source_adapter_id: 'shodan',
      adapter_version: '1',
      observed_at: '2026-07-10T10:05:30Z',
      confidence: 0.9,
      source_relationship: 'observed_from',
      source_target: { target_type: 'ip', target_value: '203.0.113.10' },
    },
  ],
  next_cursor: null,
};

export function createMockApi(overrides = {}) {
  return {
    listCases: async () => [caseRecord],
    getCase: async () => caseRecord,
    listCaseScans: async () => [scanRecord],
    createCase: async (input) => ({ ...caseRecord, ...input, id: 'case-new' }),
    getCapabilities: async () => capabilities,
    createScan: async () => scanRecord,
    getScan: async () => scanRecord,
    getGraph: async () => graphPage,
    cancelScan: async () => ({ ...scanRecord, state: 'cancelled' }),
    subscribeScanEvents: () => () => {},
    ...overrides,
  };
}
