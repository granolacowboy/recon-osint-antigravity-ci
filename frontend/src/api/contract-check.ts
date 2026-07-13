import type { components, paths } from './schema';

type Assert<T extends true> = T;

export type ApiCase = components['schemas']['Case'];
export type ApiScan = components['schemas']['Scan'];
export type ApiScanDetail = components['schemas']['ScanDetail'];
export type ApiGraphPage = components['schemas']['GraphPage'];

export type ContractHasCaseDetail = Assert<
  '/v1/cases/{case_id}' extends keyof paths ? true : false
>;
export type ContractHasScanEvents = Assert<
  '/v1/scans/{scan_id}/events' extends keyof paths ? true : false
>;
