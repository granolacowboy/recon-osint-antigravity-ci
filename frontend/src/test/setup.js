import '@testing-library/jest-dom/vitest';

import React from 'react';
import { expect, afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';
import { toHaveNoViolations } from 'jest-axe';

globalThis.React = React;
globalThis.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};
expect.extend(toHaveNoViolations);

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});
