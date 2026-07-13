import { useContext } from 'react';

import { ApiContext } from './ApiContext';

export function useApi() {
  return useContext(ApiContext);
}
