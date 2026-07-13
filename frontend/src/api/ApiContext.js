import { createContext } from 'react';

import { apiClient } from './client';

export const ApiContext = createContext(apiClient);
