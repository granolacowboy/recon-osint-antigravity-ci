import { ApiContext } from './ApiContext';

export function ApiProvider({ value, children }) {
  return <ApiContext.Provider value={value}>{children}</ApiContext.Provider>;
}
