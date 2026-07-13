import { createContext, useContext } from 'react';

export const AuthContext = createContext({
  enabled: false,
  loading: false,
  user: null,
  error: '',
  getAccessToken: async () => null,
  signIn: async () => {},
  signOut: async () => {},
});

export function useAuth() {
  return useContext(AuthContext);
}
