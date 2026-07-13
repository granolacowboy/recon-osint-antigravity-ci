import { useCallback, useEffect, useMemo, useState } from 'react';

import { AuthContext } from './context';

const authority = import.meta.env.VITE_OIDC_AUTHORITY || '';
const clientId = import.meta.env.VITE_OIDC_CLIENT_ID || '';
const configured = Boolean(authority && clientId);
let managerPromise;

const DEFAULT_RETURN_TO = '/cases';

function safeLocalReturnTo(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.includes('\\')) {
    return DEFAULT_RETURN_TO;
  }
  try {
    const candidate = new URL(value, window.location.origin);
    if (candidate.origin !== window.location.origin) return DEFAULT_RETURN_TO;
    return `${candidate.pathname}${candidate.search}${candidate.hash}`;
  } catch {
    return DEFAULT_RETURN_TO;
  }
}

async function defaultManagerFactory() {
  if (!configured) return null;
  if (!managerPromise) {
    managerPromise = import('oidc-client-ts').then(({ UserManager, WebStorageStateStore }) => new UserManager({
      authority,
      client_id: clientId,
      redirect_uri: import.meta.env.VITE_OIDC_REDIRECT_URI || `${window.location.origin}/`,
      post_logout_redirect_uri: import.meta.env.VITE_OIDC_POST_LOGOUT_URI || `${window.location.origin}/`,
      response_type: 'code',
      scope: import.meta.env.VITE_OIDC_SCOPE || 'openid profile email',
      extraQueryParams: import.meta.env.VITE_OIDC_AUDIENCE
        ? { audience: import.meta.env.VITE_OIDC_AUDIENCE }
        : {},
      automaticSilentRenew: true,
      monitorSession: false,
      revokeTokensOnSignout: true,
      userStore: new WebStorageStateStore({ store: window.sessionStorage }),
    }));
  }
  return managerPromise;
}

export function AuthProvider({
  children,
  enabled = configured,
  managerFactory = defaultManagerFactory,
}) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(enabled);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    let manager;
    const clearSession = (message = '') => {
      if (!active) return;
      setUser(null);
      setError(message);
    };
    const userLoaded = (record) => {
      if (!active) return;
      if (!record || record.expired) {
        clearSession('Your session expired. Sign in again to continue.');
        return;
      }
      setUser(record);
      setError('');
    };
    const userUnloaded = () => clearSession();
    const accessTokenExpired = () => clearSession('Your session expired. Sign in again to continue.');
    const silentRenewError = (renewError) => clearSession(
      renewError?.message || 'Your session could not be renewed. Sign in again to continue.',
    );

    async function initialize() {
      if (!enabled) {
        setLoading(false);
        return;
      }
      try {
        manager = await managerFactory();
        if (!manager) throw new Error('OIDC client is not configured.');
        manager.events?.addUserLoaded?.(userLoaded);
        manager.events?.addUserUnloaded?.(userUnloaded);
        manager.events?.addAccessTokenExpired?.(accessTokenExpired);
        manager.events?.addSilentRenewError?.(silentRenewError);
        const query = new URLSearchParams(window.location.search);
        if (query.has('code') || query.has('error')) {
          let callbackUser;
          if (typeof manager.signinCallback === 'function') {
            callbackUser = await manager.signinCallback(window.location.href);
          } else {
            callbackUser = await manager.signinRedirectCallback();
          }
          window.history.replaceState(
            {},
            document.title,
            safeLocalReturnTo(callbackUser?.state?.returnTo),
          );
        }
        const current = await manager.getUser();
        if (active) setUser(current && !current.expired ? current : null);
      } catch (authError) {
        if (active) setError(authError?.message || 'Authentication initialization failed.');
      } finally {
        if (active) setLoading(false);
      }
    }

    void initialize();
    return () => {
      active = false;
      manager?.events?.removeUserLoaded?.(userLoaded);
      manager?.events?.removeUserUnloaded?.(userUnloaded);
      manager?.events?.removeAccessTokenExpired?.(accessTokenExpired);
      manager?.events?.removeSilentRenewError?.(silentRenewError);
    };
  }, [enabled, managerFactory]);

  const signIn = useCallback(async () => {
    setError('');
    try {
      const manager = await managerFactory();
      const returnTo = safeLocalReturnTo(
        `${window.location.pathname}${window.location.search}${window.location.hash}`,
      );
      await manager.signinRedirect({ state: { returnTo } });
    } catch (authError) {
      setError(authError?.message || 'Unable to start sign-in.');
    }
  }, [managerFactory]);

  const signOut = useCallback(async () => {
    setError('');
    try {
      const manager = await managerFactory();
      await manager.signoutRedirect();
    } catch (authError) {
      setError(authError?.message || 'Unable to sign out.');
    }
  }, [managerFactory]);

  const getAccessToken = useCallback(async () => {
    if (!enabled) return null;
    const manager = await managerFactory();
    const current = await manager.getUser();
    if (!current || current.expired) {
      setUser(null);
      if (current?.expired) setError('Your session expired. Sign in again to continue.');
      return null;
    }
    return current.access_token;
  }, [enabled, managerFactory]);

  const value = useMemo(() => ({
    enabled,
    loading,
    user,
    error,
    getAccessToken,
    signIn,
    signOut,
  }), [enabled, error, getAccessToken, loading, signIn, signOut, user]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
