import { useMemo } from 'react';

import { createApiClient } from '../api/client';
import { ApiProvider } from '../api/context';
import { AppRoutes } from '../App';
import { useAuth } from './context';

export default function AuthGate() {
  const auth = useAuth();
  const client = useMemo(
    () => createApiClient({ tokenProvider: auth.getAccessToken }),
    [auth.getAccessToken],
  );

  if (auth.loading) {
    return <main className="auth-screen" role="status">Preparing secure sign-in…</main>;
  }
  if (auth.enabled && !auth.user) {
    return (
      <main className="auth-screen">
        <section className="auth-card" aria-labelledby="sign-in-title">
          <span className="eyebrow">Authorized investigators only</span>
          <h1 id="sign-in-title">Sign in to RECON OSINT</h1>
          <p>Use your organization identity to access case-scoped investigations.</p>
          {auth.error ? <p className="form-error" role="alert">{auth.error}</p> : null}
          <button className="button button--primary" onClick={() => void auth.signIn()} type="button">Sign in with SSO</button>
        </section>
      </main>
    );
  }

  return (
    <ApiProvider value={client}>
      <AppRoutes />
    </ApiProvider>
  );
}
