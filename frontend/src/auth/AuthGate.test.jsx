import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';

import { AuthProvider } from './AuthContext';
import AuthGate from './AuthGate';
import { useAuth } from './context';

afterEach(() => {
  window.history.replaceState({}, '', '/');
});

function AuthStateProbe() {
  const auth = useAuth();
  if (auth.loading) return <span>Loading</span>;
  return (
    <div>
      <span>{auth.user ? 'Signed in' : 'Signed out'}</span>
      {auth.error ? <span role="alert">{auth.error}</span> : null}
    </div>
  );
}


it('offers an OIDC redirect when production authentication is configured', async () => {
  window.history.replaceState({}, '', '/scans/scan-9?view=graph#node-1');
  const signinRedirect = vi.fn(async () => {});
  const manager = {
    events: {
      addUserLoaded: vi.fn(),
      addUserUnloaded: vi.fn(),
      removeUserLoaded: vi.fn(),
      removeUserUnloaded: vi.fn(),
    },
    getUser: vi.fn(async () => null),
    signinRedirect,
  };
  const managerFactory = async () => manager;
  render(
    <AuthProvider enabled managerFactory={managerFactory}>
      <AuthGate />
    </AuthProvider>,
  );
  const user = userEvent.setup();

  await user.click(await screen.findByRole('button', { name: /sign in with sso/i }));

  expect(signinRedirect).toHaveBeenCalledWith({
    state: { returnTo: '/scans/scan-9?view=graph#node-1' },
  });
});

it('dispatches OIDC callbacks and restores the retained local route', async () => {
  window.history.replaceState({}, '', '/?code=authorization-code&state=callback-state');
  const signinCallback = vi.fn(async () => ({
    state: { returnTo: '/cases/case-7?panel=history#latest' },
  }));
  const signinRedirectCallback = vi.fn(async () => {});
  const manager = {
    events: {
      addUserLoaded: vi.fn(),
      addUserUnloaded: vi.fn(),
      removeUserLoaded: vi.fn(),
      removeUserUnloaded: vi.fn(),
    },
    getUser: vi.fn(async () => null),
    signinCallback,
    signinRedirectCallback,
  };

  render(
    <AuthProvider enabled managerFactory={async () => manager}>
      <AuthGate />
    </AuthProvider>,
  );

  await waitFor(() => expect(signinCallback).toHaveBeenCalledWith(expect.stringContaining('code=authorization-code')));
  expect(signinRedirectCallback).not.toHaveBeenCalled();
  expect(`${window.location.pathname}${window.location.search}${window.location.hash}`)
    .toBe('/cases/case-7?panel=history#latest');
});

it('rejects an external OIDC return route', async () => {
  window.history.replaceState({}, '', '/?code=authorization-code&state=callback-state');
  const manager = {
    events: {},
    getUser: vi.fn(async () => null),
    signinCallback: vi.fn(async () => ({
      state: { returnTo: '//attacker.example/steal' },
    })),
  };

  render(
    <AuthProvider enabled managerFactory={async () => manager}>
      <AuthStateProbe />
    </AuthProvider>,
  );

  await screen.findByText('Signed out');
  expect(`${window.location.pathname}${window.location.search}`).toBe('/cases');
});

it.each([
  {
    event: 'expired',
    trigger: (handlers) => handlers.expired(),
    message: /session expired/i,
  },
  {
    event: 'silent renewal failure',
    trigger: (handlers) => handlers.silent(new Error('Silent renewal failed.')),
    message: /silent renewal failed/i,
  },
])('clears a stale user after $event', async ({ trigger, message }) => {
  const handlers = {};
  const manager = {
    events: {
      addUserLoaded: vi.fn(),
      addUserUnloaded: vi.fn(),
      addAccessTokenExpired: vi.fn((handler) => { handlers.expired = handler; }),
      addSilentRenewError: vi.fn((handler) => { handlers.silent = handler; }),
      removeUserLoaded: vi.fn(),
      removeUserUnloaded: vi.fn(),
      removeAccessTokenExpired: vi.fn(),
      removeSilentRenewError: vi.fn(),
    },
    getUser: vi.fn(async () => ({
      access_token: 'stale-token',
      expired: false,
      profile: { sub: 'investigator-1' },
    })),
  };

  render(
    <AuthProvider enabled managerFactory={async () => manager}>
      <AuthStateProbe />
    </AuthProvider>,
  );
  await screen.findByText('Signed in');

  act(() => trigger(handlers));

  expect(await screen.findByText('Signed out')).toBeInTheDocument();
  expect(screen.getByRole('alert')).toHaveTextContent(message);
});
