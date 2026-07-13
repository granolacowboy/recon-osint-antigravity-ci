import { Target } from 'lucide-react';
import { Link, NavLink } from 'react-router-dom';
import { useAuth } from '../auth/context';

export default function AppShell({ children }) {
  const auth = useAuth();
  const identity = auth.user?.profile?.name || auth.user?.profile?.email || auth.user?.profile?.sub;
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <header className="app-header">
        <Link className="brand" to="/cases" aria-label="RECON OSINT case history">
          <Target className="brand-icon" aria-hidden="true" size={26} />
          <span>RECON OSINT</span>
        </Link>
        <nav aria-label="Primary navigation">
          <NavLink className={({ isActive }) => `nav-link${isActive ? ' nav-link--active' : ''}`} to="/cases">
            Cases
          </NavLink>
          {auth.enabled ? (
            <button className="nav-signout" onClick={() => void auth.signOut()} type="button">
              <span>{identity || 'Investigator'}</span>
              Sign out
            </button>
          ) : null}
        </nav>
      </header>
      <main className="app-main" id="main-content" tabIndex="-1">{children}</main>
    </div>
  );
}
