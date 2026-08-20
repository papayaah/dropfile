import { createRoot } from 'react-dom/client';
import { EngageAdminPanel } from '@reactkits.dev/react-engage/admin';
import '@reactkits.dev/react-engage/styles.css';

// Served at /admin by the Go server (behind HTTP Basic Auth, which sets the
// engage_admin cookie). Same-origin fetches to /api/engage carry that cookie,
// so the sidecar authorizes the admin list/reply/broadcast actions.
const el = document.getElementById('engage-admin-root');
if (el) {
  createRoot(el).render(
    <EngageAdminPanel apiEndpoint="/api/engage" theme="inherit" />,
  );
}
