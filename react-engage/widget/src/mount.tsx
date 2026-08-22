import { createRoot } from 'react-dom/client';
import { EngageWidget } from '@reactkits.dev/react-engage';
import '@reactkits.dev/react-engage/styles.css';
import { DROPFILE_FAQS } from './faqs';

// Mount point is a <div id="engage-root"></div> injected into index.html.
// The widget is anonymous for now (no user prop); Google sign-in can supply a
// `user` here later, and resolveRequestUser on the sidecar will authenticate it.
const el = document.getElementById('engage-root');
if (el) {
  createRoot(el).render(
    <EngageWidget
      appId="dropfile"
      endpointUrl="/api/engage"
      theme="inherit"
      position="bottom-right"
      accentColor="#6366f1"
      iconOnly
      enabledTabs={['faq', 'feedback']}
      faqs={DROPFILE_FAQS}
    />,
  );
}
