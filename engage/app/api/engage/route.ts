import { createEngageRouteHandler } from '@reactkits.dev/react-engage/server';
import { timingSafeEqual } from 'crypto';
import { db } from '@/lib/db';
import {
  engageTickets,
  engageSubscribers,
  engageTemplates,
  engageBroadcasts,
} from '@/lib/schema';

// Constant-time secret comparison so admin auth can't be timing-probed.
function secretMatches(candidate: string | undefined, secret: string): boolean {
  if (!candidate) return false;
  const a = Buffer.from(candidate);
  const b = Buffer.from(secret);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// This is the entire backend. All widget submissions (bug/suggestion/ticket/
// newsletter) and admin actions are handled by the published react-engage
// package.
export const { GET, POST } = createEngageRouteHandler({
  db,
  tables: {
    tickets: engageTickets,
    subscribers: engageSubscribers,
    templates: engageTemplates,
    broadcasts: engageBroadcasts,
  },
  // Interim admin auth until Google sign-in. The Go server gates /admin behind
  // HTTP Basic Auth and, on success, sets an httpOnly `engage_admin` cookie
  // whose value is ENGAGE_ADMIN_SECRET. We validate that cookie here so the
  // admin list/reply/broadcast endpoints require it — anyone without it gets a
  // 403 (this is also what closes the "endpoints wide open" gap: react-engage
  // only enforces requireAdmin once resolveRequestUser is configured).
  resolveRequestUser: async (req) => {
    const secret = process.env.ENGAGE_ADMIN_SECRET;
    if (!secret) return null; // admin disabled until a secret is set
    const cookie = req.cookies.get('engage_admin')?.value;
    if (secretMatches(cookie, secret)) {
      return { email: 'admin@dropfile.dev', name: 'Admin', isAdmin: true };
    }
    return null;
  },
});

// Email (admin notifications, welcome, broadcasts) activates when ENGAGE_API_KEY
// (Brevo) + ENGAGE_ADMIN_EMAIL / ENGAGE_FROM_EMAIL are set in the environment.
