import {
  pgTable,
  text,
  timestamp,
  jsonb,
  integer,
  uniqueIndex,
  index,
} from 'drizzle-orm/pg-core';

// These four tables are the contract react-engage's server handler expects
// (column names must match). Kept identical to tradingdiary's engage tables so
// the same published package works unchanged. dropfile scopes its rows with
// app_id = 'dropfile'.

export const engageTickets = pgTable('engage_tickets', {
  id: text('id').primaryKey(),
  appId: text('app_id').notNull().default('app'),
  type: text('type').notNull().default('ticket'), // 'bug' | 'suggestion' | 'ticket' | 'newsletter'
  category: text('category').default('GENERAL'),
  severity: text('severity'), // 'low' | 'medium' | 'high' | 'critical'
  status: text('status').notNull().default('open'), // 'open' | 'in_progress' | 'resolved' | 'closed'
  subject: text('subject'),
  message: text('message').notNull(),
  userEmail: text('user_email'),
  userName: text('user_name'),
  attachments: jsonb('attachments'),
  environment: jsonb('environment'), // URL, browser, OS, screen specs (auto-captured)
  upvotes: integer('upvotes').notNull().default(0), // community upvotes for suggestions
  createdAt: timestamp('created_at', { mode: 'string' }).notNull().defaultNow(),
});

// One row per (suggestion, user) upvote. userKey is a user id / email / device
// identity. Added in react-engage 0.3.0 (suggestion voting).
export const engageSuggestionVotes = pgTable(
  'engage_suggestion_votes',
  {
    id: text('id').primaryKey(),
    suggestionId: text('suggestion_id')
      .notNull()
      .references(() => engageTickets.id, { onDelete: 'cascade' }),
    userKey: text('user_key').notNull(),
    createdAt: timestamp('created_at', { mode: 'string' }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('engage_vote_sugg_user_uq').on(t.suggestionId, t.userKey),
    index('engage_vote_user_idx').on(t.userKey),
  ],
);

export const engageSubscribers = pgTable('engage_subscribers', {
  id: text('id').primaryKey(),
  appId: text('app_id').notNull().default('app'),
  email: text('email').notNull().unique(),
  name: text('name'),
  frequency: text('frequency').default('all'), // 'all' | 'weekly' | 'monthly'
  subscribedAt: timestamp('subscribed_at', { mode: 'string' }).notNull().defaultNow(),
});

export const engageTemplates = pgTable('engage_templates', {
  id: text('id').primaryKey(), // 'welcome' | 'ticket_reply' | 'newsletter'
  name: text('name').notNull(),
  subject: text('subject').notNull(),
  htmlContent: text('html_content').notNull(),
  updatedAt: timestamp('updated_at', { mode: 'string' }).notNull().defaultNow(),
});

export const engageBroadcasts = pgTable('engage_broadcasts', {
  id: text('id').primaryKey(),
  appId: text('app_id').notNull().default('app'),
  subject: text('subject').notNull(),
  content: text('content').notNull(),
  recipientCount: integer('recipient_count').notNull().default(0),
  sentAt: timestamp('sent_at', { mode: 'string' }).notNull().defaultNow(),
});
