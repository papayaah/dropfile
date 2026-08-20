import { pgTable, text, timestamp, jsonb, integer } from 'drizzle-orm/pg-core';

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
  createdAt: timestamp('created_at', { mode: 'string' }).notNull().defaultNow(),
});

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
