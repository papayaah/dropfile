import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema';

const connectionString =
  process.env.DATABASE_URL ||
  'postgres://postgres:postgres@localhost:5433/dropfile_engage';

// Long-lived Node process (not serverless) -> a normal pooled client is fine.
const client = postgres(connectionString);

export const db = drizzle(client, { schema });
