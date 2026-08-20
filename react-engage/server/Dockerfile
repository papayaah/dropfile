FROM node:24-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

EXPOSE 3001

# Reconcile the schema (idempotent) before starting. On an empty DB this creates
# the engage_* tables; when already in sync it is a no-op.
CMD ["sh", "-c", "npm run db:push && npm run start"]
