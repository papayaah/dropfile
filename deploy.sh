#!/bin/bash
set -e

# Load configuration from .env
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
else
  echo "[ERROR] .env file not found! Create one with DEPLOY_SERVER, DEPLOY_DEST, and GO_BINARY_PATH."
  exit 1
fi

# 1. Rebuild the react-engage widget bundle from the published npm package so the
#    embedded assets/engage.js|css are current, then compile it into the binary.
echo "[WIDGET] Building react-engage widget bundle..."
( cd widget && npm ci --silent && npm run build )

echo "[BUILD] Building Go binary for Linux..."
GOOS=linux GOARCH=amd64 $GO_BINARY_PATH build -o dropfile_linux main.go

echo "[UPLOAD] Uploading binary to $DEPLOY_SERVER..."
rsync -azP dropfile_linux $DEPLOY_SERVER:$DEPLOY_DEST/dropfile

# 2. Ship the engage sidecar (Next.js) + compose file, then (re)build and start
#    the Postgres + sidecar containers on the server. The Go binary reaches the
#    sidecar over 127.0.0.1:3001 (ENGAGE_UPSTREAM).
echo "[ENGAGE] Syncing sidecar source to $DEPLOY_SERVER..."
rsync -azP --delete \
  --exclude 'node_modules/' \
  --exclude '.next/' \
  --exclude '.env' \
  engage/ $DEPLOY_SERVER:$DEPLOY_DEST/engage/
rsync -azP docker-compose.yml $DEPLOY_SERVER:$DEPLOY_DEST/docker-compose.yml

echo "[ENGAGE] Building & starting containers on server..."
ssh $DEPLOY_SERVER "cd $DEPLOY_DEST && docker compose up -d --build"

echo "[RESTART] Restarting dropfile service..."
ssh $DEPLOY_SERVER "systemctl restart dropfile"

echo "[OK] Done!"
rm dropfile_linux
