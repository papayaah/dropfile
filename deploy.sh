#!/bin/bash
set -e

# Load configuration from .env
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
else
  echo "[ERROR] .env file not found! Create one with DEPLOY_SERVER, DEPLOY_DEST, and GO_BINARY_PATH."
  exit 1
fi

echo "[BUILD] Building for Linux..."
GOOS=linux GOARCH=amd64 $GO_BINARY_PATH build -o dropfile_linux main.go

echo "[UPLOAD] Uploading binary to $DEPLOY_SERVER..."
rsync -azP dropfile_linux $DEPLOY_SERVER:$DEPLOY_DEST/dropfile

echo "[RESTART] Restarting service..."
ssh $DEPLOY_SERVER "systemctl restart dropfile"

echo "[OK] Done!"
rm dropfile_linux
