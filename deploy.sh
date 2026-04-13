#!/bin/bash
set -e

# Load configuration from .env
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
else
  echo "❌ .env file not found! Create one with DEPLOY_SERVER, DEPLOY_DEST, and GO_BINARY_PATH."
  exit 1
fi

echo "🚀 Building for Linux..."
GOOS=linux GOARCH=amd64 $GO_BINARY_PATH build -o dropfile_linux main.go

echo "📤 Uploading binary to $DEPLOY_SERVER..."
rsync -azP dropfile_linux $DEPLOY_SERVER:$DEPLOY_DEST/dropfile

echo "🔄 Restarting service..."
ssh $DEPLOY_SERVER "systemctl restart dropfile"

echo "✅ Done!"
rm dropfile_linux
