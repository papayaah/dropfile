# dropfile.dev

Instant temporary file sharing from terminal or browser.

## Features

- No account required.
- Files expire after 7 days.
- Real-time clipboard sync between devices on the same IP.
- Instant file list updates via SSE.
- Drag and drop support.
- Terminal-friendly via curl.

## Usage

### Browser
Drop files or paste text into the dashboard to share instantly with other devices on your local network.

### Terminal
Upload:
```bash
curl dropfile.dev -T yourfile.txt
```

Download:
```bash
curl dropfile.dev/ID/yourfile.txt
```

## Running Locally

```bash
go run main.go
```

## Deployment

1. Create a .env file with server details.
2. Run ./deploy.sh
