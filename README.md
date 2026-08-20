# dropfile.dev

> Instant temporary file sharing and clipboard sync from your terminal or browser.  
> **Live Website:** [https://dropfile.dev](https://dropfile.dev)

![dropfile.dev screenshot](screenshot.png)

---

## Features

- **No Account Needed**: Anonymous, fast, and zero registration required.
- **Auto-Expiry**: Files automatically expire and are securely deleted after 7 days.
- **Terminal-First**: Upload directly from your command line using `curl`.
- **Real-Time Sync**: Instant live updates via SSE for devices on the same local network / IP.
- **Unified Activity Feed**: Streamlined timeline of all your recent files, uploaded images, and text clips.
- **Image Thumbnails & Modal Lightbox**: High-clarity, zero-margin image previews and an in-page popup modal to view images without leaving the page.
- **Direct Image Copying**: Copy image data directly to your clipboard to paste right into Slack, Messenger, Discord, or WhatsApp.
- **Clipboard Sync**: Instantly share text snippets or paste files with <kbd>Cmd+V</kbd> / <kbd>Ctrl+V</kbd> or the Paste button.
- **Live Stats**: Real-time tracking of active files, storage used, connected devices, and total shares.

---

## Privacy

- **IP-Localized Sync**: Discovery and real-time broadcasting are localized to your public IP.
- **Ephemeral Text**: Text clipboard snippets are held in memory and never persisted to the server's disk.
- **Zero Tracking**: No telemetry, analytics, or user profiling.

---

## Usage

### Browser
Visit [https://dropfile.dev](https://dropfile.dev) and drag & drop files, click to browse, or paste (<kbd>Cmd+V</kbd> / <kbd>Ctrl+V</kbd>) from your clipboard.

### Terminal (CLI)

**Upload a file:**
```bash
curl dropfile.dev -T yourfile.txt
```

**Download a file:**
```bash
curl -O dropfile.dev/ID/yourfile.txt
```

---

## Running Locally

Make sure you have [Go](https://go.dev) installed:

```bash
# Clone the repository
git clone https://github.com/papayaah/dropfile.git
cd dropfile

# Run development server
go run main.go
```

By default, the server runs on `http://localhost:8080` (or configure via `PORT=3001 go run main.go`).

---

## Deployment

1. Create a `.env` file with your server details:
   ```env
   DEPLOY_SERVER=user@your-server-ip
   DEPLOY_DEST=/srv/dropfile
   GO_BINARY_PATH=go
   ```
2. Run the deployment script:
   ```bash
   ./deploy.sh
   ```
