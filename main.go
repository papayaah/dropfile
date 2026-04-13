package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "embed"
)

// Rate limiter: tracks upload count per IP in a sliding window.
type rateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Remove expired entries
	times := rl.requests[ip]
	valid := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.requests[ip] = valid
		return false
	}

	rl.requests[ip] = append(valid, now)
	return true
}

func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-rl.window)
	for ip, times := range rl.requests {
		valid := times[:0]
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = valid
		}
	}
}

type Config struct {
	Port            string
	UploadDir       string
	MaxFileSize     int64
	DefaultExpiry   time.Duration
	CleanupInterval time.Duration
	BaseURL         string
}

type FileMeta struct {
	Filename   string    `json:"filename"`
	Size       int64     `json:"size"`
	UploadedAt time.Time `json:"uploaded_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	UploaderIP string    `json:"uploader_ip"`
	Country    string    `json:"country,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
}

type SyncEvent struct {
	Type string `json:"type"` // "file" or "text"
	Data any    `json:"data"`
}

// Global state for live sync
var (
	clients   = make(map[string]map[chan SyncEvent]bool) // ip -> map of client channels
	clientsMu sync.Mutex
)

//go:embed index.html
var indexHTML []byte

var (
	cfg           Config
	absUploadDir  string
	uploadLimiter *rateLimiter
)

const maxStoragePerIP = 500 * 1024 * 1024 // 500MB per IP

func broadcast(ip string, event SyncEvent) {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	if list, ok := clients[ip]; ok {
		for ch := range list {
			select {
			case ch <- event:
			default:
				// If client is slow/blocked, skip
			}
		}
	}
}

func storageUsedByIP(ip string) int64 {
	entries, err := os.ReadDir(cfg.UploadDir)
	if err != nil {
		return 0
	}
	var total int64
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		meta, err := readMeta(filepath.Join(cfg.UploadDir, entry.Name()))
		if err != nil {
			continue
		}
		if meta.UploaderIP == ip && time.Now().Before(meta.ExpiresAt) {
			total += meta.Size
		}
	}
	return total
}

func checkUploadAllowed(ip string) string {
	if !uploadLimiter.allow(ip) {
		return "Rate limit exceeded. Try again in a minute.\n"
	}
	if storageUsedByIP(ip) >= maxStoragePerIP {
		return "Storage limit reached (500 MB per user). Wait for files to expire.\n"
	}
	return ""
}

func loadConfig() Config {
	c := Config{
		Port:            envOr("PORT", "8080"),
		UploadDir:       envOr("UPLOAD_DIR", "./uploads"),
		MaxFileSize:     envOrInt64("MAX_FILE_SIZE", 100*1024*1024), // 100MB
		DefaultExpiry:   envOrDuration("DEFAULT_EXPIRY", 168*time.Hour),
		CleanupInterval: envOrDuration("CLEANUP_INTERVAL", 1*time.Hour),
		BaseURL:         envOr("BASE_URL", "http://localhost:8080"), // Default for dev
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	return c
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrInt64(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			return n
		}
	}
	return fallback
}

func envOrDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return fallback
}

func generateID(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		b[i] = charset[n.Int64()]
	}
	return string(b), nil
}

func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if i := strings.IndexByte(fwd, ','); i > 0 {
			return strings.TrimSpace(fwd[:i])
		}
		return strings.TrimSpace(fwd)
	}
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

func sanitizeFilename(name string) string {
	name = filepath.Base(name)
	if name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return ""
	}
	if strings.ContainsAny(name, `/\`) {
		return ""
	}
	if name == "" {
		return ""
	}
	return name
}

func readMeta(dirPath string) (FileMeta, error) {
	var meta FileMeta
	data, err := os.ReadFile(filepath.Join(dirPath, ".meta.json"))
	if err != nil {
		return meta, err
	}
	err = json.Unmarshal(data, &meta)
	return meta, err
}

func writeMeta(dirPath string, meta FileMeta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := filepath.Join(dirPath, ".meta.json.tmp")
	finalPath := filepath.Join(dirPath, ".meta.json")
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, finalPath)
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.0f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func isCurl(r *http.Request) bool {
	return strings.HasPrefix(r.UserAgent(), "curl/")
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if isCurl(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, `
=============================================================
  dropfile.dev — temporary file sharing
=============================================================

  Upload:    curl dropfile.dev -T file.txt
  Download:  curl <url>

  Files expire after %s. Max size: %s.
=============================================================
`, cfg.DefaultExpiry, formatBytes(cfg.MaxFileSize))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func handlePostUpload(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	if msg := checkUploadAllowed(ip); msg != "" {
		http.Error(w, msg, http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxFileSize)

	file, header, err := r.FormFile("file")
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, fmt.Sprintf("File too large (max %s)\n", formatBytes(cfg.MaxFileSize)), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "No file provided\n", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := sanitizeFilename(header.Filename)
	if filename == "" {
		http.Error(w, "Invalid filename\n", http.StatusBadRequest)
		return
	}

	id, err := generateID(8)
	if err != nil {
		http.Error(w, "Internal error\n", http.StatusInternalServerError)
		return
	}

	dirPath := filepath.Join(cfg.UploadDir, id)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		http.Error(w, "Internal error\n", http.StatusInternalServerError)
		return
	}

	filePath := filepath.Join(dirPath, filename)
	f, err := os.Create(filePath)
	if err != nil {
		os.RemoveAll(dirPath)
		http.Error(w, "Internal error\n", http.StatusInternalServerError)
		return
	}

	n, err := io.Copy(f, file)
	f.Close()
	if err != nil {
		os.RemoveAll(dirPath)
		http.Error(w, "Upload failed\n", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	meta := FileMeta{
		Filename:   filename,
		Size:       n,
		UploadedAt: now,
		ExpiresAt:  now.Add(cfg.DefaultExpiry),
		UploaderIP: ip,
		Country:    r.Header.Get("CF-IPCountry"),
		UserAgent:  r.UserAgent(),
	}
	if err := writeMeta(dirPath, meta); err != nil {
		os.RemoveAll(dirPath)
		http.Error(w, "Internal error\n", http.StatusInternalServerError)
		return
	}

	downloadURL := fmt.Sprintf("%s/%s/%s", cfg.BaseURL, id, filename)

	resp := map[string]any{
		"url":      downloadURL,
		"filename": filename,
		"size":     n,
		"expires":  meta.ExpiresAt.Format(time.RFC3339),
	}

	// Broadcast upload
	broadcast(ip, SyncEvent{Type: "file", Data: resp})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	if msg := checkUploadAllowed(ip); msg != "" {
		http.Error(w, msg, http.StatusTooManyRequests)
		return
	}

	filename := sanitizeFilename(r.PathValue("filename"))
	if filename == "" {
		http.Error(w, "Invalid filename\n", http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxFileSize)

	id, err := generateID(8)
	if err != nil {
		http.Error(w, "Internal error\n", http.StatusInternalServerError)
		return
	}

	dirPath := filepath.Join(cfg.UploadDir, id)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		http.Error(w, "Internal error\n", http.StatusInternalServerError)
		return
	}

	filePath := filepath.Join(dirPath, filename)
	f, err := os.Create(filePath)
	if err != nil {
		os.RemoveAll(dirPath)
		http.Error(w, "Internal error\n", http.StatusInternalServerError)
		return
	}

	n, err := io.Copy(f, r.Body)
	f.Close()
	if err != nil {
		os.RemoveAll(dirPath)
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, fmt.Sprintf("File too large (max %s)\n", formatBytes(cfg.MaxFileSize)), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Upload failed\n", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	meta := FileMeta{
		Filename:   filename,
		Size:       n,
		UploadedAt: now,
		ExpiresAt:  now.Add(cfg.DefaultExpiry),
		UploaderIP: ip,
		Country:    r.Header.Get("CF-IPCountry"),
		UserAgent:  r.UserAgent(),
	}
	if err := writeMeta(dirPath, meta); err != nil {
		os.RemoveAll(dirPath)
		http.Error(w, "Internal error\n", http.StatusInternalServerError)
		return
	}

	downloadURL := fmt.Sprintf("%s/%s/%s", cfg.BaseURL, id, filename)

	// Broadcast upload
	broadcast(ip, SyncEvent{
		Type: "file",
		Data: map[string]any{
			"url":      downloadURL,
			"filename": filename,
			"size":     n,
			"expires":  meta.ExpiresAt.Format(time.RFC3339),
		},
	})

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "\n  file: %s\n  size: %s\n  from: %s\n  expires: %s\n  url: %s\n\n",
		filename,
		formatBytes(n),
		meta.Country,
		meta.ExpiresAt.Format("2006-01-02 15:04 UTC"),
		downloadURL,
	)
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	filename := sanitizeFilename(r.PathValue("filename"))

	if id == "" || filename == "" {
		http.Error(w, "Not found\n", http.StatusNotFound)
		return
	}

	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			http.Error(w, "Not found\n", http.StatusNotFound)
			return
		}
	}

	dirPath := filepath.Join(cfg.UploadDir, id)
	filePath := filepath.Join(dirPath, filename)

	absPath, err := filepath.Abs(filePath)
	if err != nil || !strings.HasPrefix(absPath, absUploadDir+string(filepath.Separator)) {
		http.Error(w, "Not found\n", http.StatusNotFound)
		return
	}

	meta, err := readMeta(dirPath)
	if err != nil {
		http.Error(w, "Not found\n", http.StatusNotFound)
		return
	}

	if time.Now().After(meta.ExpiresAt) {
		os.RemoveAll(dirPath)
		http.Error(w, "File has expired\n", http.StatusGone)
		return
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "Not found\n", http.StatusNotFound)
		return
	}

	http.ServeFile(w, r, filePath)
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := make(chan SyncEvent, 10)

	clientsMu.Lock()
	if clients[ip] == nil {
		clients[ip] = make(map[chan SyncEvent]bool)
	}
	clients[ip][ch] = true
	clientsMu.Unlock()

	defer func() {
		clientsMu.Lock()
		delete(clients[ip], ch)
		if len(clients[ip]) == 0 {
			delete(clients, ip)
		}
		clientsMu.Unlock()
	}()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Send initial heartbeat
	fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"ok\"}\n\n")
	flusher.Flush()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event := <-ch:
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "event: sync\ndata: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, "event: heartbeat\ndata: {}\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func handleClipboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := getClientIP(r)
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if len(req.Text) > 100*1024 { // 100KB limit for text sync
		http.Error(w, "Text too large", http.StatusRequestEntityTooLarge)
		return
	}

	broadcast(ip, SyncEvent{
		Type: "text",
		Data: req.Text,
	})

	w.WriteHeader(http.StatusOK)
}

func startCleanup(ctx context.Context) {
	ticker := time.NewTicker(cfg.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cleanExpiredUploads()
		case <-ctx.Done():
			return
		}
	}
}

func cleanExpiredUploads() {
	entries, err := os.ReadDir(cfg.UploadDir)
	if err != nil {
		log.Printf("cleanup: error reading upload dir: %v", err)
		return
	}

	now := time.Now()
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirPath := filepath.Join(cfg.UploadDir, entry.Name())
		meta, err := readMeta(dirPath)
		if err != nil {
			info, _ := entry.Info()
			if info != nil && now.Sub(info.ModTime()) > 2*cfg.DefaultExpiry {
				os.RemoveAll(dirPath)
			}
			continue
		}
		if now.After(meta.ExpiresAt) {
			os.RemoveAll(dirPath)
		}
	}
}

func main() {
	cfg = loadConfig()

	if err := os.MkdirAll(cfg.UploadDir, 0755); err != nil {
		log.Fatalf("Failed to create upload directory: %v", err)
	}

	var err error
	absUploadDir, err = filepath.Abs(cfg.UploadDir)
	if err != nil {
		log.Fatalf("Failed to resolve upload directory: %v", err)
	}

	uploadLimiter = newRateLimiter(20, 1*time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go startCleanup(ctx)

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				uploadLimiter.cleanup()
			case <-ctx.Done():
				return
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", handleIndex)
	mux.HandleFunc("GET /events", handleEvents)
	mux.HandleFunc("POST /clipboard", handleClipboard)
	mux.HandleFunc("GET /theme/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "theme/index.html")
	})
	mux.HandleFunc("GET /theme/v1", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "theme/v1/index.html")
	})
	mux.HandleFunc("GET /theme/v2-neon", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "theme/v2-neon/index.html")
	})
	mux.HandleFunc("GET /theme/v3-cartoon", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "theme/v3-cartoon/index.html")
	})
	mux.HandleFunc("GET /theme/v4-retro", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "theme/v4-retro/index.html")
	})
	mux.HandleFunc("GET /theme/v5-premium", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "theme/v5-premium/index.html")
	})
	mux.HandleFunc("GET /theme/v6-organic", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "theme/v6-organic/index.html")
	})
	mux.HandleFunc("GET /theme/v7-glitch", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "theme/v7-glitch/index.html")
	})
	mux.HandleFunc("GET /theme/v8-90s", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "theme/v8-90s/index.html")
	})
	mux.HandleFunc("GET /theme/v9-brutalist", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "theme/v9-brutalist/index.html")
	})
	mux.HandleFunc("GET /theme/v10-cosmic", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "theme/v10-cosmic/index.html")
	})
	mux.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "robots.txt")
	})
	mux.HandleFunc("GET /og-image.png", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "og-image.png")
	})
	mux.HandleFunc("GET /{id}/{filename}", handleDownload)
	mux.HandleFunc("PUT /{filename}", handleUpload)
	mux.HandleFunc("POST /{$}", handlePostUpload)

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
	}()

	log.Printf("dropfile listening on :%s", cfg.Port)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
