package tlsrouter

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// JSONLRetentionPolicy configures retention logging.
type JSONLRetentionPolicy struct {
	// Directory for log files. If empty, retention is disabled.
	Directory string

	// Rotation interval. Default: daily (24h)
	Rotation time.Duration

	// Retention period. Files older than this are deleted. Default: 7 days
	Retention time.Duration

	// Compress old files. Default: true
	Compress bool
}

// JSONLRetentionWriter writes connection stats to JSONL files.
type JSONLRetentionWriter struct {
	policy JSONLRetentionPolicy

	mu       sync.Mutex
	file     *os.File
	encoder  *json.Encoder
	filename string

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewJSONLRetentionWriter creates a new retention writer.
func NewJSONLRetentionWriter(policy JSONLRetentionPolicy) (*JSONLRetentionWriter, error) {
	if policy.Directory == "" {
		return nil, nil // Retention disabled
	}

	// Set defaults
	if policy.Rotation == 0 {
		policy.Rotation = 24 * time.Hour
	}
	if policy.Retention == 0 {
		policy.Retention = 7 * 24 * time.Hour
	}

	// Create directory if needed
	if err := os.MkdirAll(policy.Directory, 0755); err != nil {
		return nil, err
	}

	w := &JSONLRetentionWriter{
		policy: policy,
		stopCh: make(chan struct{}),
	}

	// Open initial file
	if err := w.rotate(); err != nil {
		return nil, err
	}

	// Start rotation goroutine
	w.wg.Add(1)
	go w.rotationLoop()

	// Start compression goroutine if enabled
	if policy.Compress {
		w.wg.Add(1)
		go w.compressionLoop()
	}

	return w, nil
}

// Write writes a connection stats to the current file.
func (w *JSONLRetentionWriter) Write(stats *ConnectionStats) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil // No file open
	}

	return w.encoder.Encode(stats)
}

// Close closes the retention writer.
func (w *JSONLRetentionWriter) Close() error {
	close(w.stopCh)
	w.wg.Wait()

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// rotate opens a new file for writing.
func (w *JSONLRetentionWriter) rotate() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Close current file
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			return err
		}
	}

	// Create new file
	filename := filepath.Join(
		w.policy.Directory,
		"connections-"+time.Now().Format("2006-01-02")+".jsonl",
	)

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	w.file = file
	w.filename = filename
	w.encoder = json.NewEncoder(file)
	w.encoder.SetEscapeHTML(false)

	return nil
}

// rotationLoop handles file rotation.
func (w *JSONLRetentionWriter) rotationLoop() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.policy.Rotation)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			_ = w.rotate()
			_ = w.cleanOldFiles()
		case <-w.stopCh:
			return
		}
	}
}

// cleanOldFiles removes files older than retention period.
func (w *JSONLRetentionWriter) cleanOldFiles() error {
	if w.policy.Retention == 0 {
		return nil
	}

	entries, err := os.ReadDir(w.policy.Directory)
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(-w.policy.Retention)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if filepath.Ext(name) != ".jsonl" && filepath.Ext(name) != ".jsonl.gz" {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(w.policy.Directory, name))
		}
	}

	return nil
}

// compressionLoop compresses old files.
func (w *JSONLRetentionWriter) compressionLoop() {
	defer w.wg.Done()

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			_ = w.compressOldFiles()
		case <-w.stopCh:
			return
		}
	}
}

// compressOldFiles compresses files that are not the current file.
func (w *JSONLRetentionWriter) compressOldFiles() error {
	w.mu.Lock()
	currentFile := w.filename
	w.mu.Unlock()

	entries, err := os.ReadDir(w.policy.Directory)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if filepath.Ext(name) != ".jsonl" {
			continue
		}

		// Skip current file
		fullPath := filepath.Join(w.policy.Directory, name)
		if fullPath == currentFile {
			continue
		}

		// Check if already compressed
		gzPath := fullPath + ".gz"
		if _, err := os.Stat(gzPath); err == nil {
			// Already compressed, delete uncompressed
			_ = os.Remove(fullPath)
			continue
		}

		// Compress
		if err := compressFile(fullPath, gzPath); err != nil {
			continue
		}

		// Delete original
		_ = os.Remove(fullPath)
	}

	return nil
}

// compressFile compresses a file using gzip.
func compressFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	gzWriter := gzip.NewWriter(dstFile)
	defer gzWriter.Close()

	// Copy content
	buf := make([]byte, 32*1024)
	for {
		n, err := srcFile.Read(buf)
		if n > 0 {
			if _, err := gzWriter.Write(buf[:n]); err != nil {
				return err
			}
		}
		if err != nil {
			break
		}
	}

	return nil
}