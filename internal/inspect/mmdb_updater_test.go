package inspect

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func newTestUpdater(t *testing.T, licenseKey string) (*MMDBUpdater, string) {
	t.Helper()
	dir := t.TempDir()
	store, _ := NewIOCStore(nil)
	u := NewMMDBUpdater(MMDBConfig{
		LicenseKey: licenseKey,
		DataDir:    dir,
	}, store)
	return u, dir
}

func TestNewMMDBUpdater_DefaultDBIP(t *testing.T) {
	u, _ := newTestUpdater(t, "")

	if u.source != "dbip" {
		t.Errorf("source = %q, want dbip", u.source)
	}
	if u.licenseKey != "" {
		t.Error("license key should be empty")
	}
}

func TestNewMMDBUpdater_MaxMindWithKey(t *testing.T) {
	u, _ := newTestUpdater(t, "test_key_123")

	if u.source != "maxmind" {
		t.Errorf("source = %q, want maxmind", u.source)
	}
	if u.licenseKey != "test_key_123" {
		t.Errorf("key = %q, want test_key_123", u.licenseKey)
	}
}

func TestMMDBUpdater_Status_NoFile(t *testing.T) {
	u, _ := newTestUpdater(t, "")

	status := u.Status()
	if status.Available {
		t.Error("should not be available without mmdb file")
	}
	if status.Source != "dbip" {
		t.Errorf("source = %q, want dbip", status.Source)
	}
}

func TestMMDBUpdater_SetLicenseKey(t *testing.T) {
	u, _ := newTestUpdater(t, "")

	if u.source != "dbip" {
		t.Fatalf("initial source = %q, want dbip", u.source)
	}

	// Setting a key switches to MaxMind.
	u.SetLicenseKey("new_key")

	u.mu.RLock()
	source := u.source
	key := u.licenseKey
	u.mu.RUnlock()

	if source != "maxmind" {
		t.Errorf("source = %q after SetLicenseKey, want maxmind", source)
	}
	if key != "new_key" {
		t.Errorf("key = %q, want new_key", key)
	}

	// Clearing the key switches back to DB-IP.
	u.SetLicenseKey("")
	u.mu.RLock()
	source = u.source
	u.mu.RUnlock()

	if source != "dbip" {
		t.Errorf("source = %q after clearing key, want dbip", source)
	}
}

func TestMMDBUpdater_StartStop(t *testing.T) {
	u, _ := newTestUpdater(t, "")

	// Double start should be safe.
	u.Start()
	u.Start()

	status := u.Status()
	if !status.Running {
		t.Error("should be running")
	}

	u.Stop()
	u.Stop() // Double stop should be safe.
}

func TestDecompressGzip(t *testing.T) {
	// Compress some test data.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write([]byte("hello world"))
	gw.Close()

	result, err := decompressGzip(buf.Bytes())
	if err != nil {
		t.Fatalf("decompressGzip: %v", err)
	}
	if string(result) != "hello world" {
		t.Errorf("result = %q, want 'hello world'", result)
	}
}

func TestDecompressGzip_Invalid(t *testing.T) {
	_, err := decompressGzip([]byte("not gzip data"))
	if err == nil {
		t.Error("expected error for invalid gzip")
	}
}

func TestExtractMMDB(t *testing.T) {
	// Build a tar.gz with a fake mmdb file inside.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := []byte("fake-mmdb-content")
	tw.WriteHeader(&tar.Header{
		Name:     "GeoLite2-ASN_20240101/GeoLite2-ASN.mmdb",
		Size:     int64(len(content)),
		Mode:     0644,
		Typeflag: tar.TypeReg,
	})
	tw.Write(content)
	tw.Close()
	gw.Close()

	result, err := extractMMDB(buf.Bytes(), "GeoLite2-ASN")
	if err != nil {
		t.Fatalf("extractMMDB: %v", err)
	}
	if string(result) != "fake-mmdb-content" {
		t.Errorf("result = %q", result)
	}
}

func TestExtractMMDB_NotFound(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	tw.Close()
	gw.Close()

	_, err := extractMMDB(buf.Bytes(), "GeoLite2-ASN")
	if err == nil {
		t.Error("expected error for missing mmdb in archive")
	}
}

func TestMMDBUpdater_LoadFromPath(t *testing.T) {
	u, dir := newTestUpdater(t, "")

	// Non-existent path should fail.
	if err := u.LoadFromPath("/nonexistent/path.mmdb"); err == nil {
		t.Error("expected error for missing file")
	}

	// Empty file should fail validation.
	emptyPath := filepath.Join(dir, "empty.mmdb")
	os.WriteFile(emptyPath, []byte{}, 0640)
	if err := u.LoadFromPath(emptyPath); err == nil {
		t.Error("expected error for empty mmdb")
	}
}

func TestMMDBUpdater_DownloadDBIP(t *testing.T) {
	// Set up a test HTTP server that serves a gzipped "mmdb".
	fakeMMDB := buildFakeMMDB()
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	gw.Write(fakeMMDB)
	gw.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(gzBuf.Bytes())
	}))
	defer srv.Close()

	store, _ := NewIOCStore(nil)
	dir := t.TempDir()
	u := &MMDBUpdater{
		dataDir:  dir,
		mmdbPath: filepath.Join(dir, "dbip-asn-lite.mmdb"),
		store:    store,
		source:   "dbip",
		client:   srv.Client(),
		stopCh:   make(chan struct{}),
	}

	// Override the URL by testing installMMDB directly since
	// we can't override the dbipASNURL const.
	err := u.installMMDB(fakeMMDB, "testhash123456789012")
	if err != nil {
		t.Fatalf("installMMDB: %v", err)
	}

	// File should exist.
	if _, err := os.Stat(u.mmdbPath); err != nil {
		t.Errorf("mmdb file not created: %v", err)
	}

	// Status should show available.
	u.running = true
	status := u.Status()
	if !status.Available {
		t.Error("should be available after install")
	}
}

// buildFakeMMDB creates a minimal valid mmdb file for testing.
// It has the metadata marker and basic structure.
func buildFakeMMDB() []byte {
	// Minimal mmdb: a few zero nodes + metadata.
	var buf bytes.Buffer

	// Write some tree nodes (24-bit record size, 1 node = 6 bytes).
	// Node 0: both records point to nodeCount (empty).
	nodeCount := uint32(1)
	buf.Write([]byte{0, 0, 1, 0, 0, 1}) // node 0: left=1, right=1

	// 16-byte null separator.
	buf.Write(make([]byte, 16))

	// Data section (empty).

	// Metadata marker.
	buf.Write([]byte("\xab\xcd\xefMaxMind.com"))

	// Metadata map with 2 entries: node_count and record_size.
	// Map type=7, size=2
	buf.WriteByte(7<<5 | 2)

	// Key: "node_count" (utf8_string type=2, len=10)
	buf.WriteByte(2<<5 | 10)
	buf.WriteString("node_count")
	// Value: uint32 type: extended type (0<<5 | size) then ext byte
	// For uint16 (type 5): ctrl = 0<<5 | size, ext = 5-7 = wait...
	// Actually for uint32 in mmdb: type 6, extended.
	// ctrl byte: typeNum=0 (extended), size=4 (4 bytes for uint32)
	buf.WriteByte(0<<5 | 4) // extended type, 4 bytes
	// Extended type byte: type 6 (uint32) = 6 - 7 = -1...
	// Actually extended types start at 8: ext_byte + 7 = actual_type
	// uint16=5 (not extended), uint32=6 (not extended)
	// Wait - types 1-7 use the 3-bit field directly. Let me use uint16 (type 5).
	// For type 6 (uint32): ctrl = 6<<5 | size
	buf.Bytes()[buf.Len()-1] = 6<<5 | 4 // type=6 (uint32), size=4
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(byte(nodeCount))

	// Key: "record_size" (utf8_string type=2, len=11)
	buf.WriteByte(2<<5 | 11)
	buf.WriteString("record_size")
	// Value: uint32 = 24
	buf.WriteByte(6<<5 | 1) // type=6, 1 byte
	buf.WriteByte(24)

	return buf.Bytes()
}
