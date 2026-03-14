package inspect

import (
	"testing"
)

func TestFingerprintBanner_SSH(t *testing.T) {
	e := NewEngine(nil)

	banner := &Banner{
		Type:     BannerTypeSSH,
		Value:    "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
		Software: "OpenSSH_9.6p1",
		SrcIP:    "10.0.0.1",
	}

	fp, err := e.FingerprintBanner(banner)
	if err != nil {
		t.Fatalf("FingerprintBanner: %v", err)
	}
	if fp.Hash == "" {
		t.Error("hash should not be empty")
	}
	if fp.Type != BannerTypeSSH {
		t.Errorf("type = %q, want ssh", fp.Type)
	}
	if fp.Software != "OpenSSH_9.6p1" {
		t.Errorf("software = %q", fp.Software)
	}
}

func TestFingerprintBanner_HTTP(t *testing.T) {
	e := NewEngine(nil)

	banner := &Banner{
		Type:     BannerTypeHTTP,
		Value:    "nginx/1.24.0",
		Software: "nginx/1.24.0",
		SrcIP:    "10.0.0.1",
	}

	fp, err := e.FingerprintBanner(banner)
	if err != nil {
		t.Fatalf("FingerprintBanner: %v", err)
	}
	if fp.Hash == "" {
		t.Error("hash should not be empty")
	}
}

func TestFingerprintBanner_Nil(t *testing.T) {
	e := NewEngine(nil)
	_, err := e.FingerprintBanner(nil)
	if err == nil {
		t.Error("expected error for nil")
	}
	_, err = e.FingerprintBanner(&Banner{})
	if err == nil {
		t.Error("expected error for empty banner")
	}
}

func TestParseHTTPServerBanner(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantNil  bool
		wantSoft string
	}{
		{"nginx", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n", false, "nginx/1.24.0"},
		{"apache", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n\r\n", false, "Apache/2.4.52"},
		{"no server", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n", true, ""},
		{"not http", "GET / HTTP/1.1\r\n", true, ""},
	}

	for _, tt := range tests {
		b := ParseHTTPServerBanner([]byte(tt.input))
		if tt.wantNil {
			if b != nil {
				t.Errorf("%s: expected nil, got %+v", tt.name, b)
			}
			continue
		}
		if b == nil {
			t.Errorf("%s: expected banner, got nil", tt.name)
			continue
		}
		if b.Software != tt.wantSoft {
			t.Errorf("%s: software = %q, want %q", tt.name, b.Software, tt.wantSoft)
		}
	}
}

func TestParseSMTPBanner(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantNil bool
		wantSW  string
	}{
		{"postfix", "220 mail.example.com ESMTP Postfix\r\n", false, "Postfix"},
		{"no software", "220 mx.google.com ESMTP\r\n", false, "ESMTP"},
		{"not smtp", "250 OK\r\n", true, ""},
	}

	for _, tt := range tests {
		b := ParseSMTPBanner([]byte(tt.input))
		if tt.wantNil {
			if b != nil {
				t.Errorf("%s: expected nil, got %+v", tt.name, b)
			}
			continue
		}
		if b == nil {
			t.Errorf("%s: expected banner, got nil", tt.name)
			continue
		}
		if b.Software != tt.wantSW {
			t.Errorf("%s: software = %q, want %q", tt.name, b.Software, tt.wantSW)
		}
	}
}
