package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	c := NewClient("http://localhost:8080", "test-key")
	if c.BaseURL != "http://localhost:8080" {
		t.Errorf("expected BaseURL http://localhost:8080, got %s", c.BaseURL)
	}
	if c.APIKey != "test-key" {
		t.Errorf("expected APIKey test-key, got %s", c.APIKey)
	}
	if c.HTTPClient == nil {
		t.Fatal("HTTPClient is nil")
	}
}

func TestGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/status" {
			t.Errorf("expected /api/v1/status, got %s", r.URL.Path)
		}
		if r.Header.Get("X-API-Key") != "my-key" {
			t.Errorf("expected API key header my-key, got %s", r.Header.Get("X-API-Key"))
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "my-key")
	data, err := c.Get("/api/v1/status")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	var resp map[string]string
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %s", resp["status"])
	}
}

func TestGetError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "")
	_, err := c.Get("/api/v1/zones/bogus")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestPost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["name"] != "test-zone" {
			t.Errorf("expected name test-zone, got %s", body["name"])
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "created"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "")
	data, err := c.Post("/api/v1/zones", map[string]string{"name": "test-zone"})
	if err != nil {
		t.Fatalf("Post failed: %v", err)
	}
	var resp map[string]string
	json.Unmarshal(data, &resp)
	if resp["status"] != "created" {
		t.Errorf("expected status created, got %s", resp["status"])
	}
}

func TestPut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "")
	data, err := c.Put("/api/v1/zones/test", map[string]string{"name": "test"})
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	var resp map[string]string
	json.Unmarshal(data, &resp)
	if resp["status"] != "updated" {
		t.Errorf("expected status updated, got %s", resp["status"])
	}
}

func TestDelete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "")
	data, err := c.Delete("/api/v1/zones/test", nil)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	var resp map[string]string
	json.Unmarshal(data, &resp)
	if resp["status"] != "deleted" {
		t.Errorf("expected status deleted, got %s", resp["status"])
	}
}

func TestGetNoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "" {
			t.Error("expected no API key header when key is empty")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "")
	_, err := c.Get("/api/v1/status")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
}

func TestPostError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "already exists"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "")
	_, err := c.Post("/api/v1/zones", map[string]string{"name": "dup"})
	if err == nil {
		t.Fatal("expected error for 409 response")
	}
}

func TestConnectionError(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", "")
	_, err := c.Get("/api/v1/status")
	if err == nil {
		t.Fatal("expected connection error")
	}
}
