package cli

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	// Well-known paths for TLS auto-detection.
	defaultTLSCertPath = "/etc/gatekeeper/tls/server.crt"
	defaultListenPort  = "8080"
)

// Client is the API client used by the CLI.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// NewClient creates a new CLI API client.
// If baseURL is empty, auto-detects HTTP vs HTTPS by checking for the
// well-known TLS certificate path.
func NewClient(baseURL, apiKey string) *Client {
	if baseURL == "" {
		baseURL = ResolveAPIURL()
	}
	return &Client{
		BaseURL:    baseURL,
		APIKey:     apiKey,
		HTTPClient: newHTTPClient(),
	}
}

// ResolveAPIURL returns the appropriate base URL for the API.
// If GK_API_URL is set, it is returned as-is.
// Otherwise, checks for the well-known TLS cert: if present, returns
// https://localhost:8080; if absent, returns http://localhost:8080.
func ResolveAPIURL() string {
	if u := os.Getenv("GK_API_URL"); u != "" {
		return u
	}
	if _, err := os.Stat(defaultTLSCertPath); err == nil {
		return "https://localhost:" + defaultListenPort
	}
	return "http://localhost:" + defaultListenPort
}

// newHTTPClient creates an http.Client that trusts the gatekeeper
// self-signed certificate if it exists at the well-known path.
func newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if certPEM, err := os.ReadFile(defaultTLSCertPath); err == nil {
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM(certPEM)
		transport.TLSClientConfig = &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

func (c *Client) do(method, path string, body any) ([]byte, int, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("X-API-Key", c.APIKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB limit
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return data, resp.StatusCode, nil
}

// Get sends a GET request.
func (c *Client) Get(path string) ([]byte, error) {
	data, status, err := c.do("GET", path, nil)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", status, string(data))
	}
	return data, nil
}

// Post sends a POST request.
func (c *Client) Post(path string, body any) ([]byte, error) {
	data, status, err := c.do("POST", path, body)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", status, string(data))
	}
	return data, nil
}

// Put sends a PUT request.
func (c *Client) Put(path string, body any) ([]byte, error) {
	data, status, err := c.do("PUT", path, body)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", status, string(data))
	}
	return data, nil
}

// Delete sends a DELETE request.
func (c *Client) Delete(path string, body any) ([]byte, error) {
	data, status, err := c.do("DELETE", path, body)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", status, string(data))
	}
	return data, nil
}
