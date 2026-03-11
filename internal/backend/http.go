package backend

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"
)

// GoHTTPClient implements HTTPClient using net/http.
// Replaces all exec.Command("curl", ...) calls in the codebase.
type GoHTTPClient struct {
	client *http.Client
}

// NewHTTPClient creates a new HTTP client with sensible defaults.
func NewHTTPClient() *GoHTTPClient {
	return &GoHTTPClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Get performs an HTTP GET request.
func (c *GoHTTPClient) Get(url string, headers map[string]string, timeoutSec int) ([]byte, int, error) {
	return c.do("GET", url, nil, headers, timeoutSec)
}

// Put performs an HTTP PUT request.
func (c *GoHTTPClient) Put(url string, body []byte, headers map[string]string, timeoutSec int) ([]byte, int, error) {
	return c.do("PUT", url, body, headers, timeoutSec)
}

// Post performs an HTTP POST request.
func (c *GoHTTPClient) Post(url string, body []byte, headers map[string]string, timeoutSec int) ([]byte, int, error) {
	return c.do("POST", url, body, headers, timeoutSec)
}

func (c *GoHTTPClient) do(method, url string, body []byte, headers map[string]string, timeoutSec int) ([]byte, int, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Use per-request timeout if specified.
	client := c.client
	if timeoutSec > 0 {
		client = &http.Client{
			Timeout:   time.Duration(timeoutSec) * time.Second,
			Transport: c.client.Transport,
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%s %s: %w", method, url, err)
	}
	defer resp.Body.Close()

	// Limit response body to 10MB to prevent OOM.
	const maxBody = 10 << 20
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}
