// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestObservabilityListenAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		address  string
		expected string
	}{
		{name: "empty", address: "", expected: "127.0.0.1"},
		{name: "whitespace", address: "  ", expected: "127.0.0.1"},
		{name: "explicit", address: "0.0.0.0", expected: "0.0.0.0"},
		{name: "ipv6", address: "::1", expected: "::1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := observabilityListenAddress(test.address); actual != test.expected {
				t.Fatalf("observabilityListenAddress(%q) = %q, want %q", test.address, actual, test.expected)
			}
		})
	}

	if actual := httpListenAddress("::1", 8081); actual != "[::1]:8081" {
		t.Fatalf("httpListenAddress() = %q, want %q", actual, "[::1]:8081")
	}
}

func TestNewHTTPServerTimeouts(t *testing.T) {
	t.Parallel()

	server := newHTTPServer("127.0.0.1:8081", http.NewServeMux())
	if server.ReadHeaderTimeout != httpReadHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout = %s, want %s", server.ReadHeaderTimeout, httpReadHeaderTimeout)
	}
	if server.ReadTimeout != httpReadTimeout {
		t.Fatalf("ReadTimeout = %s, want %s", server.ReadTimeout, httpReadTimeout)
	}
	if server.WriteTimeout != httpWriteTimeout {
		t.Fatalf("WriteTimeout = %s, want %s", server.WriteTimeout, httpWriteTimeout)
	}
	if server.IdleTimeout != httpIdleTimeout {
		t.Fatalf("IdleTimeout = %s, want %s", server.IdleTimeout, httpIdleTimeout)
	}
	if server.MaxHeaderBytes != maxHTTPHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d, want %d", server.MaxHeaderBytes, maxHTTPHeaderBytes)
	}
}

func TestRuntimeStatusHandlers(t *testing.T) {
	t.Parallel()

	status := &runtimeStatus{}
	mux := newMetricsMux(status)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("initial readiness status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}

	status.setReady(true)
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("ready status = %d, want %d", response.Code, http.StatusOK)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ready\n" {
		t.Fatalf("ready body = %q, want %q", body, "ready\n")
	}

	response = httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", response.Code, http.StatusOK)
	}

}
