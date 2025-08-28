package xxe

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPayloadDelivery(t *testing.T) {
	expectedPayload := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}
		if string(body) != expectedPayload {
			t.Errorf("Expected payload %q, got %q", expectedPayload, string(body))
		}
		fmt.Fprintln(w, "some response")
	}))
	defer server.Close()

	ScanURL(server.URL)
}

func TestResponseAnalysis_Vulnerable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "root:x:0:0:")
	}))
	defer server.Close()

	vulnerable, err := ScanURL(server.URL)
	if err != nil {
		t.Fatalf("ScanURL returned an error: %v", err)
	}

	if !vulnerable {
		t.Error("ScanURL returned false for a vulnerable target")
	}
}

func TestResponseAnalysis_NotVulnerable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "some other response")
	}))
	defer server.Close()

	vulnerable, err := ScanURL(server.URL)
	if err != nil {
		t.Fatalf("ScanURL returned an error: %v", err)
	}

	if vulnerable {
		t.Error("ScanURL returned true for a non-vulnerable target")
	}
}
