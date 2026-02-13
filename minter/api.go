package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type TagRegistration struct {
	UID       string `json:"uid"`
	HatName   string `json:"hat_name"`
	HatColor  string `json:"hat_color"`
	HatSKU    string `json:"hat_sku,omitempty"`
	BatchID   string `json:"batch_id,omitempty"`
	ScanCount int    `json:"scan_count,omitempty"`
	Notes     string `json:"notes,omitempty"`
}

func registerTag(endpoint, cfClientID, cfClientSecret string, reg TagRegistration) error {
	payload, err := json.Marshal(reg)
	if err != nil {
		return fmt.Errorf("marshal registration: %w", err)
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("CF-Access-Client-Id", cfClientID)
	req.Header.Set("CF-Access-Client-Secret", cfClientSecret)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API returned non-2xx status: %d %s", resp.StatusCode, resp.Status)
	}

	return nil
}
