package sync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/raynosc/vlt/internal/version"
)

// Heartbeat registers or updates the client device presence on the sync server.
func (c *Client) Heartbeat() error {
	vaultUUID, err := c.store.ConfigGet("vault_uuid")
	if err != nil {
		return fmt.Errorf("get vault_uuid: %w", err)
	}

	deviceIDBytes, err := c.store.ConfigGet("device_id")
	var deviceID string
	if err != nil || len(deviceIDBytes) == 0 {
		// Generate random device ID
		deviceID = fmt.Sprintf("dev_%d", time.Now().UnixNano())
		_ = c.store.ConfigSet("device_id", []byte(deviceID))
	} else {
		deviceID = string(deviceIDBytes)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = runtime.GOOS + "-device"
	}

	reqBody := HeartbeatRequest{
		DeviceID:      deviceID,
		Hostname:      hostname,
		ClientVersion: version.Version,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal heartbeat: %w", err)
	}

	url := fmt.Sprintf("%s/v1/vaults/%s/devices/heartbeat", c.baseURL, string(vaultUUID))
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create heartbeat request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("send heartbeat: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("heartbeat failed (%d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// ListDevices returns all connected devices for the current vault.
func (c *Client) ListDevices() ([]DeviceInfo, error) {
	vaultUUID, err := c.store.ConfigGet("vault_uuid")
	if err != nil {
		return nil, fmt.Errorf("get vault_uuid: %w", err)
	}

	url := fmt.Sprintf("%s/v1/vaults/%s/devices", c.baseURL, string(vaultUUID))
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create list devices request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get devices: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list devices failed (%d): %s", resp.StatusCode, string(body))
	}

	var devices []DeviceInfo
	if err := json.NewDecoder(resp.Body).Decode(&devices); err != nil {
		return nil, fmt.Errorf("decode devices: %w", err)
	}

	return devices, nil
}

// RevokeDevice revokes a device's access to the sync server.
func (c *Client) RevokeDevice(deviceID string) error {
	vaultUUID, err := c.store.ConfigGet("vault_uuid")
	if err != nil {
		return fmt.Errorf("get vault_uuid: %w", err)
	}

	url := fmt.Sprintf("%s/v1/vaults/%s/devices/%s/revoke", c.baseURL, string(vaultUUID), deviceID)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return fmt.Errorf("create revoke device request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revoke device failed (%d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// PublishSecurityAlert broadcasts a security alert event to all peer devices.
func (c *Client) PublishSecurityAlert(severity, reason string) error {
	vaultUUID, err := c.store.ConfigGet("vault_uuid")
	if err != nil {
		return fmt.Errorf("get vault_uuid: %w", err)
	}

	deviceIDBytes, _ := c.store.ConfigGet("device_id")
	deviceID := string(deviceIDBytes)
	if deviceID == "" {
		deviceID = fmt.Sprintf("dev_%d", time.Now().UnixNano())
	}

	hostname, _ := os.Hostname()

	alert := SecurityAlert{
		EventID:   fmt.Sprintf("evt_%d", time.Now().UnixNano()),
		VaultUUID: string(vaultUUID),
		EventType: "security_alert",
		Severity:  severity,
		Reason:    reason,
		Device: DeviceInfo{
			DeviceID:      deviceID,
			Hostname:      hostname,
			ClientVersion: version.Version,
		},
		Timestamp: time.Now().UTC(),
	}

	data, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("marshal alert: %w", err)
	}

	url := fmt.Sprintf("%s/v1/vaults/%s/alerts", c.baseURL, string(vaultUUID))
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create alert request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("send alert: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("publish alert failed (%d): %s", resp.StatusCode, string(body))
	}

	return nil
}
