package sync

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// EventUpdate represents a vault update event from the sync server.
type EventUpdate struct {
	VaultUUID string `json:"vault_uuid"`
	Seq       int64  `json:"seq"`
}

// ListenEvents connects to the sync server's SSE endpoint and listens for real-time vault updates and security alerts.
// Whenever a new update event is received, onUpdate is called with the remote seq.
// Whenever a security alert event is received, onAlert is called with the alert object.
func (c *Client) ListenEvents(ctx context.Context, onUpdate func(seq int64), onAlert func(alert SecurityAlert)) error {
	vaultUUIDBytes, err := c.store.ConfigGet("vault_uuid")
	if err != nil {
		return fmt.Errorf("get vault_uuid: %w", err)
	}
	vaultUUID := string(vaultUUIDBytes)

	url := fmt.Sprintf("%s/v1/vaults/%s/events", c.baseURL, vaultUUID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("connect to events: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("events endpoint returned status %d", resp.StatusCode)
	}

	reader := bufio.NewReader(resp.Body)
	var currentEvent string

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			currentEvent = ""
			continue
		}

		if strings.HasPrefix(line, "event:") {
			currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			switch currentEvent {
			case "vault_updated":
				var evt EventUpdate
				if err := json.Unmarshal([]byte(data), &evt); err == nil {
					if onUpdate != nil {
						onUpdate(evt.Seq)
					}
				}
			case "security_alert":
				var alert SecurityAlert
				if err := json.Unmarshal([]byte(data), &alert); err == nil {
					if onAlert != nil {
						onAlert(alert)
					}
				}
			}
		}
	}
}

// WatchAndSync runs an event listener loop with automatic reconnection and auto-pulls changes when notified.
func (c *Client) WatchAndSync(ctx context.Context, onSyncCompleted func(seq int64, err error)) {
	c.WatchAndSyncWithAlerts(ctx, onSyncCompleted, nil)
}

// WatchAndSyncWithAlerts runs an event listener loop with automatic reconnection, auto-pulls changes and handles security alerts.
func (c *Client) WatchAndSyncWithAlerts(ctx context.Context, onSyncCompleted func(seq int64, err error), onAlert func(alert SecurityAlert)) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := c.ListenEvents(ctx, func(remoteSeq int64) {
			// Auto pull & merge
			_, pullErr := c.Pull()
			if onSyncCompleted != nil {
				onSyncCompleted(remoteSeq, pullErr)
			}
		}, onAlert)

		if ctx.Err() != nil {
			return
		}

		// Reconnection backoff on network/server drop
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
	}
}
