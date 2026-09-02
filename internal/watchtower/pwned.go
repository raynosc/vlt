package watchtower

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/raynosc/vlt/internal/crypto"
)

const (
	// DefaultHIBPBaseURL is the official Pwned Passwords range API endpoint.
	DefaultHIBPBaseURL = "https://api.pwnedpasswords.com"
	// DefaultPwnedTimeout is the default HTTP client timeout (fast fail).
	DefaultPwnedTimeout = 2 * time.Second
	// DefaultPwnedCooldown is the default cooldown duration after network failure.
	DefaultPwnedCooldown = 1 * time.Hour
)

var (
	// ErrOfflineCooldown is returned when network check is skipped due to active cooldown.
	ErrOfflineCooldown = errors.New("pwned passwords check skipped (offline backoff cooldown active)")
	// ErrOfflineDisabled is returned when the external API check is explicitly disabled.
	ErrOfflineDisabled = errors.New("pwned passwords check is disabled")
)

// PwnedOption configures a PwnedClient.
type PwnedOption func(*PwnedClient)

// WithBaseURL overrides the default HIBP API base URL (useful for testing).
func WithBaseURL(baseURL string) PwnedOption {
	return func(c *PwnedClient) {
		c.baseURL = strings.TrimRight(baseURL, "/")
	}
}

// WithTimeout sets a custom HTTP timeout.
func WithTimeout(timeout time.Duration) PwnedOption {
	return func(c *PwnedClient) {
		c.httpClient.Timeout = timeout
	}
}

// PwnedClient performs zero-knowledge k-Anonymity checks against the Pwned Passwords API.
type PwnedClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewPwnedClient initializes a new HIBP client with options.
func NewPwnedClient(opts ...PwnedOption) *PwnedClient {
	c := &PwnedClient{
		baseURL: DefaultHIBPBaseURL,
		httpClient: &http.Client{
			Timeout: DefaultPwnedTimeout,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// hashPassword calculates SHA-1 of password and returns uppercase hex.
// SHA-1 is strictly required by the Have I Been Pwned API contract.
// Memory is cleared after calculation.
func hashPassword(password string) (prefix string, suffix string) {
	// #nosec G401 -- SHA-1 is mandated by the HIBP Pwned Passwords range API contract
	hasher := sha1.New()
	pwBytes := []byte(password)
	hasher.Write(pwBytes)
	crypto.Zeroize(pwBytes)

	fullHash := strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))
	return fullHash[:5], fullHash[5:]
}

// CheckPassword queries HIBP using the 5-character prefix and checks if suffix matches.
// Returns the breach count (0 if not compromised).
func (c *PwnedClient) CheckPassword(password string) (int, error) {
	prefix, suffix := hashPassword(password)
	url := fmt.Sprintf("%s/range/%s", c.baseURL, prefix)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "vlt-secrets-manager")
	req.Header.Set("Add-Padding", "true") // Cloudflare padding against response length side-channel

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("hibp returned status: %d", resp.StatusCode)
	}

	return parseHIBPResponse(resp.Body, suffix)
}

// parseHIBPResponse parses the range response stream searching for the target suffix.
func parseHIBPResponse(r io.Reader, targetSuffix string) (int, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(parts[0], targetSuffix) {
			count, err := strconv.Atoi(parts[1])
			if err != nil {
				return 0, fmt.Errorf("parse count: %w", err)
			}
			return count, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read response: %w", err)
	}
	return 0, nil
}

// PwnedManager wraps PwnedClient with offline detection and backoff cooldown.
type PwnedManager struct {
	mu         sync.RWMutex
	client     *PwnedClient
	cooldown   time.Duration
	lastFailed time.Time
	disabled   bool
}

// NewPwnedManager creates a manager managing HIBP checks and offline backoff.
func NewPwnedManager(cooldown time.Duration, opts ...PwnedOption) *PwnedManager {
	if cooldown <= 0 {
		cooldown = DefaultPwnedCooldown
	}
	return &PwnedManager{
		client:   NewPwnedClient(opts...),
		cooldown: cooldown,
	}
}

// SetDisabled enables or disables external network queries.
func (m *PwnedManager) SetDisabled(disabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disabled = disabled
}

// SetCooldown updates the offline backoff cooldown duration.
func (m *PwnedManager) SetCooldown(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cooldown = d
}

// SetLastFailedAttempt manually sets the last failed attempt time (for testing/restoring state).
func (m *PwnedManager) SetLastFailedAttempt(t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastFailed = t
}

// ShouldAttempt returns true if the manager is enabled and not within a backoff cooldown window.
func (m *PwnedManager) ShouldAttempt() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.disabled {
		return false
	}
	if m.lastFailed.IsZero() {
		return true
	}
	return time.Since(m.lastFailed) >= m.cooldown
}

// RemainingCooldown returns the remaining duration before another network attempt is allowed.
func (m *PwnedManager) RemainingCooldown() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.disabled || m.lastFailed.IsZero() {
		return 0
	}
	elapsed := time.Since(m.lastFailed)
	if elapsed >= m.cooldown {
		return 0
	}
	return m.cooldown - elapsed
}

// RecordFailure marks a network failure and starts cooldown.
func (m *PwnedManager) RecordFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastFailed = time.Now()
}

// RecordSuccess clears the failure timestamp upon successful network check.
func (m *PwnedManager) RecordSuccess() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastFailed = time.Time{}
}

// CheckBatch checks a list of passwords against HIBP, grouping by 5-char prefix to minimize HTTP calls.
func (m *PwnedManager) CheckBatch(passwords []string) (map[string]int, error) {
	if !m.ShouldAttempt() {
		m.mu.RLock()
		disabled := m.disabled
		m.mu.RUnlock()
		if disabled {
			return map[string]int{}, ErrOfflineDisabled
		}
		return map[string]int{}, ErrOfflineCooldown
	}

	results := make(map[string]int)
	var mu sync.Mutex
	// Group passwords by their 5-character prefix
	type pwRef struct {
		original string
		suffix   string
	}
	prefixMap := make(map[string][]pwRef)

	for _, pw := range passwords {
		if pw == "" {
			continue
		}
		prefix, suffix := hashPassword(pw)
		prefixMap[prefix] = append(prefixMap[prefix], pwRef{original: pw, suffix: suffix})
	}

	if len(prefixMap) == 0 {
		return results, nil
	}

	// Concurrency limit: max 8 parallel network requests
	maxWorkers := 8
	if len(prefixMap) < maxWorkers {
		maxWorkers = len(prefixMap)
	}
	sem := make(chan struct{}, maxWorkers)

	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once

	for prefix, refs := range prefixMap {
		wg.Add(1)
		go func(p string, r []pwRef) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			url := fmt.Sprintf("%s/range/%s", m.client.baseURL, p)
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				errOnce.Do(func() { firstErr = err })
				return
			}
			req.Header.Set("User-Agent", "vlt-secrets-manager")
			req.Header.Set("Add-Padding", "true")

			resp, err := m.client.httpClient.Do(req)
			if err != nil {
				errOnce.Do(func() { firstErr = err })
				return
			}

			if resp.StatusCode != http.StatusOK {
				_ = resp.Body.Close()
				errOnce.Do(func() { firstErr = fmt.Errorf("hibp returned status: %d", resp.StatusCode) })
				return
			}

			bodyBytes, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				errOnce.Do(func() { firstErr = err })
				return
			}

			for _, ref := range r {
				count, _ := parseHIBPResponse(strings.NewReader(string(bodyBytes)), ref.suffix)
				if count > 0 {
					mu.Lock()
					results[ref.original] = count
					mu.Unlock()
				}
			}
		}(prefix, refs)
	}

	wg.Wait()

	if firstErr != nil {
		m.RecordFailure()
		return results, firstErr
	}

	m.RecordSuccess()
	return results, nil
}
