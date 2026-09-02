package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/notify"
	"github.com/raynosc/vlt/internal/sync"
	"github.com/raynosc/vlt/internal/syncserver"
)

// newSyncCmd creates the `vlt sync` command group.
func newSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Manage vault synchronization",
		Long: `Synchronize the vault with a remote sync server.
Supports push, pull, status, and init operations.`,
	}

	cmd.AddCommand(newSyncInitCmd())
	cmd.AddCommand(newSyncPushCmd())
	cmd.AddCommand(newSyncPullCmd())
	cmd.AddCommand(newSyncStatusCmd())
	cmd.AddCommand(newSyncShowKeyCmd())
	cmd.AddCommand(newSyncListenCmd())

	return cmd
}

// maskKey masks an API key, showing only the last 4 characters.
func maskKey(key string) string {
	if len(key) <= 4 {
		return key
	}
	return strings.Repeat("*", len(key)-4) + key[len(key)-4:]
}

func newSyncInitCmd() *cobra.Command {
	var serverURL string

	cmd := &cobra.Command{
		Use:   "init --server <url>",
		Short: "Initialize sync configuration",
		Long: `Configure the vault for synchronization with a remote sync server.
Generates a vault UUID, sync encryption key, and API key.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSyncInit(cmd, serverURL)
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", "", "Sync server URL (required)")
	cmd.Flags().Bool("insecure", false, "allow HTTP or untrusted HTTPS sync server URLs")
	_ = cmd.MarkFlagRequired("server")

	return cmd
}

func newSyncPushCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "push",
		Short: "Push local changes to sync server",
		Long:  `Upload encrypted vault snapshot to the sync server.`,
		Args:  cobra.NoArgs,
		RunE:  runSyncPush,
	}
	cmd.Flags().Bool("insecure", false, "allow HTTP sync server URLs (insecure)")
	return cmd
}

func newSyncPullCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Pull remote changes from sync server",
		Long:  `Download and merge remote changes from the sync server.`,
		Args:  cobra.NoArgs,
		RunE:  runSyncPull,
	}
	cmd.Flags().Bool("insecure", false, "allow HTTP sync server URLs (insecure)")
	return cmd
}

func newSyncStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show sync status",
		Long:  `Display the current synchronization state of the vault.`,
		Args:  cobra.NoArgs,
		RunE:  runSyncStatus,
	}
	cmd.Flags().Bool("insecure", false, "allow HTTP sync server URLs (insecure)")
	return cmd
}

func newSyncShowKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show-key",
		Short: "Display the sync API key",
		Long:  `Show the masked API key for the configured sync server.`,
		Args:  cobra.NoArgs,
		RunE:  runSyncShowKey,
	}
}

func runSyncInit(cmd *cobra.Command, serverURL string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("resolve vault: %w", err)
	}

	// S-01: storing sensitive sync config in plaintext was the original bug.
	// Now we require the vault to be unlocked so we can wrap api_key and
	// sync_encryption_key with the master key before writing them to disk.
	s, masterKey, err := unlockVault(vaultPath)
	if err != nil {
		return fmt.Errorf("unlock vault: %w", err)
	}
	defer func() {
		crypto.Zeroize(masterKey)
		_ = s.Close()
	}()

	// Generate vault UUID
	vaultUUID, err := newUUID()
	if err != nil {
		return fmt.Errorf("generate vault uuid: %w", err)
	}

	// Generate sync encryption key (32 bytes for AES-256)
	syncKey := make([]byte, 32)
	if _, err := rand.Read(syncKey); err != nil {
		return fmt.Errorf("generate sync key: %w", err)
	}
	defer crypto.Zeroize(syncKey)

	// Generate API key (32 bytes random)
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		return fmt.Errorf("generate api key: %w", err)
	}
	defer crypto.Zeroize(rawKey)

	// SHA-256 hash the API key for server registration
	keyHash := sha256.Sum256(rawKey)
	hexKey := hex.EncodeToString(rawKey)

	// Register with the sync server
	registered := false
	var registrationSeq int64
	if serverURL != "" {
		registerReq := sync.RegisterRequest{
			VaultUUID: vaultUUID,
			KeyHash:   keyHash[:],
		}
		body, _ := json.Marshal(registerReq)

		insecure, _ := cmd.Flags().GetBool("insecure")
		tlsConfig := &tls.Config{InsecureSkipVerify: insecure}
		if caPath := os.Getenv("VLT_SYNC_CA_CERT"); caPath != "" {
			if caData, err := os.ReadFile(caPath); err == nil {
				pool, _ := x509.SystemCertPool()
				if pool == nil {
					pool = x509.NewCertPool()
				}
				pool.AppendCertsFromPEM(caData)
				tlsConfig.RootCAs = pool
			}
		}

		httpClient := &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
			Timeout:   30 * time.Second,
		}

		resp, err := httpClient.Post(
			serverURL+syncserver.RouteRegister,
			"application/json",
			bytes.NewReader(body),
		)
		if err == nil {
			if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
				registered = true
				// F1/F2: capture the server's current seq as the registration anchor.
				var regResp sync.RegisterResponse
				if decErr := json.NewDecoder(resp.Body).Decode(&regResp); decErr == nil {
					registrationSeq = regResp.VaultSeq
				}
			}
			_ = resp.Body.Close()
		}
	}

	// S-01: wrap sensitive values with the master key before persisting.
	wrappedAPI, err := sync.WrapConfigValue("api_key", []byte(hexKey), masterKey)
	if err != nil {
		return fmt.Errorf("wrap api key: %w", err)
	}
	wrappedSync, err := sync.WrapConfigValue("sync_encryption_key", syncKey, masterKey)
	if err != nil {
		return fmt.Errorf("wrap sync key: %w", err)
	}

	// Store config
	if err := s.ConfigSet("vault_uuid", []byte(vaultUUID)); err != nil {
		return fmt.Errorf("store vault uuid: %w", err)
	}
	if err := s.ConfigSet("sync_server_url", []byte(serverURL)); err != nil {
		return fmt.Errorf("store server url: %w", err)
	}
	if err := s.ConfigSet("api_key", wrappedAPI); err != nil {
		return fmt.Errorf("store api key: %w", err)
	}
	if err := s.ConfigSet("sync_encryption_key", wrappedSync); err != nil {
		return fmt.Errorf("store encryption key: %w", err)
	}
	if err := s.ConfigSet("last_sync_seq", []byte("0")); err != nil {
		return fmt.Errorf("store sync seq: %w", err)
	}
	// F1/F2: persist registration_seq so future pulls can reject rollbacks.
	regSeqStr := fmt.Sprintf("%d", registrationSeq)
	if err := s.ConfigSet("registration_seq", []byte(regSeqStr)); err != nil {
		return fmt.Errorf("store registration seq: %w", err)
	}
	// F3 (ADR-9): a freshly-initialized vault is born in the new format — both
	// api_key and sync_encryption_key are wrapped with key-specific AAD from the start.
	if err := s.ConfigSet("config_format_version", []byte("2")); err != nil {
		return fmt.Errorf("store config format version: %w", err)
	}

	if jsonOutput {
		output := map[string]interface{}{
			"status":     "configured",
			"vault_uuid": vaultUUID,
			"server_url": serverURL,
			"api_key":    maskKey(hexKey),
			"registered": registered,
		}
		data, _ := json.Marshal(output)
		fmt.Println(string(data))
		return nil
	}

	fmt.Fprintf(os.Stderr, "✅ Sync configured for vault: %s\n", vaultUUID)
	fmt.Fprintf(os.Stderr, "   Server: %s\n", serverURL)
	fmt.Fprintf(os.Stderr, "   API Key: %s\n", maskKey(hexKey))
	if !registered {
		fmt.Fprintf(os.Stderr, "   ⚠️  Server registration failed — server may be unreachable. Run 'vlt sync push' to retry.\n")
	} else {
		fmt.Fprintf(os.Stderr, "   ✅ Registered with sync server\n")
	}

	return nil
}

func runSyncPush(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")
	insecure, _ := cmd.Flags().GetBool("insecure")

	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("resolve vault: %w", err)
	}

	s, key, err := unlockVault(vaultPath)
	if err != nil {
		return fmt.Errorf("unlock vault: %w", err)
	}
	defer func() {
		crypto.Zeroize(key)
		_ = s.Close()
	}()

	var client *sync.Client
	if insecure {
		client, err = sync.NewClientInsecure(s, key)
	} else {
		client, err = sync.NewClient(s, key)
	}
	if err != nil {
		return fmt.Errorf("create sync client: %w", err)
	}

	seq, err := client.Push()
	if err != nil {
		return fmt.Errorf("sync push: %w", err)
	}

	if jsonOutput {
		output := map[string]interface{}{
			"status": "ok",
			"seq":    seq,
		}
		data, _ := json.Marshal(output)
		fmt.Println(string(data))
		return nil
	}

	fmt.Fprintf(os.Stderr, "✅ Pushed to server (seq %d)\n", seq)
	return nil
}

func runSyncPull(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")
	insecure, _ := cmd.Flags().GetBool("insecure")

	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("resolve vault: %w", err)
	}

	s, key, err := unlockVault(vaultPath)
	if err != nil {
		return fmt.Errorf("unlock vault: %w", err)
	}
	defer func() {
		crypto.Zeroize(key)
		_ = s.Close()
	}()

	var client *sync.Client
	if insecure {
		client, err = sync.NewClientInsecure(s, key)
	} else {
		client, err = sync.NewClient(s, key)
	}
	if err != nil {
		return fmt.Errorf("create sync client: %w", err)
	}

	conflicts, err := client.Pull()
	if err != nil {
		return fmt.Errorf("sync pull: %w", err)
	}

	if jsonOutput {
		output := map[string]interface{}{
			"status":    "ok",
			"conflicts": len(conflicts),
		}
		data, _ := json.Marshal(output)
		fmt.Println(string(data))
		return nil
	}

	if len(conflicts) > 0 {
		fmt.Fprintf(os.Stderr, "⚠️  Pulled with %d conflict(s)\n", len(conflicts))
		for _, c := range conflicts {
			fmt.Fprintf(os.Stderr, "   - %s: %s\n", c.Name, c.Resolved)
		}
	} else {
		fmt.Fprintln(os.Stderr, "✅ Pulled from server (no conflicts)")
	}
	return nil
}

func runSyncStatus(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")
	_, _ = cmd.Flags().GetBool("insecure") // flag exists for consistency; not used here

	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("resolve vault: %w", err)
	}

	// Open without unlock (just read config)
	s, err := openStore(vaultPath)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}
	defer func() { _ = s.Close() }()

	serverURL, err := s.ConfigGet("sync_server_url")
	if err != nil {
		return fmt.Errorf("sync not configured: run 'vlt sync init --server <url>' first")
	}

	vaultUUID, _ := s.ConfigGet("vault_uuid")
	lastSeq, _ := s.ConfigGet("last_sync_seq")

	// Count secrets
	secrets, _ := s.List()

	if jsonOutput {
		output := map[string]interface{}{
			"server_url":   string(serverURL),
			"vault_uuid":   string(vaultUUID),
			"last_seq":     string(lastSeq),
			"secret_count": len(secrets),
		}
		data, _ := json.Marshal(output)
		fmt.Println(string(data))
		return nil
	}

	fmt.Fprintf(os.Stderr, "Sync Configuration:\n")
	fmt.Fprintf(os.Stderr, "  Server:   %s\n", string(serverURL))
	fmt.Fprintf(os.Stderr, "  Vault ID: %s\n", string(vaultUUID))
	fmt.Fprintf(os.Stderr, "  Last Seq: %s\n", string(lastSeq))
	fmt.Fprintf(os.Stderr, "  Secrets:  %d\n", len(secrets))

	return nil
}

func runSyncShowKey(cmd *cobra.Command, args []string) error {
	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("resolve vault: %w", err)
	}

	// S-01: api_key is encrypted with the master key, so we need to unlock.
	s, key, err := unlockVault(vaultPath)
	if err != nil {
		return fmt.Errorf("unlock vault: %w", err)
	}
	defer func() {
		crypto.Zeroize(key)
		_ = s.Close()
	}()

	stored, err := s.ConfigGet("api_key")
	if err != nil {
		return fmt.Errorf("sync not configured: run 'vlt sync init --server <url>' first")
	}

	// F3 (ADR-9): read config_format_version; absent → legacy (1).
	configVersion := sync.ConfigFormatVersionLegacy
	if cfv, cfvErr := s.ConfigGet("config_format_version"); cfvErr == nil {
		var v int
		if _, scanErr := fmt.Sscanf(string(cfv), "%d", &v); scanErr == nil && v >= sync.ConfigFormatVersionAAD {
			configVersion = v
		}
	}

	apiKey, wrapped, err := sync.UnwrapConfigValue("api_key", stored, key, configVersion)
	if err != nil {
		return fmt.Errorf("decrypt api_key: %w", err)
	}
	defer crypto.Zeroize(apiKey)

	// Migrate legacy plaintext values on first read.
	if !wrapped {
		if rewrap, werr := sync.WrapConfigValue("api_key", apiKey, key); werr == nil {
			_ = s.ConfigSet("api_key", rewrap)
		}
	}

	fmt.Printf("API Key: %s\n", maskKey(string(apiKey)))
	return nil
}

func newSyncListenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Listen for real-time sync events from server",
		Long:  `Connects to the sync server event stream and automatically pulls changes and triggers desktop notifications.`,
		Args:  cobra.NoArgs,
		RunE:  runSyncListen,
	}
	cmd.Flags().Bool("insecure", false, "allow HTTP or untrusted HTTPS sync server URLs")
	cmd.Flags().Bool("no-notify", false, "disable desktop notifications")
	return cmd
}

func runSyncListen(cmd *cobra.Command, args []string) error {
	vaultPath, err := resolveVaultPath(cmd)
	if err != nil {
		return fmt.Errorf("resolve vault: %w", err)
	}

	s, key, err := unlockVault(vaultPath)
	if err != nil {
		return fmt.Errorf("unlock vault: %w", err)
	}
	defer func() {
		crypto.Zeroize(key)
		_ = s.Close()
	}()

	insecure, _ := cmd.Flags().GetBool("insecure")
	noNotify, _ := cmd.Flags().GetBool("no-notify")

	var client *sync.Client
	if insecure {
		client, err = sync.NewClientInsecure(s, key)
	} else {
		client, err = sync.NewClient(s, key)
	}
	if err != nil {
		return fmt.Errorf("create sync client: %w", err)
	}

	ctx := cmd.Context()
	fmt.Printf("Listening for sync events from server...\n")

	client.WatchAndSyncWithAlerts(ctx, func(seq int64, syncErr error) {
		if syncErr != nil {
			fmt.Printf("❌ Auto-sync error: %v\n", syncErr)
			return
		}
		fmt.Printf("✅ Synced with server (seq %d)\n", seq)
		if !noNotify {
			_ = notify.Send("vlt", "Bóveda sincronizada", fmt.Sprintf("Cambios remotos aplicados (secuencia %d)", seq))
		}
	}, func(alert sync.SecurityAlert) {
		fmt.Printf("\n🚨 SECURITY ALERT [%s]: %s from %s (%s)\n", alert.Severity, alert.Reason, alert.Device.Hostname, alert.Device.IPAddress)
		if !noNotify {
			_ = notify.Send("vlt Security Alert", fmt.Sprintf("[%s] Intrusión detectada", alert.Severity), fmt.Sprintf("%s en %s (%s)", alert.Reason, alert.Device.Hostname, alert.Device.IPAddress))
		}
	})

	return nil
}

// newUUID generates a v4 UUID using crypto/rand (duplicated from store package
// to avoid import cycle).
func newUUID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("rand read: %w", err)
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16]), nil
}
