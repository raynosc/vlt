package cli

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/sync"
)

func newDevicesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "devices",
		Short: "Manage devices registered with the sync server",
		Long:  `List active client devices connected to the sync server or revoke compromised devices.`,
	}

	cmd.AddCommand(newDevicesListCmd())
	cmd.AddCommand(newDevicesRevokeCmd())

	return cmd
}

func newDevicesListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List connected devices",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultPath, err := resolveVaultPath(cmd)
			if err != nil {
				return fmt.Errorf("resolve vault: %w", err)
			}

			s, key, err := unlockVault(vaultPath)
			if err != nil {
				return err
			}
			defer func() {
				crypto.Zeroize(key)
				_ = s.Close()
			}()

			insecure, _ := cmd.Flags().GetBool("insecure")
			var client *sync.Client
			if insecure {
				client, err = sync.NewClientInsecure(s, key)
			} else {
				client, err = sync.NewClient(s, key)
			}
			if err != nil {
				return fmt.Errorf("create sync client: %w", err)
			}

			// Send heartbeat first to ensure this device is registered
			_ = client.Heartbeat()

			devices, err := client.ListDevices()
			if err != nil {
				return fmt.Errorf("list devices: %w", err)
			}

			if len(devices) == 0 {
				fmt.Println("No devices registered on sync server.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			_, _ = fmt.Fprintln(w, "DEVICE ID\tHOSTNAME\tIP ADDRESS\tVERSION\tSTATUS\tLAST SEEN")
			for _, dev := range devices {
				status := "ACTIVE"
				if dev.Revoked {
					status = "REVOKED"
				}
				lastSeen := dev.LastSeenAt.Format(time.RFC3339)
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					dev.DeviceID, dev.Hostname, dev.IPAddress, dev.ClientVersion, status, lastSeen,
				)
			}
			_ = w.Flush()

			return nil
		},
	}
	cmd.Flags().Bool("insecure", false, "allow HTTP or untrusted HTTPS sync server URLs")
	return cmd
}

func newDevicesRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke <device_id>",
		Short: "Revoke a device from syncing",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID := args[0]
			vaultPath, err := resolveVaultPath(cmd)
			if err != nil {
				return fmt.Errorf("resolve vault: %w", err)
			}

			s, key, err := unlockVault(vaultPath)
			if err != nil {
				return err
			}
			defer func() {
				crypto.Zeroize(key)
				_ = s.Close()
			}()

			insecure, _ := cmd.Flags().GetBool("insecure")
			var client *sync.Client
			if insecure {
				client, err = sync.NewClientInsecure(s, key)
			} else {
				client, err = sync.NewClient(s, key)
			}
			if err != nil {
				return fmt.Errorf("create sync client: %w", err)
			}

			if err := client.RevokeDevice(deviceID); err != nil {
				return fmt.Errorf("revoke device: %w", err)
			}

			fmt.Printf("✅ Device %s successfully revoked.\n", deviceID)
			return nil
		},
	}
	cmd.Flags().Bool("insecure", false, "allow HTTP or untrusted HTTPS sync server URLs")
	return cmd
}
