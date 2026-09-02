// Package notify provides cross-platform desktop notifications.
package notify

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Send displays a desktop notification with the specified title, subtitle, and message.
// It uses native system facilities (AppleScript on macOS, notify-send on Linux).
// If notification delivery fails, it returns an error without crashing.
func Send(title, subtitle, message string) error {
	switch runtime.GOOS {
	case "darwin":
		return sendMacOS(title, subtitle, message)
	case "linux":
		return sendLinux(title, subtitle, message)
	case "windows":
		return sendWindows(title, subtitle, message)
	default:
		return nil
	}
}

func escapePowerShell(s string) string {
	s = strings.ReplaceAll(s, "'", "''")
	return s
}

func sendWindows(title, subtitle, message string) error {
	fullTitle := title
	if subtitle != "" {
		fullTitle = fmt.Sprintf("%s — %s", title, subtitle)
	}

	psScript := fmt.Sprintf(
		`[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; `+
			`$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); `+
			`$textNodes = $template.GetElementsByTagName('text'); `+
			`$textNodes.Item(0).AppendChild($template.CreateTextNode('%s')) > $null; `+
			`$textNodes.Item(1).AppendChild($template.CreateTextNode('%s')) > $null; `+
			`$toast = [Windows.UI.Notifications.ToastNotification]::new($template); `+
			`[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('vlt').Show($toast)`,
		escapePowerShell(fullTitle),
		escapePowerShell(message),
	)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	return cmd.Run()
}

func escapeAppleScript(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

func sendMacOS(title, subtitle, message string) error {
	fullTitle := title
	if subtitle != "" {
		fullTitle = fmt.Sprintf("%s — %s", title, subtitle)
	}

	script := fmt.Sprintf(
		`display notification "%s" with title "%s"`,
		escapeAppleScript(message),
		escapeAppleScript(fullTitle),
	)

	cmd := exec.Command("osascript", "-e", script)
	return cmd.Run()
}

func sendLinux(title, subtitle, message string) error {
	if _, err := exec.LookPath("notify-send"); err != nil {
		// notify-send is not installed or headless server, skip silently
		return nil
	}

	fullTitle := title
	if subtitle != "" {
		fullTitle = fmt.Sprintf("%s — %s", title, subtitle)
	}

	cmd := exec.Command("notify-send", fullTitle, message)
	return cmd.Run()
}
