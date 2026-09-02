package tui

// Footer / help text constants for all TUI screens.
const (
	addFooterText     = "tab: switch field · enter: next/save · esc: cancel · ctrl+k: kind · ctrl+o: file · ctrl+g: generate password"
	detailFooterText  = "Esc back · Enter reveal/hide · c copy · e edit · x export file · Ctrl+C exit"
	listFooterText    = "↑/↓ navigate · a add · d delete · Enter view · / search · f filter · t tag · e expiring · i inspect · q quit"
	searchFooterText  = "Type to filter · Enter select · Esc back · ↑/↓ navigate · Ctrl+C exit"
	unlockFooterText  = "Enter to unlock · Ctrl+C to quit"
	inspectFooterText = "Esc back · q back · Ctrl+C exit"
)

// Placeholder text constants for input fields.
const (
	placeholderMasterPassword = "Enter master password"
	placeholderSearch         = "Search secrets..."
	placeholderSecretName     = "Secret name"
	placeholderSecretValue    = "Secret value"
	placeholderFilePath       = "File path (e.g. /path/to/cert.pem)"
	placeholderUsername       = "Username (optional)"
	placeholderSiteURL        = "Site / URL (optional)"
	placeholderNotes          = "Notes (optional)"
)

// separatorLine is the horizontal separator rendered under the app title.
const separatorLine = "────────────────────────────────────"
