// Package theme provides shared color constants for the vlt UI.
package theme

import "image/color"

// ── Hex constants (for lipgloss / Bubble Tea) ──
const (
	HexPurple    = "#0C72E2" // Vivid Blue Accent
	HexDim       = "#555555"
	HexError     = "#EF4444"
	HexDimLight  = "#9CA3AF"
	HexLabel     = "#A1A1AA"
	HexSuccess   = "#10B981"
	HexSeparator = "#2A2A2A"
	HexWarning   = "#F59E0B"
)

// ── NRGBA constants (for Fyne) ──
// Charcoal & Accent Blue palette
var (
	// Primary accent — Vivid Blue
	Purple        = color.NRGBA{R: 0x0C, G: 0x72, B: 0xE2, A: 0xFF}
	PurpleFocus   = color.NRGBA{R: 0x0C, G: 0x72, B: 0xE2, A: 0x7F}
	PurplePressed = color.NRGBA{R: 0x0A, G: 0x5C, B: 0xB7, A: 0xFF}
	PurpleDim     = color.NRGBA{R: 0x0C, G: 0x72, B: 0xE2, A: 0x3F}
	PurpleScroll  = color.NRGBA{R: 0x0C, G: 0x72, B: 0xE2, A: 0x50}

	// Surfaces — layered neutral darks for high-premium depth
	Background = color.NRGBA{R: 0x12, G: 0x12, B: 0x12, A: 0xFF} // Deepest charcoal
	Surface1   = color.NRGBA{R: 0x19, G: 0x19, B: 0x19, A: 0xFF} // Panels / Sidebar
	Surface2   = color.NRGBA{R: 0x22, G: 0x22, B: 0x22, A: 0xFF} // Cards / Details / Inputs
	Surface3   = color.NRGBA{R: 0x2D, G: 0x2D, B: 0x2D, A: 0xFF} // Hover/Selection elements

	// Glassmorphism translucent
	GlassBg      = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0x06} // ~2% white
	GlassBgHover = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0x0C} // ~5% white
	GlassBorder  = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0x10} // ~6% white

	InputBg     = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0x05} // Barely visible
	DisabledBtn = color.NRGBA{R: 0x2A, G: 0x2A, B: 0x2A, A: 0xFF}
	HeaderBg    = Surface1
	MenuBg      = Surface2
	OverlayBg   = color.NRGBA{R: 0x12, G: 0x12, B: 0x12, A: 0xE8}
	Separator   = color.NRGBA{R: 0x2A, G: 0x2A, B: 0x2A, A: 0xFF}
	Shadow      = color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0x70}

	Success    = color.NRGBA{R: 0x10, G: 0xB9, B: 0x81, A: 0xFF}
	Error      = color.NRGBA{R: 0xEF, G: 0x44, B: 0x44, A: 0xFF}
	Foreground = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF} // Crisp white
	Muted      = color.NRGBA{R: 0xA1, G: 0xA1, B: 0xAA, A: 0xFF} // Sleek light gray

	// Icon colors (vibrant palette for secret kinds)
	Blue       = color.NRGBA{R: 0x0C, G: 0x72, B: 0xE2, A: 0xFF} // Accent Blue
	Orange     = color.NRGBA{R: 0xFB, G: 0x92, B: 0x3C, A: 0xFF} // Orange 400
	Green      = color.NRGBA{R: 0x34, G: 0xD3, B: 0x99, A: 0xFF} // Emerald 400
	Red        = color.NRGBA{R: 0xF8, G: 0x71, B: 0x71, A: 0xFF} // Red 400
	PurpleAlt  = color.NRGBA{R: 0xA7, G: 0x8B, B: 0xFA, A: 0xFF} // Violet 400
	Yellow     = color.NRGBA{R: 0xF4, G: 0xBF, B: 0x4F, A: 0xFF} // Amber 400
	LightBlue  = color.NRGBA{R: 0x38, G: 0xBD, B: 0xF8, A: 0xFF} // Cyan 400
	Teal       = color.NRGBA{R: 0x2D, G: 0xD4, B: 0xBF, A: 0xFF} // Teal 400
	CloseBtnBg = Purple
)
