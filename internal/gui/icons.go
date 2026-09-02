package gui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/raynosc/vlt/internal/secret"
	themepkg "github.com/raynosc/vlt/internal/theme"
)

// SecretIcon builds a colored icon with type-specific symbol for a secret.
// Size should be one of "sm" (list, 32px), "md" (detail, 64px), "lg" (large).
func SecretIcon(sec secret.Secret, size string) fyne.CanvasObject {
	col := iconColor(sec.Name)
	return buildTypeIcon(sec.Kind, sec.Name, col, size)
}

// KindIcon builds a colored icon for a secret kind (no name hash color).
func KindIcon(kind secret.Kind, size string) fyne.CanvasObject {
	col := kindColor(kind)
	return buildTypeIcon(kind, "", col, size)
}

// kindColor returns the deterministic color for a secret kind.
func kindColor(kind secret.Kind) color.NRGBA {
	switch kind {
	case secret.KindPassword:
		return themepkg.Blue
	case secret.KindAPIKey:
		return themepkg.Orange
	case secret.KindCertificate:
		return themepkg.Green
	case secret.KindSSHKey:
		return themepkg.Teal
	case secret.KindNote:
		return themepkg.Yellow
	default:
		return themepkg.PurpleAlt
	}
}

// kindIconResource returns a Fyne theme icon for a secret kind.
func kindIconResource(kind secret.Kind) fyne.Resource {
	switch kind {
	case secret.KindPassword:
		return theme.VisibilityIcon()
	case secret.KindAPIKey:
		return theme.SettingsIcon()
	case secret.KindCertificate:
		return theme.CheckButtonCheckedIcon()
	case secret.KindSSHKey:
		return theme.ComputerIcon()
	case secret.KindNote:
		return theme.DocumentIcon()
	default:
		return theme.FileIcon()
	}
}

// sideIconSize returns the pixel size for a given size label.
func sideIconSize(size string) float32 {
	switch size {
	case "sm":
		return 28
	case "md":
		return 56
	case "lg":
		return 72
	default:
		return 32
	}
}

// cornerRadiusForSize returns the corner radius for a given size label.
func cornerRadiusForSize(size string) float32 {
	switch size {
	case "sm":
		return 6
	case "md":
		return 12
	case "lg":
		return 16
	default:
		return 8
	}
}

// fontSizeForSize returns the text/icon size for a given size label.
func fontSizeForSize(size string) float32 {
	switch size {
	case "sm":
		return 14
	case "md":
		return 28
	case "lg":
		return 36
	default:
		return 16
	}
}

// buildTypeIcon creates a rounded rectangle icon with a symbol.
func buildTypeIcon(kind secret.Kind, name string, col color.NRGBA, size string) fyne.CanvasObject {
	sz := sideIconSize(size)
	bg := canvas.NewRectangle(col)
	bg.SetMinSize(fyne.NewSize(sz, sz))
	bg.CornerRadius = cornerRadiusForSize(size)

	// Use a type-specific icon inside
	iconRes := kindIconResource(kind)
	iconW := widget.NewIcon(iconRes)
	content := container.NewCenter(iconW)

	border := canvas.NewRectangle(color.Transparent)
	border.StrokeColor = themepkg.GlassBorder
	border.StrokeWidth = 1
	border.CornerRadius = cornerRadiusForSize(size)

	return container.NewCenter(container.NewStack(bg, border, content))
}

// SidebarCategoryIcon builds a small icon for a sidebar category.
func SidebarCategoryIcon(kind secret.Kind, size string) fyne.CanvasObject {
	col := kindColor(kind)
	sz := sideIconSize(size)
	bg := canvas.NewRectangle(col)
	bg.SetMinSize(fyne.NewSize(sz, sz))
	bg.CornerRadius = cornerRadiusForSize(size)

	iconW := widget.NewIcon(kindIconResource(kind))
	return container.NewStack(bg, container.NewCenter(iconW))
}
