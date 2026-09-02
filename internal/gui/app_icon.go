package gui

import (
	_ "embed"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
)

//go:embed assets/icon-128.png
var appIcon128Bytes []byte

//go:embed assets/icon-64.png
var appIcon64Bytes []byte

//go:embed assets/tray-icon.png
var trayIconBytes []byte

// AppIconResource is the 128x128 official app icon for window and dock.
var AppIconResource = fyne.NewStaticResource("app-icon.png", appIcon128Bytes)

// AppIconSmallResource is the 64x64 app icon for UI badges.
var AppIconSmallResource = fyne.NewStaticResource("app-icon-sm.png", appIcon64Bytes)

// TrayIconResource is the crisp 44x44 template icon for the system tray and macOS menu bar.
var TrayIconResource = fyne.NewStaticResource("tray-icon.png", trayIconBytes)

// NewAppIconImage returns a canvas.Image configured for UI presentation.
func NewAppIconImage(size float32) *canvas.Image {
	img := canvas.NewImageFromResource(AppIconResource)
	img.SetMinSize(fyne.NewSize(size, size))
	img.FillMode = canvas.ImageFillContain
	return img
}
