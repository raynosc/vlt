package gui

import (
	"fmt"
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/raynosc/vlt/internal/secret"
	themepkg "github.com/raynosc/vlt/internal/theme"
)

// SidebarItem represents a clickable item in the sidebar.
type SidebarItem struct {
	ID      string
	Label   string
	Kind    secret.Kind
	IconRes fyne.Resource
}

// SidebarCategories is the list of filter categories shown in the sidebar.
var SidebarCategories = []SidebarItem{
	{ID: "all", Label: "All Items", Kind: "", IconRes: theme.ListIcon()},
	{ID: "logins", Label: "Logins", Kind: secret.KindPassword, IconRes: theme.LoginIcon()},
	{ID: "servers", Label: "Servers & IPs", Kind: "", IconRes: theme.ComputerIcon()},
	{ID: "cards", Label: "Banking & Cards", Kind: "", IconRes: theme.AccountIcon()},
	{ID: "ssh_keys", Label: "SSH Keys", Kind: secret.KindSSHKey, IconRes: theme.StorageIcon()},
	{ID: "api_keys", Label: "API Keys", Kind: secret.KindAPIKey, IconRes: theme.SettingsIcon()},
	{ID: "notes", Label: "Secure Notes", Kind: secret.KindNote, IconRes: theme.DocumentIcon()},
}

// SidebarCallbacks defines the actions triggered by sidebar interactions.
type SidebarCallbacks struct {
	OnCategorySelected func(categoryID string, kind secret.Kind)
	OnWatchtower       func()
	OnLock             func()
	OnSettings         func()
	OnVaultSelected    func(vaultName string)
	OnNewVault         func()
}

// buildSidebar creates the full sidebar panel with clean active category highlight and count badges.
func buildSidebar(vaultName string, vaultList []string, currentVault string, activeCategoryID string, allSecrets []secret.Secret, callbacks SidebarCallbacks) fyne.CanvasObject {
	if activeCategoryID == "" {
		activeCategoryID = "all"
	}

	// ── Header Branding ──
	appLogo := NewAppIconImage(36)

	statusDot := canvas.NewRectangle(themepkg.Success)
	statusDot.SetMinSize(fyne.NewSize(8, 8))
	statusDot.CornerRadius = 4

	appName := canvas.NewText("vlt", themepkg.Foreground)
	appName.TextSize = 15
	appName.TextStyle = fyne.TextStyle{Bold: true}

	vaultBadge := canvas.NewText(vaultName, themepkg.Muted)
	vaultBadge.TextSize = 12

	headerText := container.NewVBox(appName, vaultBadge)
	headerContent := container.NewBorder(nil, nil, appLogo, container.NewCenter(statusDot), container.NewPadded(headerText))

	headerBg := canvas.NewRectangle(themepkg.Surface2)
	headerBg.CornerRadius = 8
	header := container.NewStack(headerBg, container.NewPadded(headerContent))

	// ── Categories List ──
	categoryBox := container.NewVBox()
	categoryLabel := widget.NewLabelWithStyle("CATEGORIES", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	categoryBox.Add(categoryLabel)

	for _, cat := range SidebarCategories {
		catItem := cat
		count := countCategoryItems(allSecrets, catItem.ID, catItem.Kind)
		isActive := catItem.ID == activeCategoryID

		btn := buildCategoryRow(catItem, count, isActive, func() {
			if callbacks.OnCategorySelected != nil {
				callbacks.OnCategorySelected(catItem.ID, catItem.Kind)
			}
		})
		categoryBox.Add(btn)
	}

	// ── Watchtower Row ──
	watchtowerActive := activeCategoryID == "watchtower"
	watchtowerBtn := buildActionRow("Watchtower", theme.WarningIcon(), themepkg.Yellow, watchtowerActive, func() {
		if callbacks.OnWatchtower != nil {
			callbacks.OnWatchtower()
		}
	})

	// ── Vault Selector ──
	vaultSectionLabel := widget.NewLabelWithStyle("VAULT", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	vaultOptions := make([]string, len(vaultList))
	copy(vaultOptions, vaultList)
	found := false
	for _, v := range vaultOptions {
		if v == currentVault {
			found = true
			break
		}
	}
	if !found && currentVault != "" {
		vaultOptions = append([]string{currentVault}, vaultOptions...)
	}
	vaultOptions = append(vaultOptions, "+ New Vault")

	vaultSelect := widget.NewSelect(vaultOptions, func(selected string) {
		if selected == "+ New Vault" {
			if callbacks.OnNewVault != nil {
				callbacks.OnNewVault()
			}
		} else if selected != currentVault {
			if callbacks.OnVaultSelected != nil {
				callbacks.OnVaultSelected(selected)
			}
		}
	})
	vaultSelect.SetSelected(currentVault)

	// ── Bottom Section ──
	lockBtn := widget.NewButtonWithIcon("Lock Vault", theme.CancelIcon(), func() {
		if callbacks.OnLock != nil {
			callbacks.OnLock()
		}
	})
	lockBtn.Importance = widget.LowImportance

	settingsBtn := widget.NewButtonWithIcon("Settings", theme.SettingsIcon(), func() {
		if callbacks.OnSettings != nil {
			callbacks.OnSettings()
		}
	})
	settingsBtn.Importance = widget.LowImportance

	bottomSection := container.NewVBox(
		widget.NewSeparator(),
		lockBtn,
		settingsBtn,
	)

	// ── Main Layout ──
	middleContent := container.NewVBox(
		categoryBox,
		widget.NewSeparator(),
		watchtowerBtn,
		widget.NewSeparator(),
		vaultSectionLabel,
		vaultSelect,
	)

	sidebar := container.NewBorder(
		container.NewVBox(header, widget.NewSeparator()),
		bottomSection,
		nil, nil,
		container.NewScroll(middleContent),
	)

	return sidebar
}

// tappableRow creates a clickable row container that renders content cleanly without an opaque button overlay.
type tappableRow struct {
	widget.BaseWidget
	content  fyne.CanvasObject
	onTapped func()
}

func newTappableRow(content fyne.CanvasObject, onTapped func()) *tappableRow {
	r := &tappableRow{content: content, onTapped: onTapped}
	r.ExtendBaseWidget(r)
	return r
}

func (r *tappableRow) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(r.content)
}

func (r *tappableRow) Tapped(_ *fyne.PointEvent) {
	if r.onTapped != nil {
		r.onTapped()
	}
}

func (r *tappableRow) MinSize() fyne.Size {
	if r.content != nil {
		return r.content.MinSize()
	}
	return fyne.NewSize(0, 0)
}

// buildCategoryRow constructs an elegant category item with icon, label and count badge.
func buildCategoryRow(cat SidebarItem, count int, isActive bool, onTapped func()) fyne.CanvasObject {
	icon := widget.NewIcon(cat.IconRes)
	label := canvas.NewText(cat.Label, themepkg.Foreground)
	label.TextSize = 13
	if isActive {
		label.TextStyle = fyne.TextStyle{Bold: true}
		label.Color = color.White
	}

	countText := canvas.NewText(fmt.Sprintf("%d", count), themepkg.Muted)
	countText.TextSize = 11
	if isActive {
		countText.Color = color.White
	}

	content := container.NewBorder(nil, nil, icon, container.NewCenter(countText), container.NewPadded(label))

	var bg *canvas.Rectangle
	if isActive {
		bg = canvas.NewRectangle(themepkg.Blue)
		bg.CornerRadius = 6
	} else {
		bg = canvas.NewRectangle(color.Transparent)
	}

	stacked := container.NewStack(bg, container.NewPadded(content))
	return newTappableRow(stacked, onTapped)
}

// buildActionRow creates a styled action button row.
func buildActionRow(title string, iconRes fyne.Resource, accent color.NRGBA, isActive bool, onTapped func()) fyne.CanvasObject {
	icon := widget.NewIcon(iconRes)
	label := canvas.NewText(title, themepkg.Foreground)
	label.TextSize = 13
	if isActive {
		label.TextStyle = fyne.TextStyle{Bold: true}
		label.Color = color.White
	}

	content := container.NewBorder(nil, nil, icon, nil, container.NewPadded(label))

	var bg *canvas.Rectangle
	if isActive {
		bg = canvas.NewRectangle(themepkg.Blue)
		bg.CornerRadius = 6
	} else {
		bg = canvas.NewRectangle(color.Transparent)
	}

	stacked := container.NewStack(bg, container.NewPadded(content))
	return newTappableRow(stacked, onTapped)
}

// buildSidebarBackground wraps the sidebar in a modern styled container.
func buildSidebarBackground(sidebar fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewRectangle(themepkg.Surface1)
	bg.SetMinSize(fyne.NewSize(220, 1))
	bg.CornerRadius = sizeCardRadius

	border := canvas.NewRectangle(color.Transparent)
	border.StrokeColor = themepkg.GlassBorder
	border.StrokeWidth = 1
	border.CornerRadius = sizeCardRadius
	border.SetMinSize(fyne.NewSize(220, 1))

	return container.NewStack(bg, border, container.NewPadded(sidebar))
}

// ── Sidebar Category Filtering ──

// countCategoryItems returns the number of secrets matching the category.
func countCategoryItems(secrets []secret.Secret, categoryID string, kind secret.Kind) int {
	return len(filterByCategory(secrets, categoryID, kind))
}

// filterByCategory filters secrets by category ID and kind.
func filterByCategory(secrets []secret.Secret, categoryID string, kind secret.Kind) []secret.Secret {
	if categoryID == "all" || categoryID == "" {
		result := make([]secret.Secret, len(secrets))
		copy(result, secrets)
		return result
	}

	var result []secret.Secret
	for _, s := range secrets {
		lowerName := strings.ToLower(s.Name)

		switch categoryID {
		case "logins":
			if s.Kind == secret.KindPassword && !isIPOrServerName(s.Name) && !isBankingBrand(s.Name) {
				result = append(result, s)
			}
		case "servers":
			if isIPOrServerName(s.Name) || s.Kind == secret.KindSSHKey {
				result = append(result, s)
			}
		case "cards":
			if isBankingBrand(s.Name) {
				result = append(result, s)
			}
		case "ssh_keys":
			if s.Kind == secret.KindSSHKey || strings.Contains(lowerName, "ssh") {
				result = append(result, s)
			}
		case "api_keys":
			if s.Kind == secret.KindAPIKey || strings.Contains(lowerName, "api") || strings.Contains(lowerName, "token") {
				result = append(result, s)
			}
		case "notes":
			if s.Kind == secret.KindNote {
				result = append(result, s)
			}
		default:
			if s.Kind == kind {
				result = append(result, s)
			}
		}
	}
	return result
}

// isBankingBrand returns true if the name matches financial / banking keywords.
func isBankingBrand(name string) bool {
	lower := strings.ToLower(name)
	banks := []string{"abitab", "brou", "itau", "santander", "scotiabank", "bbva", "midinero", "redpagos", "prex", "bna", "btgpactual", "bandes", "heritage", "bank", "banco", "card", "tarjeta", "visa", "mastercard"}
	for _, b := range banks {
		if strings.Contains(lower, b) {
			return true
		}
	}
	return false
}

// filterByCategoryAndSearch combines category filtering with text search.
func filterByCategoryAndSearch(secrets []secret.Secret, categoryID string, kind secret.Kind, query string) []secret.Secret {
	filtered := filterByCategory(secrets, categoryID, kind)
	if query == "" {
		return filtered
	}
	return filterSecrets(filtered, query)
}
