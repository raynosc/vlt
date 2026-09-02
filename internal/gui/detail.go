package gui

import (
	"context"
	"fmt"
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/raynosc/vlt/internal/secret"
	themepkg "github.com/raynosc/vlt/internal/theme"
)

// ── Field Label Helpers ──

// fieldLabel creates a small, dim label for fields. No padding wrapper — the
// surrounding field block owns the spacing so the label sits close to its value.
func fieldLabel(text string) fyne.CanvasObject {
	lbl := canvas.NewText(text, themepkg.Muted)
	lbl.TextSize = 12
	return lbl
}

// fieldDivider returns a thin horizontal hairline drawn between detail field
// rows to give a clean card-row separation. The color is slightly
// lighter than the card background (Surface2 #222) so the line is actually
// visible — the theme Separator (#2A2A2A) was too close to the background.
func fieldDivider() fyne.CanvasObject {
	line := canvas.NewRectangle(color.NRGBA{R: 0x3A, G: 0x3A, B: 0x3A, A: 0xFF})
	line.SetMinSize(fyne.NewSize(0, 1))
	return line
}

// ── Enhanced Detail View ──

// buildEnhancedDetailView creates a SecVault-style detail view with inline editing.
func (g *GUI) buildEnhancedDetailView(name string, setRight func(fyne.CanvasObject), onRefresh func()) fyne.CanvasObject {
	sec, password, err := g.backend.GetSecret(name)
	if err != nil {
		return container.NewCenter(widget.NewLabel("Failed to load secret: " + err.Error()))
	}

	meta := secret.UnmarshalPasswordMetadata(sec.Metadata)

	// ── Premium Header with Large Typography ──
	typeIcon := FaviconOrBrandIcon(*sec, "lg", nil)

	titleText := canvas.NewText(sec.Name, themepkg.Foreground)
	titleText.TextSize = 28
	titleText.TextStyle = fyne.TextStyle{Bold: true}

	// Subtitle shows the website domain only
	subtitleStr := ""
	if meta != nil && meta.URL != "" {
		subtitleStr = extractDomain(meta.URL)
	}
	subtitleText := canvas.NewText(subtitleStr, themepkg.Muted)
	subtitleText.TextSize = 14

	headerText := container.NewVBox(titleText, subtitleText)
	headerBox := container.NewBorder(nil, nil, typeIcon, nil, container.NewPadded(headerText))

	// ── Editable Fields — all shown even if empty ──
	var fields []fyne.CanvasObject

	// Lightweight reload: re-renders just this detail, not the whole list
	reloadDetail := func() {
		setRight(g.buildEnhancedDetailView(name, setRight, func() {
			g.showListScreen()
		}))
	}

	// Username field (editable inline, always shown)
	username := ""
	if meta != nil {
		username = meta.Username
	}
	usernameRow := buildEditableField(fieldLabel("username"), username, false, func(newVal string) {
		g.updateMetadataField(name, "username", newVal, meta, reloadDetail)
	})
	fields = append(fields, usernameRow)

	// Password field (editable inline, with reveal/hide toggle)
	passwordRow := buildPasswordField(fieldLabel("password"), password, func(newVal string) {
		g.updateSecretValue(name, newVal, reloadDetail)
	})
	fields = append(fields, passwordRow)

	// Website/URL field (editable inline, always shown)
	url := ""
	if meta != nil {
		url = meta.URL
	}
	urlRow := buildURLEditableField(fieldLabel("website"), url, func(newVal string) {
		g.updateMetadataField(name, "url", newVal, meta, reloadDetail)
	})
	fields = append(fields, urlRow)

	// TOTP field
	totpAuth := ""
	if meta != nil {
		totpAuth = meta.OTPAuth
	}
	if totpAuth != "" {
		totpRow := g.buildTOTPField(fieldLabel("one-time password"), name)
		fields = append(fields, totpRow)
	} else {
		totpRow := buildReadonlyField(fieldLabel("one-time password"), "Not configured")
		fields = append(fields, totpRow)
	}

	// Kind field (informational)
	kindRow := buildReadonlyField(fieldLabel("kind"), string(sec.Kind))
	fields = append(fields, kindRow)

	// Tags field (always shown)
	tags := sec.Tags
	if tags == "" {
		tags = "None"
	}
	tagsRow := buildReadonlyField(fieldLabel("tags"), tags)
	fields = append(fields, tagsRow)

	// Created/Updated timestamps
	updatedRow := buildReadonlyField(fieldLabel("updated"), sec.UpdatedAt.Format("Jan 2, 2006 3:04 PM"))
	fields = append(fields, updatedRow)

	// ── Notes (always shown) ──
	notesHeader := widget.NewLabelWithStyle("NOTES", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Italic: true})
	notesText := widget.NewLabel(sec.Notes)
	if sec.Notes == "" {
		notesText = widget.NewLabel("No notes")
	}
	notesText.Wrapping = fyne.TextWrapWord
	// Notes stay in their own section, separate from the divided field rows.
	notesSection := container.NewVBox(widget.NewSeparator(), notesHeader, notesText)

	// ── Toolbar ──
	editBtn := widget.NewButtonWithIcon("Edit", theme.DocumentCreateIcon(), func() {
		setRight(g.buildFormView(name, onRefresh, func() {
			setRight(g.buildEnhancedDetailView(name, setRight, onRefresh))
		}))
	})
	editBtn.Importance = widget.LowImportance

	deleteBtn := widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), func() {
		dialog.ShowConfirm("Delete Secret",
			fmt.Sprintf("Are you sure you want to delete '%s'?", name),
			func(confirmed bool) {
				if confirmed {
					if err := g.backend.DeleteSecret(name); err == nil {
						onRefresh()
					}
				}
			}, g.window)
	})
	deleteBtn.Importance = widget.LowImportance

	openInBrowserBtn := widget.NewButtonWithIcon("Open", theme.ComputerIcon(), func() {
		if meta != nil && meta.URL != "" {
			_ = openBrowser(meta.URL)
		}
	})
	openInBrowserBtn.Importance = widget.LowImportance

	// Use spacer to push toolbar to the right
	toolbar := container.NewBorder(nil, nil, nil, container.NewHBox(openInBrowserBtn, editBtn, deleteBtn))

	// ── Assemble Card ──
	innerContent := container.NewVBox(
		container.NewPadded(toolbar),
		container.NewPadded(headerBox),
		widget.NewSeparator(),
	)
	// Each field row is separated by a thin divider for a clean
	// card-row feel; notes follow as their own section.
	for i, f := range fields {
		if i > 0 {
			innerContent.Add(fieldDivider())
		}
		innerContent.Add(f)
	}
	innerContent.Add(notesSection)

	scrollContent := container.NewPadded(container.NewScroll(innerContent))

	// Card with Surface2 background and glass border
	cardBg := canvas.NewRectangle(themepkg.Surface2)
	cardBg.CornerRadius = sizeCardRadius
	cardBorder := canvas.NewRectangle(color.Transparent)
	cardBorder.StrokeColor = themepkg.GlassBorder
	cardBorder.StrokeWidth = 1
	cardBorder.CornerRadius = sizeCardRadius

	card := container.NewStack(cardBg, cardBorder, scrollContent)

	return card
}

// ── Editable Field Components ──

// buildEditableField creates a field label + value row with inline edit capability.
// Layout: [label] [value/entry fills remaining space] [buttons compact]
func buildEditableField(label fyne.CanvasObject, displayValue string, isPassword bool, onSave func(string)) fyne.CanvasObject {
	// View layer: shows the current value
	valLbl := widget.NewLabel(displayValue)
	valLbl.Truncation = fyne.TextTruncateClip

	// Edit layer: the text entry for editing
	editEntry := widget.NewEntry()
	if isPassword {
		editEntry.Password = true
		editEntry.SetPlaceHolder("new value...")
	} else {
		editEntry.SetPlaceHolder("new value...")
	}
	editEntry.Hide()

	// Center stack: swaps between view and edit
	centerStack := container.NewStack(valLbl, editEntry)

	// View buttons (right side, compact)
	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		fyne.CurrentApp().Clipboard().SetContent(displayValue)
	})
	copyBtn.Importance = widget.LowImportance

	editBtn := widget.NewButtonWithIcon("", theme.DocumentCreateIcon(), func() {})
	editBtn.Importance = widget.LowImportance
	viewBtns := container.NewHBox(copyBtn, editBtn)

	// Empty field: show a muted placeholder and hide the copy action (copying an
	// empty value is a no-op). Edit stays so the user can fill it in.
	if displayValue == "" {
		valLbl.SetText("Not set")
		copyBtn.Hide()
	}

	// Edit buttons (right side, compact)
	saveBtn := widget.NewButtonWithIcon("✓", theme.ConfirmIcon(), func() {})
	saveBtn.Importance = widget.HighImportance
	cancelBtn := widget.NewButtonWithIcon("✗", theme.CancelIcon(), func() {})
	cancelBtn.Importance = widget.LowImportance
	editBtns := container.NewHBox(saveBtn, cancelBtn)
	editBtns.Hide()

	// Right stack: swaps between view buttons and edit buttons
	rightStack := container.NewStack(viewBtns, editBtns)

	// ── State transitions ──
	editBtn.OnTapped = func() {
		editEntry.SetText(displayValue)
		valLbl.Hide()
		editEntry.Show()
		viewBtns.Hide()
		editBtns.Show()
		// Focus the entry after a short delay so canvas is ready
		editEntry.FocusGained()
	}

	saveBtn.OnTapped = func() {
		newVal := editEntry.Text
		editEntry.Hide()
		editBtns.Hide()
		valLbl.SetText(newVal)
		valLbl.Show()
		viewBtns.Show()
		if onSave != nil {
			onSave(newVal)
		}
	}

	cancelBtn.OnTapped = func() {
		editEntry.Hide()
		editBtns.Hide()
		valLbl.Show()
		viewBtns.Show()
	}

	// Layout: label above, value and buttons below
	bottomRow := container.NewBorder(nil, nil, nil, rightStack, centerStack)
	block := container.NewVBox(label, bottomRow)
	// Add some padding to simulate a clean field block
	return container.NewPadded(block)
}

func calculatePasswordStrength(pwd string) (color.NRGBA, string) {
	if len(pwd) == 0 {
		return themepkg.Muted, ""
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range pwd {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	diversity := 0
	if hasUpper {
		diversity++
	}
	if hasLower {
		diversity++
	}
	if hasDigit {
		diversity++
	}
	if hasSpecial {
		diversity++
	}

	if len(pwd) >= 14 && diversity >= 3 {
		return themepkg.Success, "Strong password"
	}
	if len(pwd) >= 8 && diversity >= 2 {
		return themepkg.Yellow, "Good password"
	}
	return themepkg.Error, "Weak password"
}

// buildPasswordField creates a password field with reveal/hide toggle, strength meter, and inline edit.
func buildPasswordField(label fyne.CanvasObject, realValue string, onSave func(string)) fyne.CanvasObject {
	isMultiLine := strings.Contains(realValue, "\n")

	// Track reveal state
	revealed := false
	var maskedValue string
	if isMultiLine {
		maskedValue = "•••••••••••••••• (Multi-line Secret)"
	} else {
		maskedValue = strings.Repeat("•", min(len(realValue), 16))
	}

	valLbl := widget.NewLabel(maskedValue)
	if isMultiLine {
		valLbl.Wrapping = fyne.TextWrapBreak
	} else {
		valLbl.Truncation = fyne.TextTruncateClip
	}

	// Strength indicator bar
	strColor, strText := calculatePasswordStrength(realValue)
	strengthBar := canvas.NewRectangle(strColor)
	strengthBar.SetMinSize(fyne.NewSize(60, 3))
	strengthBar.CornerRadius = 1

	strengthLbl := canvas.NewText(strText, themepkg.Muted)
	strengthLbl.TextSize = 10

	strengthBox := container.NewHBox(strengthBar, strengthLbl)
	if isMultiLine || len(realValue) == 0 {
		strengthBox.Hide()
	}

	// Edit entry
	editEntry := widget.NewEntry()
	if isMultiLine {
		editEntry.MultiLine = true
		editEntry.Wrapping = fyne.TextWrapBreak
		editEntry.SetMinRowsVisible(6)
	} else {
		editEntry.Password = true
	}
	editEntry.SetPlaceHolder("new password...")
	editEntry.Hide()

	centerStack := container.NewStack(valLbl, editEntry)

	// Reveal/Hide button
	revealBtn := widget.NewButtonWithIcon("", theme.VisibilityIcon(), func() {})
	revealBtn.Importance = widget.LowImportance

	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		fyne.CurrentApp().Clipboard().SetContent(realValue)
	})
	copyBtn.Importance = widget.LowImportance

	editBtn := widget.NewButtonWithIcon("", theme.DocumentCreateIcon(), func() {})
	editBtn.Importance = widget.LowImportance
	viewBtns := container.NewHBox(revealBtn, copyBtn, editBtn)

	// Edit buttons
	saveBtn := widget.NewButtonWithIcon("✓", theme.ConfirmIcon(), func() {})
	saveBtn.Importance = widget.HighImportance
	cancelBtn := widget.NewButtonWithIcon("✗", theme.CancelIcon(), func() {})
	cancelBtn.Importance = widget.LowImportance
	editBtns := container.NewHBox(saveBtn, cancelBtn)
	editBtns.Hide()

	rightStack := container.NewStack(viewBtns, editBtns)

	// ── Reveal toggle ──
	revealBtn.OnTapped = func() {
		revealed = !revealed
		if revealed {
			valLbl.SetText(realValue)
			revealBtn.SetIcon(theme.VisibilityOffIcon())
		} else {
			valLbl.SetText(maskedValue)
			revealBtn.SetIcon(theme.VisibilityIcon())
		}
	}

	// ── Edit transitions ──
	editBtn.OnTapped = func() {
		editEntry.SetText(realValue)
		editEntry.Password = !revealed
		valLbl.Hide()
		strengthBox.Hide()
		editEntry.Show()
		viewBtns.Hide()
		editBtns.Show()
		editEntry.FocusGained()
	}

	saveBtn.OnTapped = func() {
		newVal := editEntry.Text
		editEntry.Hide()
		editBtns.Hide()
		maskedValue = strings.Repeat("•", min(len(newVal), 16))
		valLbl.SetText(maskedValue)
		valLbl.Show()
		viewBtns.Show()
		revealed = false
		revealBtn.SetIcon(theme.VisibilityIcon())

		newCol, newTxt := calculatePasswordStrength(newVal)
		strengthBar.FillColor = newCol
		strengthBar.Refresh()
		strengthLbl.Text = newTxt
		strengthLbl.Refresh()
		if !isMultiLine && len(newVal) > 0 {
			strengthBox.Show()
		}

		if onSave != nil {
			onSave(newVal)
		}
	}

	cancelBtn.OnTapped = func() {
		editEntry.Hide()
		editBtns.Hide()
		valLbl.Show()
		if !isMultiLine && len(realValue) > 0 {
			strengthBox.Show()
		}
		viewBtns.Show()
	}

	// Layout: label above, value and buttons below, strength meter at bottom
	bottomRow := container.NewBorder(nil, nil, nil, rightStack, centerStack)
	block := container.NewVBox(label, bottomRow, strengthBox)
	return container.NewPadded(block)
}

// buildURLEditableField creates an editable URL field with open-in-browser button.
// Inline edit: shows entry + save/cancel, same pattern as buildEditableField.
func buildURLEditableField(label fyne.CanvasObject, displayValue string, onSave func(string)) fyne.CanvasObject {
	// View layer
	valLbl := widget.NewLabel(displayValue)
	valLbl.Truncation = fyne.TextTruncateClip

	// Edit layer
	editEntry := widget.NewEntry()
	editEntry.SetPlaceHolder("new url...")
	editEntry.Hide()

	centerStack := container.NewStack(valLbl, editEntry)

	// View buttons
	openBtn := widget.NewButtonWithIcon("", theme.ComputerIcon(), func() {
		_ = openBrowser(displayValue)
	})
	openBtn.Importance = widget.LowImportance

	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		fyne.CurrentApp().Clipboard().SetContent(displayValue)
	})
	copyBtn.Importance = widget.LowImportance

	editBtn := widget.NewButtonWithIcon("", theme.DocumentCreateIcon(), func() {})
	editBtn.Importance = widget.LowImportance
	viewBtns := container.NewHBox(openBtn, copyBtn, editBtn)

	// Empty website: hide open-in-browser and copy (both no-ops without a URL),
	// show a muted placeholder. Edit stays so the user can add a URL.
	if displayValue == "" {
		valLbl.SetText("Not set")
		openBtn.Hide()
		copyBtn.Hide()
	}

	// Edit buttons
	saveBtn := widget.NewButtonWithIcon("✓", theme.ConfirmIcon(), func() {})
	saveBtn.Importance = widget.HighImportance
	cancelBtn := widget.NewButtonWithIcon("✗", theme.CancelIcon(), func() {})
	cancelBtn.Importance = widget.LowImportance
	editBtns := container.NewHBox(saveBtn, cancelBtn)
	editBtns.Hide()

	rightStack := container.NewStack(viewBtns, editBtns)

	// ── Edit transitions ──
	editBtn.OnTapped = func() {
		editEntry.SetText(displayValue)
		valLbl.Hide()
		editEntry.Show()
		viewBtns.Hide()
		editBtns.Show()
		editEntry.FocusGained()
	}

	saveBtn.OnTapped = func() {
		newVal := editEntry.Text
		editEntry.Hide()
		editBtns.Hide()
		valLbl.SetText(newVal)
		valLbl.Show()
		viewBtns.Show()
		if onSave != nil {
			onSave(newVal)
		}
	}

	cancelBtn.OnTapped = func() {
		editEntry.Hide()
		editBtns.Hide()
		valLbl.Show()
		viewBtns.Show()
	}

	// Layout: label above, value and buttons below
	bottomRow := container.NewBorder(nil, nil, nil, rightStack, centerStack)
	block := container.NewVBox(label, bottomRow)
	return container.NewPadded(block)
}

// buildReadonlyField creates a non-editable label:value row.
func buildReadonlyField(label fyne.CanvasObject, value string) fyne.CanvasObject {
	valLbl := widget.NewLabelWithStyle(value, fyne.TextAlignLeading, fyne.TextStyle{})
	valLbl.Wrapping = fyne.TextWrapWord
	block := container.NewVBox(label, valLbl)
	return container.NewPadded(block)
}

// ── TOTP Field ──

func (g *GUI) buildTOTPField(label fyne.CanvasObject, name string) fyne.CanvasObject {
	valLbl := widget.NewLabel("Generating...")

	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		code, _, err := g.backend.GetTOTP(name)
		if err == nil {
			g.fyneApp.Clipboard().SetContent(code)
		}
	})
	copyBtn.Importance = widget.LowImportance

	// Cancel any previous TOTP goroutine
	if g.totpCancel != nil {
		g.totpCancel()
	}
	totpCtx, cancel := context.WithCancel(context.Background())
	g.totpCancel = cancel

	go func() {
		type totpResult struct {
			code      string
			remaining int
			err       error
		}
		ch := make(chan totpResult, 1)
		go func() {
			code, remaining, e := g.backend.GetTOTP(name)
			ch <- totpResult{code, remaining, e}
		}()
		select {
		case <-totpCtx.Done():
			return
		case r := <-ch:
			if r.err == nil {
				fyne.Do(func() {
					valLbl.SetText(fmt.Sprintf("%s (%ds)", r.code, r.remaining))
				})
			}
		}
	}()

	bottomRow := container.NewBorder(nil, nil, nil, copyBtn, valLbl)
	block := container.NewVBox(label, bottomRow)
	return container.NewPadded(block)
}

// ── Metadata Update Helpers ──

func (g *GUI) updateMetadataField(name, field, newValue string, meta *secret.PasswordMetadata, onRefresh func()) {
	if meta == nil {
		meta = &secret.PasswordMetadata{}
	}

	switch field {
	case "username":
		meta.Username = newValue
	case "url":
		meta.URL = newValue
	case "otpauth":
		meta.OTPAuth = newValue
	}

	metadataJSON := secret.MarshalPasswordMetadata(meta)
	_ = g.backend.UpdateMetadata(name, metadataJSON)
	onRefresh()
}

func (g *GUI) updateSecretValue(name, newValue string, onRefresh func()) {
	if newValue == "" {
		return
	}

	sec, _, err := g.backend.GetSecret(name)
	if err != nil {
		return
	}

	// Use EditSecret to update the value
	_ = g.backend.EditSecret(name, string(sec.Kind), newValue, sec.Notes, sec.Tags)
	onRefresh()
}
