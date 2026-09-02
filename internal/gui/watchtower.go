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

	themepkg "github.com/raynosc/vlt/internal/theme"
	"github.com/raynosc/vlt/internal/watchtower"
)

// doubleClickableCard is a custom container that responds to double clicks or taps.
type doubleClickableCard struct {
	widget.BaseWidget
	content       fyne.CanvasObject
	onDoubleClick func()
}

func newDoubleClickableCard(content fyne.CanvasObject, onDoubleClick func()) *doubleClickableCard {
	c := &doubleClickableCard{
		content:       content,
		onDoubleClick: onDoubleClick,
	}
	c.ExtendBaseWidget(c)
	return c
}

func (c *doubleClickableCard) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(c.content)
}

func (c *doubleClickableCard) DoubleTapped(_ *fyne.PointEvent) {
	if c.onDoubleClick != nil {
		c.onDoubleClick()
	}
}

func (c *doubleClickableCard) Tapped(_ *fyne.PointEvent) {
	// Standard single tap
}

// ── Watchtower View ──

// buildWatchtowerView creates the Watchtower security dashboard asynchronously.
func (g *GUI) buildWatchtowerView(setRight func(fyne.CanvasObject)) fyne.CanvasObject {
	loadingProgress := widget.NewProgressBarInfinite()
	loadingLabel := canvas.NewText("Auditing vault secrets & security health...", themepkg.Muted)
	loadingLabel.TextSize = 14
	loadingLabel.Alignment = fyne.TextAlignCenter

	loadingBox := container.NewCenter(container.NewVBox(
		loadingProgress,
		container.NewPadded(loadingLabel),
	))

	contentHolder := container.NewStack(loadingBox)

	go func() {
		result, err := g.backend.AnalyzePasswords()
		if err != nil {
			contentHolder.Objects = []fyne.CanvasObject{
				container.NewCenter(widget.NewLabel("Watchtower analysis failed: " + err.Error())),
			}
			contentHolder.Refresh()
			return
		}

		view := g.renderWatchtowerDashboard(result, setRight)
		contentHolder.Objects = []fyne.CanvasObject{view}
		contentHolder.Refresh()
	}()

	return contentHolder
}

func (g *GUI) renderWatchtowerDashboard(result *watchtower.WatchtowerResult, setRight func(fyne.CanvasObject)) fyne.CanvasObject {
	overallScore := g.computeWatchtowerScore(result)

	scoreCardBg := canvas.NewRectangle(themepkg.Surface2)
	scoreCardBg.CornerRadius = sizeCardRadius
	scoreCardBorder := canvas.NewRectangle(color.Transparent)
	scoreCardBorder.StrokeColor = themepkg.GlassBorder
	scoreCardBorder.StrokeWidth = 1
	scoreCardBorder.CornerRadius = sizeCardRadius

	scoreBadgeBg := canvas.NewRectangle(scoreBannerColor(overallScore))
	scoreBadgeBg.SetMinSize(fyne.NewSize(64, 64))
	scoreBadgeBg.CornerRadius = 14

	scoreText := canvas.NewText(fmt.Sprintf("%d%%", overallScore), color.White)
	scoreText.Alignment = fyne.TextAlignCenter
	scoreText.TextSize = 22
	scoreText.TextStyle = fyne.TextStyle{Bold: true}

	scoreBadge := container.NewStack(scoreBadgeBg, container.NewCenter(scoreText))

	healthTitle := canvas.NewText("Vault Security Health", themepkg.Foreground)
	healthTitle.TextSize = 18
	healthTitle.TextStyle = fyne.TextStyle{Bold: true}

	healthSubtitleText := scoreLabelText(overallScore)
	if result.IsOfflineMode {
		healthSubtitleText += fmt.Sprintf(" • 🟡 Offline (%s)", result.OfflineReason)
	} else {
		healthSubtitleText += " • 🟢 Online (Pwned Check Active)"
	}
	healthSubtitle := canvas.NewText(healthSubtitleText, themepkg.Muted)
	healthSubtitle.TextSize = 13

	headerInfo := container.NewVBox(healthTitle, healthSubtitle)
	headerContent := container.NewBorder(nil, nil, scoreBadge, nil, container.NewPadded(headerInfo))

	scoreBanner := container.NewStack(scoreCardBg, scoreCardBorder, container.NewPadded(headerContent))

	// ── Stats Row (3 Columns) ──
	statsGrid := container.NewGridWithColumns(3,
		buildStatCard("Total Secrets", fmt.Sprintf("%d", result.TotalSecrets), themepkg.Blue),
		buildStatCard("Analyzed", fmt.Sprintf("%d", result.AnalyzedPasswordCount), themepkg.Purple),
		buildStatCard("Issues", fmt.Sprintf("%d", g.countWatchtowerIssues(result)), themepkg.Error),
	)

	// ── Findings List ──
	findings := container.NewVBox()

	openEditSecret := func(secretName string) {
		g.selectedName = secretName
		setRight(g.buildFormView(secretName, func() {
			setRight(g.buildWatchtowerView(setRight))
		}, func() {
			setRight(g.buildWatchtowerView(setRight))
		}))
	}

	// Compromised in public breaches (Pwned Passwords)
	if len(result.CompromisedPasswords) > 0 {
		pwnedHeader := widget.NewLabelWithStyle(
			fmt.Sprintf("🚨 COMPROMISED IN PUBLIC DATA BREACHES (%d)", len(result.CompromisedPasswords)),
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		)
		findings.Add(pwnedHeader)

		for _, c := range result.CompromisedPasswords {
			secretName := c.SecretName
			scoreColor := themepkg.Error
			scoreRect := canvas.NewRectangle(scoreColor)
			scoreRect.SetMinSize(fyne.NewSize(10, 10))
			scoreRect.CornerRadius = 5

			itemText := secretName
			if c.Username != "" {
				itemText += " — " + c.Username
			}

			nameLbl := canvas.NewText(itemText, themepkg.Foreground)
			nameLbl.TextSize = 14
			nameLbl.TextStyle = fyne.TextStyle{Bold: true}

			reasonLbl := canvas.NewText(fmt.Sprintf("Found in data breaches (%d occurrences) — Double-click to edit & fix", c.BreachCount), themepkg.Error)
			reasonLbl.TextSize = 12

			editBtn := widget.NewButtonWithIcon("", theme.DocumentCreateIcon(), func() {
				openEditSecret(secretName)
			})
			editBtn.Importance = widget.LowImportance

			rowContent := container.NewBorder(
				nil, nil,
				container.NewCenter(scoreRect),
				container.NewCenter(editBtn),
				container.NewVBox(nameLbl, reasonLbl),
			)

			itemCardBg := canvas.NewRectangle(themepkg.Surface1)
			itemCardBg.CornerRadius = 8
			itemCard := newDoubleClickableCard(
				container.NewStack(itemCardBg, container.NewPadded(rowContent)),
				func() { openEditSecret(secretName) },
			)
			findings.Add(itemCard)
		}
	}

	// Weak passwords
	if len(result.WeakPasswords) > 0 {
		weakHeader := widget.NewLabelWithStyle(
			fmt.Sprintf("WEAK PASSWORDS (%d)", len(result.WeakPasswords)),
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		)
		findings.Add(weakHeader)

		for _, w := range result.WeakPasswords {
			secretName := w.SecretName
			scoreColor := parseHexColor(w.Score.ColorHex())
			scoreRect := canvas.NewRectangle(scoreColor)
			scoreRect.SetMinSize(fyne.NewSize(10, 10))
			scoreRect.CornerRadius = 5

			itemText := secretName
			if w.Username != "" {
				itemText += " — " + w.Username
			}

			nameLbl := canvas.NewText(itemText, themepkg.Foreground)
			nameLbl.TextSize = 14
			nameLbl.TextStyle = fyne.TextStyle{Bold: true}

			reasonLbl := canvas.NewText(fmt.Sprintf("%s: %s (Double-click to edit)", w.Score.String(), w.Reason), themepkg.Muted)
			reasonLbl.TextSize = 12

			editBtn := widget.NewButtonWithIcon("", theme.DocumentCreateIcon(), func() {
				openEditSecret(secretName)
			})
			editBtn.Importance = widget.LowImportance

			rowContent := container.NewBorder(
				nil, nil,
				container.NewCenter(scoreRect),
				container.NewCenter(editBtn),
				container.NewVBox(nameLbl, reasonLbl),
			)

			itemCardBg := canvas.NewRectangle(themepkg.Surface1)
			itemCardBg.CornerRadius = 8
			itemCard := newDoubleClickableCard(
				container.NewStack(itemCardBg, container.NewPadded(rowContent)),
				func() { openEditSecret(secretName) },
			)
			findings.Add(itemCard)
		}
	}

	// Duplicate passwords
	if len(result.DuplicatePasswords) > 0 {
		dupHeader := widget.NewLabelWithStyle(
			fmt.Sprintf("REUSED PASSWORDS (%d)", len(result.DuplicatePasswords)),
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		)
		findings.Add(dupHeader)

		for _, d := range result.DuplicatePasswords {
			firstSecret := ""
			if len(d.SecretNames) > 0 {
				firstSecret = d.SecretNames[0]
			}
			dupNames := strings.Join(d.SecretNames, ", ")
			nameLbl := canvas.NewText(dupNames, themepkg.Foreground)
			nameLbl.TextSize = 14
			nameLbl.TextStyle = fyne.TextStyle{Bold: true}

			hashLbl := canvas.NewText(fmt.Sprintf("Same password used %d times (Double-click to edit %s)", len(d.SecretNames), firstSecret), themepkg.Yellow)
			hashLbl.TextSize = 12

			editBtn := widget.NewButtonWithIcon("", theme.DocumentCreateIcon(), func() {
				if firstSecret != "" {
					openEditSecret(firstSecret)
				}
			})
			editBtn.Importance = widget.LowImportance

			warnIcon := widget.NewIcon(theme.WarningIcon())
			rowContent := container.NewBorder(
				nil, nil,
				warnIcon,
				container.NewCenter(editBtn),
				container.NewVBox(nameLbl, hashLbl),
			)

			itemCardBg := canvas.NewRectangle(themepkg.Surface1)
			itemCardBg.CornerRadius = 8
			itemCard := newDoubleClickableCard(
				container.NewStack(itemCardBg, container.NewPadded(rowContent)),
				func() {
					if firstSecret != "" {
						openEditSecret(firstSecret)
					}
				},
			)
			findings.Add(itemCard)
		}
	}

	// Missing 2FA
	if len(result.Missing2FA) > 0 {
		tfaHeader := widget.NewLabelWithStyle(
			fmt.Sprintf("MISSING TWO-FACTOR AUTH (%d)", len(result.Missing2FA)),
			fyne.TextAlignLeading,
			fyne.TextStyle{Bold: true},
		)
		findings.Add(tfaHeader)

		for _, m := range result.Missing2FA {
			secretName := m.SecretName
			nameLbl := canvas.NewText(secretName, themepkg.Foreground)
			nameLbl.TextSize = 14
			nameLbl.TextStyle = fyne.TextStyle{Bold: true}

			desc := "No TOTP/2FA configured (Double-click to setup 2FA)"
			if m.URL != "" {
				desc = m.URL + " — No 2FA (Double-click to configure)"
			}
			descLbl := canvas.NewText(desc, themepkg.Muted)
			descLbl.TextSize = 12

			editBtn := widget.NewButtonWithIcon("", theme.DocumentCreateIcon(), func() {
				openEditSecret(secretName)
			})
			editBtn.Importance = widget.LowImportance

			shieldIcon := widget.NewIcon(theme.InfoIcon())
			rowContent := container.NewBorder(
				nil, nil,
				shieldIcon,
				container.NewCenter(editBtn),
				container.NewVBox(nameLbl, descLbl),
			)

			itemCardBg := canvas.NewRectangle(themepkg.Surface1)
			itemCardBg.CornerRadius = 8
			itemCard := newDoubleClickableCard(
				container.NewStack(itemCardBg, container.NewPadded(rowContent)),
				func() { openEditSecret(secretName) },
			)
			findings.Add(itemCard)
		}
	}

	if len(result.CompromisedPasswords) == 0 && len(result.WeakPasswords) == 0 && len(result.DuplicatePasswords) == 0 && len(result.Missing2FA) == 0 {
		emptyIcon := widget.NewIcon(theme.ConfirmIcon())
		emptyLabel := widget.NewLabelWithStyle(
			"Everything looks great! No security issues found.",
			fyne.TextAlignCenter,
			fyne.TextStyle{Bold: true},
		)
		findings.Add(container.NewCenter(
			container.NewVBox(
				emptyIcon,
				emptyLabel,
			),
		))
	}

	// ── Refresh button ──
	refreshBtn := widget.NewButtonWithIcon("Refresh Analysis", theme.ViewRefreshIcon(), func() {
		setRight(g.buildWatchtowerView(setRight))
	})
	refreshBtn.Importance = widget.HighImportance

	// ── Assemble ──
	topSection := container.NewVBox(
		scoreBanner,
		statsGrid,
		refreshBtn,
		widget.NewSeparator(),
	)

	scrollContent := container.NewVBox(findings)
	contentWithScroll := container.NewBorder(
		topSection,
		nil, nil, nil,
		container.NewScroll(scrollContent),
	)

	return container.NewPadded(contentWithScroll)
}

// ── Watchtower Helpers ──

func (g *GUI) countWatchtowerIssues(result *watchtower.WatchtowerResult) int {
	count := 0
	count += len(result.CompromisedPasswords)
	count += result.SecretsWithWeakPass
	count += len(result.DuplicatePasswords)
	count += result.SecretsWithNoOTP
	count += result.ExpiringCertificates
	return count
}

func (g *GUI) computeWatchtowerScore(result *watchtower.WatchtowerResult) int {
	if result.AnalyzedPasswordCount == 0 {
		return 100
	}

	vulnerable := len(result.CompromisedPasswords)*2 + result.SecretsWithWeakPass + len(result.DuplicatePasswords)
	if vulnerable > result.AnalyzedPasswordCount {
		vulnerable = result.AnalyzedPasswordCount
	}

	safe := result.AnalyzedPasswordCount - vulnerable
	score := int((float64(safe) / float64(result.AnalyzedPasswordCount)) * 100.0)
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func scoreBannerColor(score int) color.NRGBA {
	switch {
	case score >= 90:
		return themepkg.Success
	case score >= 70:
		return themepkg.Yellow
	default:
		return themepkg.Error
	}
}

func scoreLabelText(score int) string {
	switch {
	case score >= 90:
		return "Excellent — Strong security posture"
	case score >= 70:
		return "Good — A few password improvements recommended"
	case score >= 50:
		return "Fair — Several duplicate or weak passwords found"
	default:
		return "Action Required — Multiple weak or reused passwords detected"
	}
}

func buildStatCard(label, value string, accentColor color.NRGBA) fyne.CanvasObject {
	valueLbl := canvas.NewText(value, themepkg.Foreground)
	valueLbl.Alignment = fyne.TextAlignCenter
	valueLbl.TextSize = 20
	valueLbl.TextStyle = fyne.TextStyle{Bold: true}

	labelLbl := canvas.NewText(label, themepkg.Muted)
	labelLbl.Alignment = fyne.TextAlignCenter
	labelLbl.TextSize = 11

	accent := canvas.NewRectangle(accentColor)
	accent.SetMinSize(fyne.NewSize(1, 3))
	accent.CornerRadius = 1

	bg := canvas.NewRectangle(themepkg.Surface2)
	bg.CornerRadius = 8

	border := canvas.NewRectangle(color.Transparent)
	border.StrokeColor = themepkg.GlassBorder
	border.StrokeWidth = 1
	border.CornerRadius = 8

	return container.NewStack(
		bg,
		border,
		container.NewPadded(
			container.NewBorder(
				accent, nil, nil, nil,
				container.NewCenter(container.NewVBox(valueLbl, labelLbl)),
			),
		),
	)
}

func parseHexColor(hex string) color.NRGBA {
	hex = strings.TrimPrefix(hex, "#")
	var r, g, b uint8
	if _, err := fmt.Sscanf(hex, "%02x%02x%02x", &r, &g, &b); err != nil {
		// Malformed hex color; return opaque black as a safe fallback.
		return color.NRGBA{A: 0xFF}
	}
	return color.NRGBA{R: r, G: g, B: b, A: 0xFF}
}
