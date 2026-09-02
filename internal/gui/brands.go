package gui

import (
	"image/color"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"github.com/raynosc/vlt/internal/config"
	"github.com/raynosc/vlt/internal/secret"
	themepkg "github.com/raynosc/vlt/internal/theme"
)

// brandInfo holds display info for a recognized brand.
type brandInfo struct {
	Color   color.NRGBA
	Symbol  string // single character or emoji-style symbol
	Aliases []string
}

// brandRegistry maps recognizable brand names/keywords to their visual identity.
// Keywords are matched against secret name (lowercase) and URL domain.
var brandRegistry = map[string]brandInfo{
	"1password": {
		Color:   color.NRGBA{R: 0x0A, G: 0x85, B: 0xEA, A: 0xFF}, // 1Password blue
		Symbol:  "1",
		Aliases: []string{"1password.com", "1password", "my.1password.com", "onepassword"},
	},
	"arc": {
		Color:   color.NRGBA{R: 0x18, G: 0x18, B: 0x1B, A: 0xFF}, // Arc dark
		Symbol:  "A",
		Aliases: []string{"arc.dev", "arc.net", "arc browser", "arc()", "arc"},
	},
	"firefox": {
		Color:   color.NRGBA{R: 0xFF, G: 0x71, B: 0x39, A: 0xFF}, // Firefox orange
		Symbol:  "F",
		Aliases: []string{"firefox.com", "accounts.firefox.com", "mozilla.org", "firefox", "mozilla"},
	},
	"amazon": {
		Color:   color.NRGBA{R: 0xFF, G: 0x99, B: 0x00, A: 0xFF}, // Amazon orange
		Symbol:  "a",
		Aliases: []string{"amazon.com", "amazon.es", "amazon.de", "amazon.co.uk", "amazon.com.mx", "amazon"},
	},
	// ── Financial & Banking (Uruguay & Regional) ──
	"abitab": {
		Color:   color.NRGBA{R: 0x00, G: 0x33, B: 0x66, A: 0xFF}, // Abitab navy
		Symbol:  "A",
		Aliases: []string{"abitab.com.uy", "abitab"},
	},
	"brou": {
		Color:   color.NRGBA{R: 0x00, G: 0x55, B: 0x99, A: 0xFF}, // Banco República blue
		Symbol:  "B",
		Aliases: []string{"brou.com.uy", "bancorepublica", "ebrou.brou.com.uy", "brou"},
	},
	"itau": {
		Color:   color.NRGBA{R: 0xEC, G: 0x70, B: 0x00, A: 0xFF}, // Itaú orange
		Symbol:  "I",
		Aliases: []string{"itau.com.uy", "itau.com.br", "itau.com.ar", "itau"},
	},
	"santander": {
		Color:   color.NRGBA{R: 0xEC, G: 0x00, B: 0x00, A: 0xFF}, // Santander red
		Symbol:  "S",
		Aliases: []string{"santander.com.uy", "santander.com.ar", "santander.es", "santander.com", "santander"},
	},
	"scotiabank": {
		Color:   color.NRGBA{R: 0xEC, G: 0x11, B: 0x1A, A: 0xFF}, // Scotiabank red
		Symbol:  "S",
		Aliases: []string{"scotiabank.com.uy", "scotiabank.com", "scotiabank"},
	},
	"bbva": {
		Color:   color.NRGBA{R: 0x00, G: 0x44, B: 0x81, A: 0xFF}, // BBVA blue
		Symbol:  "B",
		Aliases: []string{"bbva.com.uy", "bbva.com.ar", "bbva.es", "bbva.com", "bbva"},
	},
	"midinero": {
		Color:   color.NRGBA{R: 0x00, G: 0xB0, B: 0x74, A: 0xFF}, // Midinero green
		Symbol:  "M",
		Aliases: []string{"midinero.com.uy", "auth.midinero.com.uy", "midinero"},
	},
	"redpagos": {
		Color:   color.NRGBA{R: 0x00, G: 0x52, B: 0x9B, A: 0xFF}, // Redpagos blue
		Symbol:  "R",
		Aliases: []string{"redpagos.com.uy", "redpagos"},
	},
	"mercadopago": {
		Color:   color.NRGBA{R: 0x00, G: 0x9E, B: 0xE3, A: 0xFF}, // Mercado Pago light blue
		Symbol:  "M",
		Aliases: []string{"mercadopago.com", "mercadopago.com.uy", "mercadolibre.com", "mercadolibre", "mercadopago"},
	},
	"prex": {
		Color:   color.NRGBA{R: 0x78, G: 0x24, B: 0xB4, A: 0xFF}, // Prex purple
		Symbol:  "P",
		Aliases: []string{"prexcard.com", "prex"},
	},
	"bna": {
		Color:   color.NRGBA{R: 0x1C, G: 0x6E, B: 0x8C, A: 0xFF}, // Banco Nación blue
		Symbol:  "B",
		Aliases: []string{"bna.com.ar", "banconacion"},
	},
	"btgpactual": {
		Color:   color.NRGBA{R: 0x0A, G: 0x22, B: 0x40, A: 0xFF}, // BTG Pactual navy
		Symbol:  "B",
		Aliases: []string{"btgpactual.com", "btgpactual"},
	},
	"bandes": {
		Color:   color.NRGBA{R: 0xD4, G: 0x14, B: 0x1E, A: 0xFF}, // Bandes red
		Symbol:  "B",
		Aliases: []string{"bandes.com.uy", "bandes"},
	},
	"heritage": {
		Color:   color.NRGBA{R: 0x33, G: 0x33, B: 0x33, A: 0xFF}, // Heritage grey
		Symbol:  "H",
		Aliases: []string{"bancoheritage.com", "heritage"},
	},
	"microsoft": {
		Color:   color.NRGBA{R: 0x00, G: 0x78, B: 0xD4, A: 0xFF}, // Microsoft blue
		Symbol:  "M",
		Aliases: []string{"ms", "msft", "office", "office.com", "onedrive", "sharepoint", "microsoft.com", "login.microsoftonline.com", "microsoft365", "m365"},
	},
	"outlook": {
		Color:   color.NRGBA{R: 0x00, G: 0x72, B: 0xC6, A: 0xFF}, // Outlook blue
		Symbol:  "O",
		Aliases: []string{"outlook.com", "outlook.office.com", "outlook.live.com", "hotmail.com", "live.com", "outlook", "hotmail"},
	},
	"azure": {
		Color:   color.NRGBA{R: 0x00, G: 0x78, B: 0xD4, A: 0xFF}, // Azure blue
		Symbol:  "A",
		Aliases: []string{"azure-devops", "dev.azure.com", "dev.azure", "azure.com", "portal.azure.com", "azdevops", "azure"},
	},
	"github": {
		Color:   color.NRGBA{R: 0x24, G: 0x29, B: 0x2E, A: 0xFF}, // GitHub dark
		Symbol:  "G",
		Aliases: []string{"gh", "github.com", "github", "gh-token", "github-token"},
	},
	"gitlab": {
		Color:   color.NRGBA{R: 0x29, G: 0x29, B: 0x61, A: 0xFF}, // GitLab deep purple (high contrast for orange logo)
		Symbol:  "G",
		Aliases: []string{"gitlab.com", "gitlab"},
	},
	"gmail": {
		Color:   color.NRGBA{R: 0xEA, G: 0x43, B: 0x35, A: 0xFF}, // Gmail red
		Symbol:  "M",
		Aliases: []string{"mail.google.com", "gmail.com", "googlemail.com", "gmail", "google-mail"},
	},
	"drive": {
		Color:   color.NRGBA{R: 0x34, G: 0xA8, B: 0x53, A: 0xFF}, // Drive green
		Symbol:  "D",
		Aliases: []string{"drive.google.com", "docs.google.com", "sheets.google.com", "google-drive", "gdrive", "drive"},
	},
	"youtube": {
		Color:   color.NRGBA{R: 0xFF, G: 0x00, B: 0x00, A: 0xFF}, // YouTube red
		Symbol:  "Y",
		Aliases: []string{"youtube.com", "youtu.be", "youtube"},
	},
	"google": {
		Color:   color.NRGBA{R: 0x42, G: 0x85, B: 0xF4, A: 0xFF}, // Google blue
		Symbol:  "G",
		Aliases: []string{"gcp", "google.com", "firebase", "accounts.google.com", "google"},
	},
	"aws": {
		Color:   color.NRGBA{R: 0xFF, G: 0x99, B: 0x00, A: 0xFF}, // AWS orange
		Symbol:  "A",
		Aliases: []string{"amazon-web-services", "aws.amazon", "signin.aws.amazon.com", "console.aws.amazon.com", "aws.training", "aws-root", "aws-cli", "aws"},
	},
	"atlassian": {
		Color:   color.NRGBA{R: 0x00, G: 0x52, B: 0xCC, A: 0xFF}, // Atlassian blue
		Symbol:  "A",
		Aliases: []string{"atlassian.net", "atlassian.com", "atlassian"},
	},
	"jira": {
		Color:   color.NRGBA{R: 0x00, G: 0x52, B: 0xCC, A: 0xFF}, // Jira blue
		Symbol:  "J",
		Aliases: []string{"jira.atlassian.net", "jira.com", "jira"},
	},
	"confluence": {
		Color:   color.NRGBA{R: 0x00, G: 0x52, B: 0xCC, A: 0xFF}, // Confluence blue
		Symbol:  "C",
		Aliases: []string{"confluence.atlassian.net", "confluence"},
	},
	"bitbucket": {
		Color:   color.NRGBA{R: 0x00, G: 0x52, B: 0xCC, A: 0xFF}, // Bitbucket blue
		Symbol:  "B",
		Aliases: []string{"bitbucket.org", "bitbucket"},
	},
	"trello": {
		Color:   color.NRGBA{R: 0x00, G: 0x79, B: 0xBF, A: 0xFF}, // Trello blue
		Symbol:  "T",
		Aliases: []string{"trello.com", "trello"},
	},
	"kubernetes": {
		Color:   color.NRGBA{R: 0x32, G: 0x6C, B: 0xE5, A: 0xFF}, // Kubernetes blue
		Symbol:  "K",
		Aliases: []string{"kubernetes.io", "k8s", "kubernetes", "kube"},
	},
	"slack": {
		Color:   color.NRGBA{R: 0x4A, G: 0x15, B: 0x4B, A: 0xFF}, // Slack purple
		Symbol:  "S",
		Aliases: []string{"slack.com", "slack"},
	},
	"discord": {
		Color:   color.NRGBA{R: 0x58, G: 0x65, B: 0xF2, A: 0xFF}, // Discord blurple
		Symbol:  "D",
		Aliases: []string{"discord.com", "discord"},
	},
	"spotify": {
		Color:   color.NRGBA{R: 0x1D, G: 0xB9, B: 0x54, A: 0xFF}, // Spotify green
		Symbol:  "S",
		Aliases: []string{"spotify.com", "spotify"},
	},
	"netflix": {
		Color:   color.NRGBA{R: 0xE5, G: 0x09, B: 0x14, A: 0xFF}, // Netflix red
		Symbol:  "N",
		Aliases: []string{"netflix.com", "netflix"},
	},
	"stripe": {
		Color:   color.NRGBA{R: 0x63, G: 0x5B, B: 0xFF, A: 0xFF}, // Stripe purple
		Symbol:  "S",
		Aliases: []string{"stripe.com", "stripe"},
	},
	"docker": {
		Color:   color.NRGBA{R: 0x24, G: 0x96, B: 0xED, A: 0xFF}, // Docker blue
		Symbol:  "D",
		Aliases: []string{"docker.com", "hub.docker.com", "hub.docker", "docker"},
	},
	"figma": {
		Color:   color.NRGBA{R: 0xF2, G: 0x4E, B: 0x1E, A: 0xFF}, // Figma red-orange
		Symbol:  "F",
		Aliases: []string{"figma.com", "figma"},
	},
	"notion": {
		Color:   color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0xFF}, // Notion black
		Symbol:  "N",
		Aliases: []string{"notion.so", "notion.site", "notion"},
	},
	"dropbox": {
		Color:   color.NRGBA{R: 0x00, G: 0x61, B: 0xFF, A: 0xFF}, // Dropbox blue
		Symbol:  "D",
		Aliases: []string{"dropbox.com", "dropbox"},
	},
	"twitter": {
		Color:   color.NRGBA{R: 0x11, G: 0x11, B: 0x11, A: 0xFF}, // X / Twitter black
		Symbol:  "X",
		Aliases: []string{"x.com", "twitter.com", "tweet", "twitter"},
	},
	"linkedin": {
		Color:   color.NRGBA{R: 0x0A, G: 0x66, B: 0xC2, A: 0xFF}, // LinkedIn blue
		Symbol:  "L",
		Aliases: []string{"linkedin.com", "linkedin"},
	},
	"facebook": {
		Color:   color.NRGBA{R: 0x18, G: 0x77, B: 0xF2, A: 0xFF}, // Facebook blue
		Symbol:  "F",
		Aliases: []string{"fb", "facebook.com", "meta", "instagram", "instagram.com"},
	},
	"apple": {
		Color:   color.NRGBA{R: 0x55, G: 0x55, B: 0x55, A: 0xFF}, // Apple grey
		Symbol:  "A",
		Aliases: []string{"icloud", "apple.com", "icloud.com", "mac", "iphone", "ipad", "app-store", "apple"},
	},
	"cloudflare": {
		Color:   color.NRGBA{R: 0xF3, G: 0x80, B: 0x20, A: 0xFF}, // Cloudflare orange
		Symbol:  "C",
		Aliases: []string{"cloudflare.com", "cloudflare"},
	},
	"heroku": {
		Color:   color.NRGBA{R: 0x43, G: 0x00, B: 0x98, A: 0xFF}, // Heroku purple
		Symbol:  "H",
		Aliases: []string{"heroku.com", "heroku"},
	},
	"vercel": {
		Color:   color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0xFF}, // Vercel black
		Symbol:  "V",
		Aliases: []string{"vercel.com", "vercel", "nextjs"},
	},
	"digitalocean": {
		Color:   color.NRGBA{R: 0x00, G: 0x80, B: 0xFF, A: 0xFF}, // DO blue
		Symbol:  "D",
		Aliases: []string{"digitalocean.com", "digitalocean"},
	},
	"mongodb": {
		Color:   color.NRGBA{R: 0x00, G: 0xED, B: 0x64, A: 0xFF}, // MongoDB green
		Symbol:  "M",
		Aliases: []string{"mongo", "mongodb.com", "atlas", "mongodb"},
	},
	"redis": {
		Color:   color.NRGBA{R: 0xDC, G: 0x38, B: 0x2D, A: 0xFF}, // Redis red
		Symbol:  "R",
		Aliases: []string{"redis.io", "redis"},
	},
	"postgres": {
		Color:   color.NRGBA{R: 0x33, G: 0x67, B: 0x91, A: 0xFF}, // Postgres blue
		Symbol:  "P",
		Aliases: []string{"postgresql.org", "postgres", "postgresql", "psql"},
	},
	"mysql": {
		Color:   color.NRGBA{R: 0x00, G: 0x75, B: 0x8F, A: 0xFF}, // MySQL blue
		Symbol:  "M",
		Aliases: []string{"mysql.com", "mysql", "mariadb"},
	},
	"npm": {
		Color:   color.NRGBA{R: 0xCB, G: 0x38, B: 0x37, A: 0xFF}, // npm red
		Symbol:  "N",
		Aliases: []string{"npmjs.com", "yarn", "pnpm", "npm"},
	},
	"cloud": {
		Color:   color.NRGBA{R: 0x42, G: 0x85, B: 0xF4, A: 0xFF}, // Generic cloud blue
		Symbol:  "C",
		Aliases: []string{"gcloud", "cloud", "gcp", "ibm", "oracle", "salesforce"},
	},
	"server": {
		Color:   color.NRGBA{R: 0x0C, G: 0x72, B: 0xE2, A: 0xFF}, // Server blue
		Symbol:  "S",
		Aliases: []string{"server", "vps", "host", "node", "cluster", "bastion", "gateway", "router"},
	},
	"terminal": {
		Color:   color.NRGBA{R: 0x10, G: 0xB9, B: 0x81, A: 0xFF}, // Terminal emerald
		Symbol:  ">",
		Aliases: []string{"ssh", "terminal", "console", "cli"},
	},
}

var (
	faviconCacheMu  sync.RWMutex
	faviconCache    = make(map[string]fyne.Resource)
	faviconFetching = make(map[string]bool)
)

// InferDomain extracts or deduces the domain associated with a secret.
func InferDomain(sec secret.Secret) string {
	meta := secret.UnmarshalPasswordMetadata(sec.Metadata)
	if meta != nil && meta.URL != "" {
		d := extractDomain(meta.URL)
		if d != "" {
			return d
		}
	}
	if meta != nil && meta.Username != "" && strings.Contains(meta.Username, "@") {
		parts := strings.Split(meta.Username, "@")
		if len(parts) == 2 && strings.Contains(parts[1], ".") {
			return strings.ToLower(strings.TrimSpace(parts[1]))
		}
	}
	// Check known brand keywords in secret name
	lowerName := strings.ToLower(sec.Name)
	for _, info := range brandRegistry {
		for _, alias := range info.Aliases {
			if strings.Contains(alias, ".") && strings.Contains(lowerName, strings.Split(alias, ".")[0]) {
				return alias
			}
		}
	}
	return ""
}

// brandPriorityOrder defines a deterministic evaluation order for brand detection.
// Specialized sub-brands (e.g. aws, gmail, jira, azure, server, terminal) MUST appear before
// parent companies (e.g. amazon, google, atlassian, microsoft) to prevent
// non-deterministic map iteration flipping and generic parent hijacking.
var brandPriorityOrder = []string{
	// ── Specialized Cloud & Dev Sub-Services (Highest Priority) ──
	"aws",
	"azure",
	"outlook",
	"gmail",
	"drive",
	"youtube",
	"jira",
	"confluence",
	"bitbucket",
	"trello",

	// ── Developer Platforms & Tools ──
	"github",
	"gitlab",
	"docker",
	"kubernetes",
	"cloudflare",
	"vercel",
	"heroku",
	"digitalocean",
	"mongodb",
	"redis",
	"postgres",
	"mysql",
	"npm",
	"server",
	"terminal",

	// ── Specialized Banking & Fintech ──
	"mercadopago",
	"midinero",
	"redpagos",
	"prex",
	"brou",
	"itau",
	"santander",
	"scotiabank",
	"bbva",
	"bna",
	"btgpactual",
	"bandes",
	"heritage",
	"abitab",
	"stripe",

	// ── Productivity & Communication ──
	"arc",
	"slack",
	"discord",
	"notion",
	"figma",
	"dropbox",
	"spotify",
	"netflix",
	"twitter",
	"linkedin",
	"facebook",

	// ── Parent Companies & Broader Ecosystems (Evaluated last) ──
	"amazon",
	"google",
	"microsoft",
	"atlassian",
	"apple",
	"1password",
	"firefox",
	"cloud",
}

// isIPOrServerName returns true if the name matches an IP address (e.g. 10.213.2, 192.168.1.1)
func isIPOrServerName(name string) bool {
	trimmed := strings.TrimSpace(name)
	if len(trimmed) > 0 && trimmed[0] >= '0' && trimmed[0] <= '9' && strings.Contains(trimmed, ".") {
		return true
	}
	return false
}

// detectBrand returns the brand key, brand info and true if the secret name or URL matches a known brand.
// Evaluation is deterministic:
//
//	Pass 1 (Strongest): Matches keywords against the Secret Name.
//	Pass 2 (Fallback): Matches keywords against the URL / Domain.
func detectBrand(name, url string) (string, brandInfo, bool) {
	lowerName := strings.ToLower(name)
	lowerURL := strings.ToLower(url)

	// Direct IP address detection -> server icon
	if isIPOrServerName(name) {
		return "server", brandRegistry["server"], true
	}

	// ── Pass 1: Secret Name Match (Strongest signal) ──
	for _, brand := range brandPriorityOrder {
		info, ok := brandRegistry[brand]
		if !ok {
			continue
		}
		// Direct name match
		if strings.Contains(lowerName, brand) {
			return brand, info, true
		}
		// Alias name match
		for _, alias := range info.Aliases {
			if strings.Contains(lowerName, alias) {
				return brand, info, true
			}
		}
	}

	// ── Pass 2: URL / Domain Match (Fallback if name didn't match) ──
	if lowerURL != "" {
		if isIPOrServerName(extractDomain(url)) {
			return "server", brandRegistry["server"], true
		}
		for _, brand := range brandPriorityOrder {
			info, ok := brandRegistry[brand]
			if !ok {
				continue
			}
			// Direct brand keyword in URL
			if strings.Contains(lowerURL, brand) {
				return brand, info, true
			}
			// Alias match in URL
			for _, alias := range info.Aliases {
				if strings.Contains(lowerURL, alias) {
					return brand, info, true
				}
			}
		}
	}

	return "", brandInfo{}, false
}

// iconContainer wraps custom downloaded favicon images in a clean dark squircle with subtle border.
func iconContainer(content fyne.CanvasObject, size string) fyne.CanvasObject {
	sz := sideIconSize(size)
	radius := cornerRadiusForSize(size)

	bg := canvas.NewRectangle(color.NRGBA{R: 0x1E, G: 0x29, B: 0x3B, A: 0xFF}) // Clean modern dark surface
	bg.SetMinSize(fyne.NewSize(sz, sz))
	bg.CornerRadius = radius

	border := canvas.NewRectangle(color.Transparent)
	border.StrokeColor = color.NRGBA{R: 0x33, G: 0x41, B: 0x55, A: 0x80}
	border.StrokeWidth = 1
	border.CornerRadius = radius

	paddedContent := container.New(
		layout.NewCustomPaddedLayout(3, 3, 3, 3),
		container.NewCenter(content),
	)

	return container.NewCenter(container.NewStack(bg, border, paddedContent))
}

// FaviconOrBrandIcon returns a brand SVG/badge icon or favicon image if available/cached.
func FaviconOrBrandIcon(sec secret.Secret, size string, onLoaded func()) fyne.CanvasObject {
	meta := secret.UnmarshalPasswordMetadata(sec.Metadata)
	url := ""
	if meta != nil {
		url = meta.URL
	}

	// 1. If it matches a known brand with an embedded vector SVG, use the vector SVG directly
	if brandKey, brand, ok := detectBrand(sec.Name, url); ok {
		if svgRes, has := brandSVGRegistry[brandKey]; has && svgRes != nil {
			return buildBrandSVGIcon(svgRes, brand, size)
		}
		return buildBrandIcon(brand, size)
	}

	// 2. Try favicon cache for custom website domains
	domain := InferDomain(sec)
	sz := sideIconSize(size)

	if domain != "" {
		faviconCacheMu.RLock()
		res, has := faviconCache[domain]
		faviconCacheMu.RUnlock()

		if !has {
			// Check disk cache first
			if diskRes := loadFaviconFromDisk(domain); diskRes != nil {
				faviconCacheMu.Lock()
				faviconCache[domain] = diskRes
				faviconCacheMu.Unlock()
				res = diskRes
				has = true
			}
		}

		if has && res != nil {
			img := canvas.NewImageFromResource(res)
			img.SetMinSize(fyne.NewSize(sz-6, sz-6))
			img.FillMode = canvas.ImageFillContain
			return iconContainer(img, size)
		}

		// Trigger background fetch if not already fetching
		faviconCacheMu.Lock()
		if !faviconFetching[domain] {
			faviconFetching[domain] = true
			faviconCacheMu.Unlock()
			go fetchAndCacheFavicon(domain, onLoaded)
		} else {
			faviconCacheMu.Unlock()
		}
	}

	return SecretIcon(sec, size)
}

func faviconDiskCacheDir() string {
	vaultDir, err := config.VaultDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(vaultDir, "cache", "favicons")
	_ = os.MkdirAll(dir, 0700)
	return dir
}

func loadFaviconFromDisk(domain string) *fyne.StaticResource {
	dir := faviconDiskCacheDir()
	if dir == "" {
		return nil
	}
	safeName := strings.ReplaceAll(domain, ":", "_") + ".png"
	filePath := filepath.Join(dir, safeName)
	data, err := os.ReadFile(filePath)
	if err != nil || len(data) < 100 {
		return nil
	}
	return fyne.NewStaticResource(domain+"_fav", data)
}

func saveFaviconToDisk(domain string, data []byte) {
	dir := faviconDiskCacheDir()
	if dir == "" || len(data) < 100 {
		return
	}
	safeName := strings.ReplaceAll(domain, ":", "_") + ".png"
	filePath := filepath.Join(dir, safeName)
	_ = os.WriteFile(filePath, data, 0600)
}

func fetchAndCacheFavicon(domain string, onLoaded func()) {
	url := "https://www.google.com/s2/favicons?domain=" + domain + "&sz=64"
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(url)
	if err == nil && resp.StatusCode == http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		buf, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
		if err == nil && len(buf) > 100 {
			res := fyne.NewStaticResource(domain+"_fav", buf)
			saveFaviconToDisk(domain, buf)
			faviconCacheMu.Lock()
			faviconCache[domain] = res
			faviconFetching[domain] = false
			faviconCacheMu.Unlock()
			if onLoaded != nil {
				fyne.Do(onLoaded)
			}
			return
		}
	}
	faviconCacheMu.Lock()
	faviconFetching[domain] = false
	faviconCacheMu.Unlock()
}

// BrandIcon returns a brand-colored icon (vector SVG or symbol) if the secret matches a known brand,
// otherwise falls back to the generic type icon.
func BrandIcon(sec secret.Secret, size string) fyne.CanvasObject {
	meta := secret.UnmarshalPasswordMetadata(sec.Metadata)
	url := ""
	if meta != nil {
		url = meta.URL
	}

	if brandKey, brand, ok := detectBrand(sec.Name, url); ok {
		if svgRes, has := brandSVGRegistry[brandKey]; has && svgRes != nil {
			return buildBrandSVGIcon(svgRes, brand, size)
		}
		return buildBrandIcon(brand, size)
	}
	return SecretIcon(sec, size)
}

// buildBrandSVGIcon renders the authentic vector SVG directly.
func buildBrandSVGIcon(svgRes *fyne.StaticResource, brand brandInfo, size string) fyne.CanvasObject {
	sz := sideIconSize(size)
	img := canvas.NewImageFromResource(svgRes)
	img.SetMinSize(fyne.NewSize(sz, sz))
	img.FillMode = canvas.ImageFillContain
	return container.NewCenter(img)
}

// buildBrandIcon creates an icon with brand color and text symbol.
func buildBrandIcon(brand brandInfo, size string) fyne.CanvasObject {
	sz := sideIconSize(size)
	bg := canvas.NewRectangle(brand.Color)
	bg.SetMinSize(fyne.NewSize(sz, sz))
	bg.CornerRadius = cornerRadiusForSize(size)

	symbol := canvas.NewText(brand.Symbol, color.White)
	symbol.Alignment = fyne.TextAlignCenter
	symbol.TextSize = fontSizeForSize(size)
	symbol.TextStyle = fyne.TextStyle{Bold: true}

	border := canvas.NewRectangle(color.Transparent)
	border.StrokeColor = themepkg.GlassBorder
	border.StrokeWidth = 1
	border.CornerRadius = cornerRadiusForSize(size)

	return container.NewCenter(container.NewStack(bg, border, container.NewCenter(symbol)))
}
