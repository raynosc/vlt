package parse

import (
	"encoding/csv"
	"fmt"
	"strings"
)

// Record represents a parsed password manager entry from CSV or JSON exports.
type Record struct {
	Title    string
	URL      string
	Username string
	Password string
	OTPAuth  string
	Tags     string
	Notes    string
}

// detectDelimiter inspects the header line to determine whether comma, semicolon, or tab is used.
func detectDelimiter(headerLine string) rune {
	delimiters := []rune{',', ';', '\t'}
	bestDelim := ','
	maxCols := 0

	for _, d := range delimiters {
		r := csv.NewReader(strings.NewReader(headerLine))
		r.Comma = d
		r.LazyQuotes = true
		r.FieldsPerRecord = -1
		cols, err := r.Read()
		if err == nil && len(cols) > maxCols {
			maxCols = len(cols)
			bestDelim = d
		}
	}

	return bestDelim
}

// normalizeHeaderKey cleans and standardizes header names for flexible matching.
func normalizeHeaderKey(h string) string {
	s := strings.ToLower(strings.TrimSpace(h))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, "-", "")
	return s
}

// matchColumnType returns the standardized field type for a normalized header name with explicit precedence.
func matchColumnType(norm string) string {
	switch norm {
	case "title", "name", "itemname":
		return "title"
	case "password", "pass", "secret", "loginpassword", "value":
		return "password"
	case "username", "user", "login", "email", "loginusername", "loginname", "useremail":
		return "username"
	case "url", "uri", "website", "loginuri", "link", "address", "webaddress":
		return "url"
	case "notes", "note", "comments", "comment", "extra", "description", "details":
		return "notes"
	case "otpauth", "otp", "totp", "onetimepassword", "logintotp", "2fa", "twofactor":
		return "otpauth"
	case "tags", "tag", "folder", "category", "grouping", "group":
		return "tags"
	// Secondary matches for title if no primary title is present
	case "account", "service", "entry":
		return "alt_title"
	default:
		return ""
	}
}

// cleanDomainTitle extracts a clean, readable name from a URL domain.
// e.g. "https://marta-jimenez.com:8443/" -> "marta-jimenez.com"
// e.g. "https://login.upv.es/" -> "upv.es"
func cleanDomainTitle(rawURL string) string {
	u := strings.TrimSpace(rawURL)
	if u == "" {
		return ""
	}
	// Strip protocol
	if idx := strings.Index(u, "://"); idx != -1 {
		u = u[idx+3:]
	}
	// Strip path and query
	if idx := strings.IndexAny(u, "/?#"); idx != -1 {
		u = u[:idx]
	}
	// Strip port
	if idx := strings.Index(u, ":"); idx != -1 {
		u = u[:idx]
	}
	// Strip www prefix
	u = strings.TrimPrefix(u, "www.")
	return u
}

// ParsePasswordCSV parses CSV export data from various password managers and browsers.
// It handles UTF-8 BOM, auto-detects delimiters (comma, semicolon, tab), and maps column names flexibly.
func ParsePasswordCSV(data []byte) ([]Record, error) {
	content := data
	// Strip UTF-8 BOM if present
	if len(content) >= 3 && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF {
		content = content[3:]
	}

	rawStr := strings.TrimSpace(string(content))
	if rawStr == "" {
		return nil, nil
	}

	// Determine best delimiter by checking first line
	firstNewline := strings.IndexAny(rawStr, "\r\n")
	headerLine := rawStr
	if firstNewline != -1 {
		headerLine = rawStr[:firstNewline]
	}
	delim := detectDelimiter(headerLine)

	reader := csv.NewReader(strings.NewReader(rawStr))
	reader.Comma = delim
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true

	allRecords, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read csv: %w", err)
	}

	if len(allRecords) < 2 {
		return nil, nil // header only or empty
	}

	header := allRecords[0]
	colIndices := make(map[string]int)

	for i, h := range header {
		colType := matchColumnType(normalizeHeaderKey(h))
		if colType != "" {
			if _, exists := colIndices[colType]; !exists {
				colIndices[colType] = i
			}
		}
	}

	// Fallback to alt_title (account, service) if no primary title column exists
	if _, hasTitle := colIndices["title"]; !hasTitle {
		if altIdx, hasAlt := colIndices["alt_title"]; hasAlt {
			colIndices["title"] = altIdx
		}
	}

	titleIdx, hasTitle := colIndices["title"]
	passIdx, hasPass := colIndices["password"]

	if !hasPass {
		var found []string
		for _, h := range header {
			if t := strings.TrimSpace(h); t != "" {
				found = append(found, t)
			}
		}
		return nil, fmt.Errorf("CSV missing required Password column. Found headers: [%s]", strings.Join(found, ", "))
	}

	urlIdx, hasURL := colIndices["url"]
	userIdx, hasUser := colIndices["username"]
	otpIdx, hasOTP := colIndices["otpauth"]
	tagsIdx, hasTags := colIndices["tags"]
	notesIdx, hasNotes := colIndices["notes"]

	safeGet := func(row []string, idx int, has bool) string {
		if !has || idx < 0 || idx >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[idx])
	}

	var records []Record
	for _, row := range allRecords[1:] {
		// Skip entirely blank rows
		allEmpty := true
		for _, f := range row {
			if strings.TrimSpace(f) != "" {
				allEmpty = false
				break
			}
		}
		if allEmpty {
			continue
		}

		password := safeGet(row, passIdx, hasPass)
		if password == "" {
			continue
		}

		title := safeGet(row, titleIdx, hasTitle)
		urlVal := safeGet(row, urlIdx, hasURL)

		// Smart title inference if Title is blank
		if title == "" && urlVal != "" {
			title = cleanDomainTitle(urlVal)
		}
		if title == "" {
			userVal := safeGet(row, userIdx, hasUser)
			if userVal != "" {
				title = userVal
			} else {
				title = "Imported Secret"
			}
		}

		rec := Record{
			Title:    title,
			Password: password,
			URL:      urlVal,
			Username: safeGet(row, userIdx, hasUser),
			OTPAuth:  safeGet(row, otpIdx, hasOTP),
			Tags:     safeGet(row, tagsIdx, hasTags),
			Notes:    safeGet(row, notesIdx, hasNotes),
		}

		records = append(records, rec)
	}

	return records, nil
}
