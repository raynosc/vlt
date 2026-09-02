package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/parse"
	"github.com/raynosc/vlt/internal/secret"
)

// updateAdd handles key events in the add secret form.
func (m model) updateAdd(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Ctrl+K cycles the kind selector (doesn't interfere with typing)
	if msg.Type == tea.KeyCtrlK {
		return m.cycleAddKind(), nil
	}

	// Ctrl+O toggles file mode (doesn't interfere with typing)
	if msg.Type == tea.KeyCtrlO {
		m.addFileMode = !m.addFileMode
		m.addFileInput.Reset()
		m.err = ""
		return m, nil
	}

	// Ctrl+G generates a random password in the value field
	if msg.Type == tea.KeyCtrlG {
		if m.addFileMode {
			m.err = "Cannot generate password in file mode"
			return m, nil
		}
		pw, err := generatePassword(24)
		if err != nil {
			m.err = fmt.Sprintf("Generate failed: %v", err)
			return m, nil
		}
		m.addValueInput.SetValue(string(pw))
		m.err = "✓ Password generated"
		return m, nil
	}

	switch msg.String() {
	case "esc":
		// Cancel and return to list
		m.state = stateList
		m.err = ""
		m.addNameInput.Reset()
		m.addValueInput.Reset()
		m.addFileInput.Reset()
		m.addUserInput.Reset()
		m.addSiteInput.Reset()
		m.addNotesInput.Reset()
		m.addKindIndex = 0
		m.addFileMode = false
		m.addFocusIndex = 0
		m.editMode = false
		m.editSecretName = ""
		m.addNameInput.Focus()
		m.addValueInput.Blur()
		m.secrets, _ = m.st.List()
		return m, nil

	case "tab":
		// Toggle focus between fields (user/site/notes only for password kind)
		maxFocus := 1
		if m.isPasswordKind() && !m.addFileMode {
			maxFocus = 4 // name → value → user → site → notes
		}
		m.addFocusIndex = (m.addFocusIndex + 1) % (maxFocus + 1)
		m = m.focusAddField()
		return m, nil

	case "enter":
		maxFocus := 1
		if m.isPasswordKind() && !m.addFileMode {
			maxFocus = 4
		}
		if m.addFocusIndex == maxFocus {
			// On last field, save
			return m.saveNewSecret()
		}
		// Move to next field
		m.addFocusIndex++
		m = m.focusAddField()
		return m, nil
	}

	// Delegate typing to focused input
	var cmd tea.Cmd
	switch m.addFocusIndex {
	case 0:
		m.addNameInput, cmd = m.addNameInput.Update(msg)
	case 1:
		if m.addFileMode {
			m.addFileInput, cmd = m.addFileInput.Update(msg)
		} else {
			m.addValueInput, cmd = m.addValueInput.Update(msg)
		}
	case 2:
		m.addUserInput, cmd = m.addUserInput.Update(msg)
	case 3:
		m.addSiteInput, cmd = m.addSiteInput.Update(msg)
	case 4:
		m.addNotesInput, cmd = m.addNotesInput.Update(msg)
	}
	return m, cmd
}

// focusAddField blurs all add fields and focuses the one at addFocusIndex.
func (m model) focusAddField() model {
	m.addNameInput.Blur()
	m.addValueInput.Blur()
	m.addFileInput.Blur()
	m.addUserInput.Blur()
	m.addSiteInput.Blur()
	m.addNotesInput.Blur()
	switch m.addFocusIndex {
	case 0:
		m.addNameInput.Focus()
	case 1:
		if m.addFileMode {
			m.addFileInput.Focus()
		} else {
			m.addValueInput.Focus()
		}
	case 2:
		m.addUserInput.Focus()
	case 3:
		m.addSiteInput.Focus()
	case 4:
		m.addNotesInput.Focus()
	}
	return m
}

// isPasswordKind returns true if the currently selected kind is password.
func (m model) isPasswordKind() bool {
	return secret.ValidKinds()[m.addKindIndex] == secret.KindPassword
}

// cycleAddKind advances the kind selector to the next valid kind.
func (m model) cycleAddKind() model {
	m.addKindIndex = (m.addKindIndex + 1) % len(secret.ValidKinds())
	return m
}

// saveNewSecret encrypts and stores the new secret, then returns to list.
func (m model) saveNewSecret() (tea.Model, tea.Cmd) {
	if m.addFileMode {
		return m.saveNewSecretFromFile()
	}

	name := m.addNameInput.Value()
	value := m.addValueInput.Value()

	if name == "" {
		m.err = "Name cannot be empty"
		return m, nil
	}
	if value == "" {
		m.err = "Value cannot be empty"
		return m, nil
	}

	// Encrypt the value
	ciphertext, nonce, err := m.engine.Encrypt([]byte(value), m.key)
	if err != nil {
		m.err = fmt.Sprintf("Encryption failed: %v", err)
		return m, nil
	}

	// Pack nonce || ciphertext for storage
	encryptedBlob := make([]byte, len(nonce)+len(ciphertext))
	copy(encryptedBlob, nonce)
	copy(encryptedBlob[len(nonce):], ciphertext)

	// Use selected kind from kind selector
	kind := secret.ValidKinds()[m.addKindIndex]

	// Build metadata and notes for password entries
	var metadataStr, notesStr string
	if kind == secret.KindPassword {
		username := m.addUserInput.Value()
		site := m.addSiteInput.Value()
		notesStr = m.addNotesInput.Value()
		if username != "" || site != "" {
			meta := map[string]string{}
			if username != "" {
				meta[secret.MetadataKeyUsername] = username
			}
			if site != "" {
				meta[secret.MetadataKeySite] = site
			}
			b, _ := json.Marshal(meta)
			metadataStr = string(b)
		}
	}

	// Create the secret
	// Encrypt metadata fields for v7 schema
	encName, nonceName, _ := m.engine.Encrypt([]byte(name), m.key)
	encNotes, nonceNotes, _ := m.engine.Encrypt([]byte(notesStr), m.key)
	encTags, nonceTags, _ := m.engine.Encrypt([]byte(""), m.key)
	encMeta, nonceMeta, _ := m.engine.Encrypt([]byte(metadataStr), m.key)

	sec := secret.Secret{
		Name:              name,
		NameLookup:        crypto.ComputeNameLookup(m.key, name),
		Kind:              kind,
		EncryptedValue:    encryptedBlob,
		EncryptedName:     crypto.PackEnvelope(nonceName, encName),
		EncryptedNotes:    crypto.PackEnvelope(nonceNotes, encNotes),
		EncryptedTags:     crypto.PackEnvelope(nonceTags, encTags),
		EncryptedMetadata: crypto.PackEnvelope(nonceMeta, encMeta),
	}

	if m.editMode {
		// In edit mode, delete the original secret first, then store the updated one.
		if err := m.st.DeleteByLookup(crypto.ComputeNameLookup(m.key, m.editSecretName)); err != nil { // hard Delete: internal replace, not user deletion
			m.err = fmt.Sprintf("Delete failed: %v", err)
			return m, nil
		}
	}

	if err := m.st.Store(sec); err != nil {
		// Check for duplicate
		m.err = fmt.Sprintf("Store failed: %v. Use --overwrite to replace", err)
		return m, nil
	}

	return m.afterSave(), nil
}

// saveNewSecretFromFile reads a file, detects format, encrypts, and stores.
func (m model) saveNewSecretFromFile() (tea.Model, tea.Cmd) {
	name := m.addNameInput.Value()
	filePath := m.addFileInput.Value()

	if name == "" {
		// Auto-generate name from filename if empty
		name = strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
	}
	if filePath == "" {
		m.err = "File path cannot be empty"
		return m, nil
	}

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			m.err = "Error: File not found"
		} else if os.IsPermission(err) {
			m.err = "Error: Unable to read file"
		} else {
			m.err = fmt.Sprintf("Error: Unable to read file: %v", err)
		}
		return m, nil
	}
	defer crypto.Zeroize(data)

	// Detect format and auto-set kind and metadata
	format, detectErr := parse.Detect(data)
	if detectErr != nil {
		m.err = fmt.Sprintf("Error: Unable to detect format: %v", detectErr)
		return m, nil
	}

	var kind secret.Kind
	var metadataStr string

	switch format {
	case parse.FormatX509PEM:
		kind = secret.KindCertificate
		meta, err := parse.ParseX509(data)
		if err != nil {
			m.err = fmt.Sprintf("Error: Unable to parse certificate: %v", err)
			return m, nil
		}
		metaBytes, _ := json.Marshal(meta)
		metadataStr = string(metaBytes)

	case parse.FormatSSHPrivate:
		kind = secret.KindSSHKey
		meta, err := parse.ParseSSHPrivate(data)
		if err != nil {
			m.err = fmt.Sprintf("Error: Unable to parse SSH key: %v", err)
			return m, nil
		}
		metaBytes, _ := json.Marshal(meta)
		metadataStr = string(metaBytes)

	case parse.FormatSSHPublic:
		kind = secret.KindSSHKey
		meta, err := parse.ParseSSHPublic(data)
		if err != nil {
			m.err = fmt.Sprintf("Error: Unable to parse SSH key: %v", err)
			return m, nil
		}
		metaBytes, _ := json.Marshal(meta)
		metadataStr = string(metaBytes)

	case parse.FormatPKCS12:
		kind = secret.KindCertificate
		meta, err := parse.ParsePKCS12(data, "")
		if err != nil {
			m.err = fmt.Sprintf("Error: Unable to parse PKCS12: %v", err)
			return m, nil
		}
		metaBytes, _ := json.Marshal(meta)
		metadataStr = string(metaBytes)

	default:
		kind = secret.KindPassword
	}

	// Encrypt the raw file data
	ciphertext, nonce, err := m.engine.Encrypt(data, m.key)
	if err != nil {
		m.err = fmt.Sprintf("Encryption failed: %v", err)
		return m, nil
	}
	// Data zeroized by deferred Zeroize above.

	// Pack nonce || ciphertext for storage
	encryptedBlob := make([]byte, len(nonce)+len(ciphertext))
	copy(encryptedBlob, nonce)
	copy(encryptedBlob[len(nonce):], ciphertext)

	sec := secret.Secret{
		Name:           name,
		Kind:           kind,
		EncryptedValue: encryptedBlob,
		Metadata:       metadataStr,
	}
	if err := encryptSecretMetadata(&sec, m.engine, m.key); err != nil {
		m.err = fmt.Sprintf("Encryption failed: %v", err)
		return m, nil
	}

	if err := m.st.Store(sec); err != nil {
		m.err = fmt.Sprintf("Store failed: %v. Use --overwrite to replace", err)
		return m, nil
	}

	return m.afterSave(), nil
}

// afterSave resets form state, refreshes list, and returns to list view.
func (m model) afterSave() model {
	// Log audit entry for the add/edit
	action := "secret_add"
	if m.editMode {
		action = "secret_edit"
	}
	kind := secret.ValidKinds()[m.addKindIndex]
	_ = m.st.LogAction(action, m.addNameInput.Value(), string(kind))

	// Refresh audit log for footer
	entries, _ := m.st.GetAuditLog(3)
	m.auditEntries = entries

	secrets, err := m.loadSecrets()
	if err != nil {
		m.err = fmt.Sprintf("List failed: %v", err)
		return m
	}
	m.secrets = secrets
	m.state = stateList
	m.err = ""
	m.addNameInput.Reset()
	m.addValueInput.Reset()
	m.addFileInput.Reset()
	m.addUserInput.Reset()
	m.addSiteInput.Reset()
	m.addNotesInput.Reset()
	m.addKindIndex = 0
	m.addFileMode = false
	m.addFocusIndex = 0
	m.editMode = false
	m.editSecretName = ""
	m.addNameInput.Focus()
	m.addValueInput.Blur()
	return m
}

// viewAdd renders the add secret form.
func (m model) viewAdd() string {
	title := titleStyle.Render("Add Secret")

	// Show current kind
	kind := secret.ValidKinds()[m.addKindIndex]
	kindRow := fmt.Sprintf("\n  %s %s  [ctrl+k: cycle kind]\n", labelStyle.Render("Kind:"), string(kind))

	// Show mode indicator
	var modeRow string
	if m.addFileMode {
		modeRow = fmt.Sprintf("  %s %s  [ctrl+o: switch to manual]\n", labelStyle.Render("Mode:"), "file import")
	} else {
		modeRow = fmt.Sprintf("  %s %s  [ctrl+o: switch to file]\n", labelStyle.Render("Mode:"), "manual")
	}

	help := helpStyle.Render(addFooterText)

	var valueSection string
	if m.addFileMode {
		valueSection = fmt.Sprintf("  %s\n  %s", labelStyle.Render("File Path:"), m.addFileInput.View())
	} else {
		valueSection = fmt.Sprintf("  %s\n  %s", labelStyle.Render("Value:"), m.addValueInput.View())
	}

	// Password extra fields
	var extraFields string
	if m.isPasswordKind() && !m.addFileMode {
		extraFields = fmt.Sprintf("\n  %s\n  %s\n\n  %s\n  %s\n\n  %s\n  %s",
			labelStyle.Render("Username:"), m.addUserInput.View(),
			labelStyle.Render("Site:"), m.addSiteInput.View(),
			labelStyle.Render("Notes:"), m.addNotesInput.View(),
		)
	}

	var errStr string
	if m.err != "" {
		errStr = "\n" + errorStyle.Render(m.err)
	}

	return fmt.Sprintf("%s%s%s\n\n  %s\n  %s\n\n%s%s\n\n%s%s",
		title,
		kindRow,
		modeRow,
		labelStyle.Render("Name:"),
		m.addNameInput.View(),
		valueSection,
		extraFields,
		help,
		errStr,
	)
}
