package secret

import (
	"testing"
	"time"
)

func TestValidKinds_ReturnsAll(t *testing.T) {
	kinds := ValidKinds()
	if len(kinds) != 6 {
		t.Fatalf("expected 6 valid kinds, got %d", len(kinds))
	}
	expected := []Kind{KindPassword, KindAPIKey, KindCertificate, KindSSHKey, KindNote, KindOther}
	for i, k := range expected {
		if kinds[i] != k {
			t.Errorf("kinds[%d] = %q, want %q", i, kinds[i], k)
		}
	}
}

func TestIsValidKind(t *testing.T) {
	tests := []struct {
		name  string
		kind  string
		valid bool
	}{
		{"password", "password", true},
		{"api_key", "api_key", true},
		{"certificate", "certificate", true},
		{"ssh_key", "ssh_key", true},
		{"note", "note", true},
		{"other", "other", true},
		{"invalid", "invalid_type", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidKind(tt.kind)
			if got != tt.valid {
				t.Errorf("IsValidKind(%q) = %v, want %v", tt.kind, got, tt.valid)
			}
		})
	}
}

func TestNewSecret_Defaults(t *testing.T) {
	s := NewSecret("", "test-name", KindPassword, []byte("encrypted"), "notes", "tags")

	if s.ID != "" {
		t.Errorf("ID = %q, want empty", s.ID)
	}
	if s.Name != "test-name" {
		t.Errorf("Name = %q", s.Name)
	}
	if s.Kind != KindPassword {
		t.Errorf("Kind = %q", s.Kind)
	}
	if string(s.EncryptedValue) != "encrypted" {
		t.Errorf("EncryptedValue mismatch")
	}
	if s.Notes != "notes" {
		t.Errorf("Notes = %q", s.Notes)
	}
	if s.Tags != "tags" {
		t.Errorf("Tags = %q", s.Tags)
	}
	if s.Metadata != "" {
		t.Errorf("Metadata = %q, want empty", s.Metadata)
	}
	if s.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
	if s.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should not be zero")
	}
}

func TestNewSecret_WithID(t *testing.T) {
	s := NewSecret("uuid-123", "named", KindAPIKey, []byte("data"), "", "")
	if s.ID != "uuid-123" {
		t.Errorf("ID = %q", s.ID)
	}
}

func TestNewSecret_NonNilEncryptedValue(t *testing.T) {
	s := NewSecret("", "a", KindNote, []byte{}, "n", "")
	if s.EncryptedValue == nil {
		t.Error("EncryptedValue should be non-nil even if empty")
	}
}

func TestMarshalPasswordMetadata_Nil(t *testing.T) {
	if s := MarshalPasswordMetadata(nil); s != "" {
		t.Errorf("expected empty for nil, got %q", s)
	}
}

func TestMarshalPasswordMetadata_Empty(t *testing.T) {
	meta := &PasswordMetadata{}
	if s := MarshalPasswordMetadata(meta); s != "" {
		t.Errorf("expected empty for empty meta, got %q", s)
	}
}

func TestMarshalPasswordMetadata_WithFields(t *testing.T) {
	meta := &PasswordMetadata{URL: "https://example.com", Username: "user", OTPAuth: "otpauth://..."}
	s := MarshalPasswordMetadata(meta)
	if s == "" {
		t.Fatal("expected non-empty JSON")
	}
	if s != `{"url":"https://example.com","username":"user","otpauth":"otpauth://..."}` {
		t.Errorf("unexpected JSON: %q", s)
	}
}

func TestUnmarshalPasswordMetadata_Empty(t *testing.T) {
	if meta := UnmarshalPasswordMetadata(""); meta != nil {
		t.Error("expected nil for empty string")
	}
}

func TestUnmarshalPasswordMetadata_Valid(t *testing.T) {
	json := `{"url":"https://example.com","username":"testuser"}`
	meta := UnmarshalPasswordMetadata(json)
	if meta == nil {
		t.Fatal("expected non-nil")
		return
	}
	if meta.URL != "https://example.com" {
		t.Errorf("URL = %q", meta.URL)
	}
	if meta.Username != "testuser" {
		t.Errorf("Username = %q", meta.Username)
	}
}

func TestUnmarshalPasswordMetadata_BackwardCompat(t *testing.T) {
	// Old format used "site" instead of "url" — will only populate Username
	// since "site" doesn't map to URL in struct unmarshal.
	json := `{"site":"https://old.example.com","username":"olduser"}`
	meta := UnmarshalPasswordMetadata(json)
	if meta == nil {
		t.Fatal("expected non-nil for backward compat")
		return
	}
	if meta.Username != "olduser" {
		t.Errorf("Username = %q", meta.Username)
	}
}

func TestUnmarshalPasswordMetadata_SiteOnly(t *testing.T) {
	// If only "site" is present (no username), the fallback reads it as URL.
	json := `{"site":"https://site-only.example.com"}`
	meta := UnmarshalPasswordMetadata(json)
	if meta == nil {
		t.Fatal("expected non-nil for site-only backward compat")
		return
	}
	if meta.URL != "https://site-only.example.com" {
		t.Errorf("URL = %q (should read from 'site')", meta.URL)
	}
}

func TestUnmarshalPasswordMetadata_InvalidJSON(t *testing.T) {
	meta := UnmarshalPasswordMetadata("{invalid}")
	if meta != nil {
		t.Error("expected nil for invalid JSON")
	}
}

func TestSecret_RoundTrip(t *testing.T) {
	now := time.Now().UTC()
	s := Secret{
		ID:             "id-1",
		Name:           "test",
		Kind:           KindPassword,
		EncryptedValue: []byte("secret-data"),
		Notes:          "my notes",
		Tags:           "tag1,tag2",
		Metadata:       `{"key":"val"}`,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if s.ID != "id-1" {
		t.Errorf("ID = %q", s.ID)
	}
	if s.Name != "test" {
		t.Errorf("Name = %q", s.Name)
	}
	if s.Kind != KindPassword {
		t.Errorf("Kind = %q", s.Kind)
	}
	if string(s.EncryptedValue) != "secret-data" {
		t.Errorf("EncryptedValue = %q", string(s.EncryptedValue))
	}
	if s.Notes != "my notes" {
		t.Errorf("Notes = %q", s.Notes)
	}
	if s.Tags != "tag1,tag2" {
		t.Errorf("Tags = %q", s.Tags)
	}
	if s.Metadata != `{"key":"val"}` {
		t.Errorf("Metadata = %q", s.Metadata)
	}
}
