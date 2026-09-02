package parse

import (
	"strings"
	"testing"
)

// FuzzParseCSV tests that ParsePasswordCSV does not panic or crash on arbitrary malformed inputs.
func FuzzParseCSV(f *testing.F) {
	// Seed corpus with valid and edge cases
	f.Add([]byte("Title,Username,Password,URL,Notes\nGoogle,user@example.com,pass123,https://google.com,note"))
	f.Add([]byte("name,login_username,login_password,url,notes\nGitHub,dev,token,https://github.com,ssh-key"))
	f.Add([]byte("Title;Username;Password;URL\nCompany;admin;Secret!;https://corp.local"))
	f.Add([]byte("\xef\xbb\xbfTitle,Username,Password\nBOM,admin,pass"))
	f.Add([]byte(""))
	f.Add([]byte("\n\n\n"))
	f.Add([]byte(",,,,,\n,,,,,"))
	f.Add([]byte("\"unclosed quote,1,2,3"))
	f.Add([]byte("Title,Password\n" + strings.Repeat("A", 10000) + "," + strings.Repeat("B", 10000)))

	f.Fuzz(func(t *testing.T, data []byte) {
		// ParsePasswordCSV must handle any raw data gracefully without panicking
		_, _ = ParsePasswordCSV(data)
	})
}

// FuzzDetectFormat tests that Detect handles arbitrary byte streams.
func FuzzDetectFormat(f *testing.F) {
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nMIIB..."))
	f.Add([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIE..."))
	f.Add([]byte("ssh-rsa AAAAB3NzaC1yc2E... user@host"))
	f.Add([]byte("Title,Username,Password\ntest,user,pass"))
	f.Add([]byte("{\"title\": \"test\"}"))
	f.Add([]byte("\x00\x01\x02\x03\xff\xfe"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Detect(data)
	})
}
