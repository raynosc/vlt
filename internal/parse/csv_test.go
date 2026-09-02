package parse

import (
	"strings"
	"testing"
)

func TestParsePasswordCSV_StandardComma(t *testing.T) {
	csvData := `Title,URL,Username,Password,Notes,OTPAuth
ABITAB,https://abitab.com.uy/,this is not a login form,zcf2KMC1bqe@uzw1rpx,,
Abitab.com,https://abitab.com.uy/,63721782,aqntjste-Q1,,
AC Atlassian,https://id.atlassian.com/,,tax.ftc8ACJ.bvd-btj,,`

	records, err := ParsePasswordCSV([]byte(csvData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}

	if records[0].Title != "ABITAB" || records[0].Password != "zcf2KMC1bqe@uzw1rpx" || records[0].Username != "this is not a login form" {
		t.Errorf("unexpected record 0: %+v", records[0])
	}
	if records[1].Title != "Abitab.com" || records[1].Password != "aqntjste-Q1" || records[1].Username != "63721782" {
		t.Errorf("unexpected record 1: %+v", records[1])
	}
	if records[2].Title != "AC Atlassian" || records[2].Password != "tax.ftc8ACJ.bvd-btj" || records[2].Username != "" {
		t.Errorf("unexpected record 2: %+v", records[2])
	}
}

func TestParsePasswordCSV_SemicolonDelimited(t *testing.T) {
	csvData := `Title;Url;Username;Password;OTPAuth;Favorite;Archived;Tags;Notes
GitHub;https://github.com;octocat;ghp_secret123;otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP;1;0;Dev;My GitHub account`

	records, err := ParsePasswordCSV([]byte(csvData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	rec := records[0]
	if rec.Title != "GitHub" || rec.Password != "ghp_secret123" || rec.Username != "octocat" || rec.URL != "https://github.com" || rec.Notes != "My GitHub account" || rec.Tags != "Dev" {
		t.Errorf("unexpected record: %+v", rec)
	}
}

func TestParsePasswordCSV_BitwardenFormat(t *testing.T) {
	csvData := `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
Personal,,login,Google,Primary email,,0,https://accounts.google.com,user@gmail.com,mySecretPassword123,JBSWY3DPEHPK3PXP`

	records, err := ParsePasswordCSV([]byte(csvData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	rec := records[0]
	if rec.Title != "Google" || rec.Password != "mySecretPassword123" || rec.Username != "user@gmail.com" || rec.URL != "https://accounts.google.com" || rec.Notes != "Primary email" {
		t.Errorf("unexpected record: %+v", rec)
	}
}

func TestParsePasswordCSV_ChromeFormat(t *testing.T) {
	csvData := `name,url,username,password,note
Netflix,https://netflix.com,user@example.com,p@ssw0rdNetflix,Family plan`

	records, err := ParsePasswordCSV([]byte(csvData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	rec := records[0]
	if rec.Title != "Netflix" || rec.Password != "p@ssw0rdNetflix" || rec.Username != "user@example.com" || rec.Notes != "Family plan" {
		t.Errorf("unexpected record: %+v", rec)
	}
}

func TestParsePasswordCSV_KeePassFormat(t *testing.T) {
	csvData := `Account,Login Name,Password,Web Site,Comments
Banking,bankuser,superSecretBankKey,https://mybank.com,Checking account`

	records, err := ParsePasswordCSV([]byte(csvData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	rec := records[0]
	if rec.Title != "Banking" || rec.Password != "superSecretBankKey" || rec.Username != "bankuser" || rec.Notes != "Checking account" {
		t.Errorf("unexpected record: %+v", rec)
	}
}

func TestParsePasswordCSV_WithBOM(t *testing.T) {
	bomCSV := append([]byte{0xEF, 0xBB, 0xBF}, []byte("Title,Password\nSite,secret123")...)
	records, err := ParsePasswordCSV(bomCSV)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 || records[0].Title != "Site" || records[0].Password != "secret123" {
		t.Errorf("unexpected record: %+v", records)
	}
}

func TestParsePasswordCSV_MultilineExport(t *testing.T) {
	// Standard export header with multiline notes, blank username, and blank URL
	csvData := `Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes
RedHat: Roi,https://roi.redhat.com,raynosc,mySecretPass1,,FALSE,FALSE,Personal;Services,
BHU,https://www.bhu.com.uy,,passBHU123,,FALSE,FALSE,Personal,Banco Hipotecario Uruguay
Copaair,https://login.copaair.com,RAYNERIS SANCHEZ,copaSecret,,FALSE,FALSE,,
GMail,,raynosc@gmail.com,gmailPass123,,FALSE,FALSE,Mail;Personal,"https://mail.google.com
https://accounts.firefox.com
https://accounts.google.com"
,https://marta-jimenez.com:8443/,admin,martaPass,,FALSE,FALSE,,`

	records, err := ParsePasswordCSV([]byte(csvData))
	if err != nil {
		t.Fatalf("unexpected error parsing multiline CSV: %v", err)
	}

	if len(records) != 5 {
		t.Fatalf("expected 5 records, got %d", len(records))
	}

	if records[0].Title != "RedHat: Roi" || records[0].Username != "raynosc" {
		t.Errorf("record 0 mismatch: %+v", records[0])
	}
	if records[1].Title != "BHU" || records[1].Notes != "Banco Hipotecario Uruguay" {
		t.Errorf("record 1 mismatch: %+v", records[1])
	}
	if records[2].Title != "Copaair" || records[2].Username != "RAYNERIS SANCHEZ" {
		t.Errorf("record 2 mismatch: %+v", records[2])
	}
	// GMail with multiline notes
	if records[3].Title != "GMail" || records[3].Username != "raynosc@gmail.com" {
		t.Errorf("record 3 mismatch: %+v", records[3])
	}
	if !strings.Contains(records[3].Notes, "https://accounts.google.com") {
		t.Errorf("expected multiline notes in GMail, got %q", records[3].Notes)
	}
	// Inferred domain title from blank title
	if records[4].Title != "marta-jimenez.com" || records[4].Username != "admin" {
		t.Errorf("record 4 inferred title mismatch: %+v", records[4])
	}
}
