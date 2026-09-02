package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/raynosc/vlt/internal/crypto"
	"github.com/raynosc/vlt/internal/parse"
	"github.com/raynosc/vlt/internal/secret"
	"github.com/raynosc/vlt/internal/store"
)

// getByName decrypts a secret by name via HMAC lookup.
func getByName(s *store.SQLStore, key []byte, name string) (secret.Secret, error) {
	lookup := crypto.ComputeNameLookup(key, name)
	sec, err := s.GetByNameLookup(lookup)
	if err != nil {
		return secret.Secret{}, err
	}
	if err := decryptSecretMetadata(&sec, key); err != nil {
		return secret.Secret{}, fmt.Errorf("decrypt metadata: %w", err)
	}
	return sec, nil
}

// deleteByName removes a secret by name via HMAC lookup.
func deleteByName(s *store.SQLStore, key []byte, name string) error {
	lookup := crypto.ComputeNameLookup(key, name)
	return s.DeleteByLookup(lookup)
}

// softDeleteByName soft-deletes a secret by name via HMAC lookup.
func softDeleteByName(s *store.SQLStore, key []byte, name string) error {
	lookup := crypto.ComputeNameLookup(key, name)
	return s.SoftDeleteByLookup(lookup)
}

// searchSecrets returns secrets whose decrypted metadata contains the query.
func searchSecrets(s *store.SQLStore, key []byte, query string) ([]secret.Secret, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if err := decryptSecretMetadata(&all[i], key); err != nil {
			return nil, fmt.Errorf("decrypt metadata: %w", err)
		}
	}
	if query == "" {
		return all, nil
	}
	query = strings.ToLower(query)
	var results []secret.Secret
	for _, sec := range all {
		if strings.Contains(strings.ToLower(sec.Name), query) ||
			strings.Contains(strings.ToLower(sec.Notes), query) ||
			strings.Contains(strings.ToLower(sec.Tags), query) ||
			strings.Contains(strings.ToLower(sec.Metadata), query) {
			results = append(results, sec)
		}
	}
	return results, nil
}

// listExpiring returns certificate secrets expiring within the given days.
func listExpiring(s *store.SQLStore, key []byte, days int) ([]secret.Secret, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	var results []secret.Secret
	for i := range all {
		if all[i].Kind != secret.KindCertificate {
			continue
		}
		if err := decryptSecretMetadata(&all[i], key); err != nil {
			continue
		}
		if all[i].Metadata == "" {
			continue
		}
		var meta parse.Metadata
		if err := json.Unmarshal([]byte(all[i].Metadata), &meta); err != nil {
			continue
		}
		if meta.NotAfter == "" {
			continue
		}
		d := meta.DaysUntilExpiry()
		if d <= days {
			results = append(results, all[i])
		}
	}
	return results, nil
}

// incrementHOTPCounter increments the HOTP counter in a secret's metadata.
func incrementHOTPCounter(s *store.SQLStore, eng *crypto.Engine, key []byte, name string) (uint64, error) {
	lookup := crypto.ComputeNameLookup(key, name)
	sec, err := s.GetByNameLookup(lookup)
	if err != nil {
		return 0, fmt.Errorf("get secret: %w", err)
	}
	if err := decryptSecretMetadata(&sec, key); err != nil {
		return 0, fmt.Errorf("decrypt metadata: %w", err)
	}
	meta := secret.UnmarshalPasswordMetadata(sec.Metadata)
	if meta == nil {
		meta = &secret.PasswordMetadata{}
	}
	meta.HOTPCounter++
	sec.Metadata = secret.MarshalPasswordMetadata(meta)
	sec, err = encryptSecretMetadata(sec, eng, key)
	if err != nil {
		return 0, fmt.Errorf("encrypt metadata: %w", err)
	}
	if err := s.UpdateOTPSeedAndMetadata(lookup, sec.EncryptedOTPSeed, sec.EncryptedMetadata); err != nil {
		return 0, fmt.Errorf("update metadata: %w", err)
	}
	return meta.HOTPCounter, nil
}

// decryptSecretMetadata decrypts all metadata BLOBs of a secret in-place.
func decryptSecretMetadata(sec *secret.Secret, key []byte) error {
	eng := crypto.NewEngine(nil)
	if len(sec.EncryptedName) > 0 {
		nonce, ct, err := crypto.UnpackEnvelope(sec.EncryptedName)
		if err != nil {
			return fmt.Errorf("decrypt name: %w", err)
		}
		pt, err := eng.Decrypt(ct, key, nonce)
		if err != nil {
			return fmt.Errorf("decrypt name: %w", err)
		}
		sec.Name = string(pt)
		crypto.Zeroize(pt)
	}
	if len(sec.EncryptedNotes) > 0 {
		nonce, ct, err := crypto.UnpackEnvelope(sec.EncryptedNotes)
		if err != nil {
			return fmt.Errorf("decrypt notes: %w", err)
		}
		pt, err := eng.Decrypt(ct, key, nonce)
		if err != nil {
			return fmt.Errorf("decrypt notes: %w", err)
		}
		sec.Notes = string(pt)
		crypto.Zeroize(pt)
	}
	if len(sec.EncryptedTags) > 0 {
		nonce, ct, err := crypto.UnpackEnvelope(sec.EncryptedTags)
		if err != nil {
			return fmt.Errorf("decrypt tags: %w", err)
		}
		pt, err := eng.Decrypt(ct, key, nonce)
		if err != nil {
			return fmt.Errorf("decrypt tags: %w", err)
		}
		sec.Tags = string(pt)
		crypto.Zeroize(pt)
	}
	if len(sec.EncryptedMetadata) > 0 {
		nonce, ct, err := crypto.UnpackEnvelope(sec.EncryptedMetadata)
		if err != nil {
			return fmt.Errorf("decrypt metadata: %w", err)
		}
		pt, err := eng.Decrypt(ct, key, nonce)
		if err != nil {
			return fmt.Errorf("decrypt metadata: %w", err)
		}
		sec.Metadata = string(pt)
		crypto.Zeroize(pt)
	}
	return nil
}

// encryptSecretMetadata encrypts all plaintext metadata fields.
// Empty fields are stored as empty BLOBs (NOT NULL with DEFAULT X”).
func encryptSecretMetadata(s secret.Secret, eng *crypto.Engine, key []byte) (secret.Secret, error) {
	ct, nonce, err := eng.Encrypt([]byte(s.Name), key)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("encrypt name: %w", err)
	}
	s.EncryptedName = crypto.PackEnvelope(nonce, ct)

	if s.Notes != "" {
		ct, nonce, err = eng.Encrypt([]byte(s.Notes), key)
		if err != nil {
			return secret.Secret{}, fmt.Errorf("encrypt notes: %w", err)
		}
		s.EncryptedNotes = crypto.PackEnvelope(nonce, ct)
	} else {
		s.EncryptedNotes = []byte{}
	}

	if s.Tags != "" {
		ct, nonce, err = eng.Encrypt([]byte(s.Tags), key)
		if err != nil {
			return secret.Secret{}, fmt.Errorf("encrypt tags: %w", err)
		}
		s.EncryptedTags = crypto.PackEnvelope(nonce, ct)
	} else {
		s.EncryptedTags = []byte{}
	}

	if s.Metadata != "" {
		ct, nonce, err = eng.Encrypt([]byte(s.Metadata), key)
		if err != nil {
			return secret.Secret{}, fmt.Errorf("encrypt metadata: %w", err)
		}
		s.EncryptedMetadata = crypto.PackEnvelope(nonce, ct)
	} else {
		s.EncryptedMetadata = []byte{}
	}

	s.NameLookup = crypto.ComputeNameLookup(key, s.Name)
	return s, nil
}
