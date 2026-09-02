package store

import "errors"

// Sentinel errors returned by Store operations.
var (
	// ErrNotFound is returned when a secret is not found by ID or name.
	ErrNotFound = errors.New("secret not found")

	// ErrDuplicate is returned when attempting to store a secret with
	// a name that already exists in the vault.
	ErrDuplicate = errors.New("secret with this name already exists")

	// ErrMigrationRequired is returned when opening a legacy vault whose
	// schema version is too old to be upgraded in-place. The user must
	// export data from a prior build and re-import into a fresh vault.
	ErrMigrationRequired = errors.New("vault schema too old: export from prior build and re-import into a fresh vault")
)
