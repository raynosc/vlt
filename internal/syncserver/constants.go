package syncserver

// JSON response payloads.
var (
	statusOKJSON       = []byte(`{"status":"ok"}`)
	statusNotReadyJSON = []byte(`{"status":"not ready"}`)
)

// Error messages.
const (
	errVaultAlreadyExists     = "vault already exists"
	errFailedToCreateVault    = "failed to create vault"
	errFailedToStoreAPIKey    = "failed to store api key"
	errAPIKeyNotFound         = "api key not found"
	errVaultNotFound          = "vault not found"
	errSeqMismatch            = "sequence mismatch: pull latest first"
	errFailedToUpdateBlob     = "failed to update blob"
	errNoBlobForVault         = "no blob for this vault"
	errAPIKeyNotAuthorized    = "api key not authorized for this vault"
	errVaultUUIDRequired      = "vault uuid is required"
	errInvalidRequestBody     = "invalid request body"
	errVaultUUIDFieldRequired = "vault_uuid is required"
	errKeyHashRequired        = "key_hash is required"
	errRegistrationRateLimit  = "registration rate limit exceeded"
)

// Auth error messages.
const (
	errAuthMissingHeader    = "missing authorization header"
	errAuthInvalidFormat    = "invalid authorization format"
	errAuthEmptyToken       = "empty token"
	errAuthInvalidKeyFormat = "invalid api key format"
	errAuthRateLimit        = "rate limit exceeded"
	errAuthInvalidAPIKey    = "invalid api key"
	errAuthKeyRevoked       = "api key revoked"
)

// Environment variable names.
const (
	envSyncAddr        = "VLT_SYNC_ADDR"
	envSyncDBPath      = "VLT_SYNC_DB_PATH"
	envSyncTLSCert     = "VLT_SYNC_TLS_CERT"
	envSyncTLSKey      = "VLT_SYNC_TLS_KEY"
	envSyncTLSClientCA = "VLT_SYNC_TLS_CLIENT_CA"
)
