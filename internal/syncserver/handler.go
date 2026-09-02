package syncserver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	syncpkg "github.com/raynosc/vlt/internal/sync"
)

// EventMessage represents an SSE event dispatched by the broadcaster.
type EventMessage struct {
	Type string      // "vault_updated" or "security_alert"
	Data interface{} // Sequence int64 or syncpkg.SecurityAlert
}

// Broadcaster manages real-time event subscribers for vaults.
type Broadcaster struct {
	mu          sync.RWMutex
	subscribers map[string]map[chan EventMessage]struct{}
}

// NewBroadcaster creates a new Broadcaster instance.
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{
		subscribers: make(map[string]map[chan EventMessage]struct{}),
	}
}

// Subscribe registers a listener channel for the given vaultUUID.
func (b *Broadcaster) Subscribe(vaultUUID string) (chan EventMessage, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan EventMessage, 32)
	if b.subscribers[vaultUUID] == nil {
		b.subscribers[vaultUUID] = make(map[chan EventMessage]struct{})
	}
	b.subscribers[vaultUUID][ch] = struct{}{}

	cancel := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if subs, ok := b.subscribers[vaultUUID]; ok {
			delete(subs, ch)
			if len(subs) == 0 {
				delete(b.subscribers, vaultUUID)
			}
		}
		close(ch)
	}

	return ch, cancel
}

// Broadcast sends the updated sequence number to all subscribers of vaultUUID.
func (b *Broadcaster) Broadcast(vaultUUID string, seq int64) {
	b.BroadcastEvent(vaultUUID, EventMessage{Type: "vault_updated", Data: seq})
}

// BroadcastAlert sends a security alert to all subscribers of vaultUUID.
func (b *Broadcaster) BroadcastAlert(vaultUUID string, alert syncpkg.SecurityAlert) {
	b.BroadcastEvent(vaultUUID, EventMessage{Type: "security_alert", Data: alert})
}

// BroadcastEvent dispatches an EventMessage to all subscribers of vaultUUID.
func (b *Broadcaster) BroadcastEvent(vaultUUID string, msg EventMessage) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if subs, ok := b.subscribers[vaultUUID]; ok {
		for ch := range subs {
			select {
			case ch <- msg:
			default:
				// If subscriber is slow, drop to avoid blocking other subscribers
			}
		}
	}
}

// Handler contains the dependencies for HTTP handlers.
type Handler struct {
	store       *ServerStore
	auth        *AuthMiddleware
	broadcaster *Broadcaster
}

// NewHandlerMux creates an http.Handler with all routes configured.
func NewHandlerMux(store *ServerStore, auth *AuthMiddleware) http.Handler {
	h := &Handler{
		store:       store,
		auth:        auth,
		broadcaster: NewBroadcaster(),
	}

	mux := http.NewServeMux()

	// Health endpoints (no auth)
	mux.HandleFunc("GET "+RouteHealthz, h.handleHealthz)
	mux.HandleFunc("GET "+RouteReadyz, h.handleReadyz)

	// Auth endpoints
	mux.HandleFunc("POST "+RouteRegister, h.handleRegister)
	mux.Handle("POST "+RouteRevoke, h.auth.Authenticate(http.HandlerFunc(h.handleRevoke)))

	// Vault endpoints (authenticated)
	mux.Handle("POST "+RoutePush, h.auth.Authenticate(http.HandlerFunc(h.handlePush)))
	mux.Handle("GET "+RoutePull, h.auth.Authenticate(http.HandlerFunc(h.handlePull)))
	mux.Handle("GET "+RouteStatus, h.auth.Authenticate(http.HandlerFunc(h.handleStatus)))
	mux.Handle("GET "+RouteEvents, h.auth.Authenticate(http.HandlerFunc(h.handleEvents)))

	// Device & Alert endpoints (authenticated)
	mux.Handle("GET "+RouteDevices, h.auth.Authenticate(http.HandlerFunc(h.handleListDevices)))
	mux.Handle("POST "+RouteHeartbeat, h.auth.Authenticate(http.HandlerFunc(h.handleHeartbeat)))
	mux.Handle("POST "+RouteRevokeDevice, h.auth.Authenticate(http.HandlerFunc(h.handleRevokeDevice)))
	mux.Handle("POST "+RouteAlerts, h.auth.Authenticate(http.HandlerFunc(h.handleAlerts)))

	return mux
}

func (h *Handler) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(statusOKJSON)
}

func (h *Handler) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Check if store is accessible
	if h.store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write(statusNotReadyJSON)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(statusOKJSON)
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Rate limit by source IP
	clientIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = host
	}
	if h.auth.rateLimitRegister(clientIP) {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(registerRateWindow.Seconds())))
		writeError(w, http.StatusTooManyRequests, errRegistrationRateLimit)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4<<10) // 4 KB limit: register carries only a UUID + key hash

	var req syncpkg.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.VaultUUID == "" {
		writeError(w, http.StatusBadRequest, errVaultUUIDFieldRequired)
		return
	}
	if len(req.KeyHash) == 0 {
		writeError(w, http.StatusBadRequest, errKeyHashRequired)
		return
	}

	// Create vault
	if err := h.store.CreateVault(req.VaultUUID); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "unique") {
			writeError(w, http.StatusConflict, errVaultAlreadyExists)
			return
		}
		writeError(w, http.StatusInternalServerError, errFailedToCreateVault)
		return
	}

	// Store the key hash provided by the client (client already generated the API key)
	if err := h.store.AddAPIKey(req.VaultUUID, req.KeyHash, "default"); err != nil {
		writeError(w, http.StatusInternalServerError, errFailedToStoreAPIKey)
		return
	}

	// F1/F2: read current vault seq to anchor the client's registration_seq.
	// New vault → seq 0. Existing vault → current seq.
	var vaultSeq int64
	if status, err := h.store.GetVaultStatus(req.VaultUUID); err == nil {
		vaultSeq = status.Seq
	}

	resp := syncpkg.RegisterResponse{
		VaultUUID: req.VaultUUID,
		Status:    "ok",
		VaultSeq:  vaultSeq,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	authVaultUUID, _ := r.Context().Value(ContextKeyVaultUUID).(string)
	if authVaultUUID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit

	var req syncpkg.RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	if len(req.KeyHash) == 0 {
		writeError(w, http.StatusBadRequest, "key_hash is required")
		return
	}

	if err := h.store.RevokeAPIKey(authVaultUUID, req.KeyHash); err != nil {
		writeError(w, http.StatusNotFound, errAPIKeyNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(statusOKJSON)
}

func (h *Handler) handlePush(w http.ResponseWriter, r *http.Request) {
	vaultUUID := r.PathValue("uuid")
	if vaultUUID == "" {
		writeError(w, http.StatusBadRequest, errVaultUUIDRequired)
		return
	}

	authVaultUUID, _ := r.Context().Value(ContextKeyVaultUUID).(string)
	if authVaultUUID != vaultUUID {
		writeError(w, http.StatusForbidden, errAPIKeyNotAuthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10 MB limit

	var req syncpkg.PushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, errInvalidRequestBody)
		return
	}

	if len(req.Blob) == 0 {
		writeError(w, http.StatusBadRequest, "blob is required")
		return
	}

	newSeq, err := h.store.UpdateBlob(vaultUUID, req.Blob, req.Seq)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, errVaultNotFound)
			return
		}
		if strings.Contains(err.Error(), "seq mismatch") {
			writeError(w, http.StatusConflict, errSeqMismatch)
			return
		}
		writeError(w, http.StatusInternalServerError, errFailedToUpdateBlob)
		return
	}

	h.broadcaster.Broadcast(vaultUUID, newSeq)

	resp := syncpkg.PushResponse{
		Seq:    newSeq,
		Status: "ok",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handlePull(w http.ResponseWriter, r *http.Request) {
	vaultUUID := r.PathValue("uuid")
	if vaultUUID == "" {
		writeError(w, http.StatusBadRequest, errVaultUUIDRequired)
		return
	}

	authVaultUUID, _ := r.Context().Value(ContextKeyVaultUUID).(string)
	if authVaultUUID != vaultUUID {
		writeError(w, http.StatusForbidden, errAPIKeyNotAuthorized)
		return
	}

	vault, err := h.store.GetVault(vaultUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, errVaultNotFound)
		return
	}

	if vault.EncryptedBlob == nil {
		writeError(w, http.StatusNotFound, errNoBlobForVault)
		return
	}

	resp := syncpkg.PullResponse{
		Seq:  vault.Seq,
		Blob: vault.EncryptedBlob,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	vaultUUID := r.PathValue("uuid")
	if vaultUUID == "" {
		writeError(w, http.StatusBadRequest, errVaultUUIDRequired)
		return
	}

	authVaultUUID, _ := r.Context().Value(ContextKeyVaultUUID).(string)
	if authVaultUUID != vaultUUID {
		writeError(w, http.StatusForbidden, errAPIKeyNotAuthorized)
		return
	}

	status, err := h.store.GetVaultStatus(vaultUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, errVaultNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(status)
}

func (h *Handler) handleEvents(w http.ResponseWriter, r *http.Request) {
	vaultUUID := r.PathValue("uuid")
	if vaultUUID == "" {
		writeError(w, http.StatusBadRequest, errVaultUUIDRequired)
		return
	}

	authVaultUUID, _ := r.Context().Value(ContextKeyVaultUUID).(string)
	if authVaultUUID != vaultUUID {
		writeError(w, http.StatusForbidden, errAPIKeyNotAuthorized)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Send initial connected event
	if _, err := fmt.Fprintf(w, "event: connected\ndata: {\"vault_uuid\":\"%s\"}\n\n", vaultUUID); err != nil {
		return
	}
	flusher.Flush()

	ch, cancel := h.broadcaster.Subscribe(vaultUUID)
	defer cancel()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg, open := <-ch:
			if !open {
				return
			}
			dataJSON, err := json.Marshal(msg.Data)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", msg.Type, string(dataJSON)); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (h *Handler) handleListDevices(w http.ResponseWriter, r *http.Request) {
	vaultUUID := r.PathValue("uuid")
	if vaultUUID == "" {
		writeError(w, http.StatusBadRequest, errVaultUUIDRequired)
		return
	}

	authVaultUUID, _ := r.Context().Value(ContextKeyVaultUUID).(string)
	if authVaultUUID != vaultUUID {
		writeError(w, http.StatusForbidden, errAPIKeyNotAuthorized)
		return
	}

	devices, err := h.store.ListDevices(vaultUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if devices == nil {
		devices = []syncpkg.DeviceInfo{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(devices)
}

func (h *Handler) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	vaultUUID := r.PathValue("uuid")
	if vaultUUID == "" {
		writeError(w, http.StatusBadRequest, errVaultUUIDRequired)
		return
	}

	authVaultUUID, _ := r.Context().Value(ContextKeyVaultUUID).(string)
	if authVaultUUID != vaultUUID {
		writeError(w, http.StatusForbidden, errAPIKeyNotAuthorized)
		return
	}

	var req syncpkg.HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.DeviceID == "" {
		writeError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	// Extract remote IP
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	if ip == "" {
		ip = r.RemoteAddr
	}

	dev := syncpkg.DeviceInfo{
		DeviceID:              req.DeviceID,
		VaultUUID:             vaultUUID,
		Hostname:              req.Hostname,
		IPAddress:             ip,
		ClientVersion:         req.ClientVersion,
		ClientCertFingerprint: req.ClientCertFingerprint,
	}

	if err := h.store.UpsertDevice(dev); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (h *Handler) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	vaultUUID := r.PathValue("uuid")
	deviceID := r.PathValue("device_id")
	if vaultUUID == "" || deviceID == "" {
		writeError(w, http.StatusBadRequest, "uuid and device_id are required")
		return
	}

	authVaultUUID, _ := r.Context().Value(ContextKeyVaultUUID).(string)
	if authVaultUUID != vaultUUID {
		writeError(w, http.StatusForbidden, errAPIKeyNotAuthorized)
		return
	}

	if err := h.store.RevokeDevice(vaultUUID, deviceID); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"revoked"}`))
}

func (h *Handler) handleAlerts(w http.ResponseWriter, r *http.Request) {
	vaultUUID := r.PathValue("uuid")
	if vaultUUID == "" {
		writeError(w, http.StatusBadRequest, errVaultUUIDRequired)
		return
	}

	authVaultUUID, _ := r.Context().Value(ContextKeyVaultUUID).(string)
	if authVaultUUID != vaultUUID {
		writeError(w, http.StatusForbidden, errAPIKeyNotAuthorized)
		return
	}

	var alert syncpkg.SecurityAlert
	if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
		writeError(w, http.StatusBadRequest, "invalid alert payload")
		return
	}
	alert.VaultUUID = vaultUUID
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now().UTC()
	}

	// Broadcast alert to all active SSE listeners for this vault
	h.broadcaster.BroadcastAlert(vaultUUID, alert)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"broadcasted"}`))
}

func writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	resp := syncpkg.ErrorResponse{Error: message, Code: code}
	_ = json.NewEncoder(w).Encode(resp)
}
