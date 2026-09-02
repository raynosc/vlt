//go:build linux

package keychain

import (
	"fmt"
	"log"

	"github.com/godbus/dbus/v5"
)

const (
	secretServiceName = "org.freedesktop.secrets"
	secretServicePath = "/org/freedesktop/secrets"
	defaultAliasPath  = "/org/freedesktop/secrets/aliases/default"
	secretItemLabel   = "org.freedesktop.Secret.Item.Label"
	secretItemAttrs   = "org.freedesktop.Secret.Item.Attributes"
	secretContentType = "application/octet-stream"
)

// New creates a Linux Secret Service (D-Bus) Keychain implementation.
// Falls back to unsupportedKeychain if D-Bus session bus is not available.
func New() Keychain {
	conn, err := dbus.SessionBus()
	if err != nil {
		return &unsupportedKeychain{}
	}
	return &linuxKeychain{conn: conn}
}

type linuxKeychain struct {
	conn *dbus.Conn
}

// openSession opens an encrypted secret service session, falling back to plain.
// Returns the session object path used to create items.
func (k *linuxKeychain) openSession() (dbus.ObjectPath, error) {
	svc := k.conn.Object(secretServiceName, secretServicePath)

	// Try encrypted session first
	call := svc.Call("org.freedesktop.Secret.Service.OpenSession", 0, "dh-ietf1024-sha256-aes128-cbc-pkcs7", dbus.MakeVariant(""))
	if call.Err == nil {
		var output dbus.Variant
		var sessionPath dbus.ObjectPath
		if err := call.Store(&output, &sessionPath); err == nil {
			return sessionPath, nil
		}
	}

	// Fallback to plain session with warning
	log.Println("WARNING: encrypted D-Bus session unavailable, falling back to plain")
	call = svc.Call("org.freedesktop.Secret.Service.OpenSession", 0, "plain", dbus.MakeVariant(""))
	if call.Err != nil {
		return "", fmt.Errorf("open session: %w", call.Err)
	}

	var output dbus.Variant
	var sessionPath dbus.ObjectPath
	if err := call.Store(&output, &sessionPath); err != nil {
		return "", fmt.Errorf("store session result: %w", err)
	}
	return sessionPath, nil
}

// getDefaultCollection resolves the default secret collection alias.
func (k *linuxKeychain) getDefaultCollection() (dbus.ObjectPath, error) {
	svc := k.conn.Object(secretServiceName, secretServicePath)
	variant, err := svc.GetProperty("org.freedesktop.Secret.Service.Collections")
	if err != nil {
		return "", fmt.Errorf("get collections: %w", err)
	}

	collections := variant.Value().([]dbus.ObjectPath)
	if len(collections) == 0 {
		return "", fmt.Errorf("no secret collections available")
	}

	// Use default alias if possible
	alias := k.conn.Object(secretServiceName, defaultAliasPath)
	aliasVariant, err := alias.GetProperty("org.freedesktop.Secret.Collection.default")
	if err == nil {
		if path, ok := aliasVariant.Value().(dbus.ObjectPath); ok && path != "/" {
			return path, nil
		}
	}

	// Fallback: use the first collection
	return collections[0], nil
}

func (k *linuxKeychain) Save(key []byte, service, account string) error {
	sessionPath, err := k.openSession()
	if err != nil {
		return fmt.Errorf("keychain save: %w", err)
	}

	collectionPath, err := k.getDefaultCollection()
	if err != nil {
		return fmt.Errorf("keychain save: %w", err)
	}

	// Build item properties
	props := map[string]dbus.Variant{
		secretItemLabel: dbus.MakeVariant(fmt.Sprintf("vlt: %s/%s", service, account)),
		secretItemAttrs: dbus.MakeVariant(map[string]string{
			"service": service,
			"account": account,
		}),
	}

	// Secret struct: (session, parameters, value, content_type)
	secret := struct {
		Session     dbus.ObjectPath
		Parameters  []byte
		Value       []byte
		ContentType string
	}{
		Session:     sessionPath,
		Parameters:  []byte{},
		Value:       key,
		ContentType: secretContentType,
	}

	collection := k.conn.Object(secretServiceName, collectionPath)
	call := collection.Call("org.freedesktop.Secret.Collection.CreateItem", 0, props, secret, true)
	if call.Err != nil {
		return fmt.Errorf("keychain save: %w", call.Err)
	}

	return nil
}

func (k *linuxKeychain) Load(service, account string) ([]byte, error) {
	sessionPath, err := k.openSession()
	if err != nil {
		return nil, fmt.Errorf("keychain load: %w", err)
	}

	collectionPath, err := k.getDefaultCollection()
	if err != nil {
		return nil, fmt.Errorf("keychain load: %w", err)
	}

	// Search for items matching service + account
	attrs := map[string]string{
		"service": service,
		"account": account,
	}

	collection := k.conn.Object(secretServiceName, collectionPath)
	call := collection.Call("org.freedesktop.Secret.Collection.SearchItems", 0, attrs)
	if call.Err != nil {
		return nil, fmt.Errorf("keychain load search: %w", call.Err)
	}

	var unlocked []dbus.ObjectPath
	var locked []dbus.ObjectPath
	if err := call.Store(&unlocked, &locked); err != nil {
		return nil, fmt.Errorf("keychain load store results: %w", err)
	}

	if len(unlocked) == 0 {
		return nil, ErrNotFound
	}

	// Get the secret from the first matching item
	item := k.conn.Object(secretServiceName, unlocked[0])
	getCall := item.Call("org.freedesktop.Secret.Item.GetSecret", 0, sessionPath)
	if getCall.Err != nil {
		return nil, fmt.Errorf("keychain load get secret: %w", getCall.Err)
	}

	// Secret struct returned by GetSecret
	var secret struct {
		Session     dbus.ObjectPath
		Parameters  []byte
		Value       []byte
		ContentType string
	}
	if err := getCall.Store(&secret); err != nil {
		return nil, fmt.Errorf("keychain load store secret: %w", err)
	}

	// Return a copy to avoid potential memory aliasing
	keyCopy := make([]byte, len(secret.Value))
	copy(keyCopy, secret.Value)
	return keyCopy, nil
}

func (k *linuxKeychain) Delete(service, account string) error {
	collectionPath, err := k.getDefaultCollection()
	if err != nil {
		return fmt.Errorf("keychain delete: %w", err)
	}

	// Search for items matching service + account
	attrs := map[string]string{
		"service": service,
		"account": account,
	}

	collection := k.conn.Object(secretServiceName, collectionPath)
	call := collection.Call("org.freedesktop.Secret.Collection.SearchItems", 0, attrs)
	if call.Err != nil {
		return fmt.Errorf("keychain delete search: %w", call.Err)
	}

	var unlocked []dbus.ObjectPath
	var locked []dbus.ObjectPath
	if err := call.Store(&unlocked, &locked); err != nil {
		return fmt.Errorf("keychain delete store results: %w", err)
	}

	if len(unlocked) == 0 {
		// Non-existent → no error (idempotent)
		return nil
	}

	// Delete the matching item
	item := k.conn.Object(secretServiceName, unlocked[0])
	delCall := item.Call("org.freedesktop.Secret.Item.Delete", 0)
	if delCall.Err != nil {
		return fmt.Errorf("keychain delete: %w", delCall.Err)
	}

	return nil
}
