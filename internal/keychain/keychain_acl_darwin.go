//go:build darwin && keychain_biometric

package keychain

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>

// addItemWithBiometricACL creates a generic-password item protected by
// kSecAccessControlBiometryCurrentSet. Biometrics-only — no passcode fallback.
// Returns the OSStatus from SecItemAdd.
OSStatus addItemWithBiometricACL(const char *service, const char *account,
                                  const void *data, CFIndex dataLen) {
    CFErrorRef err = NULL;
    SecAccessControlRef acl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlBiometryCurrentSet,
        &err
    );
    if (acl == NULL) {
        if (err != NULL) CFRelease(err);
        return errSecInternalError;
    }

    CFStringRef svcRef  = CFStringCreateWithCString(kCFAllocatorDefault, service,  kCFStringEncodingUTF8);
    CFStringRef accRef  = CFStringCreateWithCString(kCFAllocatorDefault, account,  kCFStringEncodingUTF8);
    CFDataRef   dataRef = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)data, dataLen);

    const void *keys[] = {
        kSecClass,
        kSecAttrService,
        kSecAttrAccount,
        kSecValueData,
        kSecAttrAccessControl,
    };
    const void *vals[] = {
        kSecClassGenericPassword,
        svcRef,
        accRef,
        dataRef,
        acl,
    };
    CFDictionaryRef attrs = CFDictionaryCreate(
        kCFAllocatorDefault,
        keys, vals, 5,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    OSStatus status = SecItemAdd(attrs, NULL);

    CFRelease(attrs);
    CFRelease(dataRef);
    CFRelease(accRef);
    CFRelease(svcRef);
    CFRelease(acl);
    if (err != NULL) CFRelease(err);

    return status;
}

// copyItemWithBiometricPrompt reads a generic-password item. The Keychain
// internally triggers Touch ID because the item was stored with
// kSecAccessControlBiometryCurrentSet. promptMsg is shown in the Touch ID
// dialog via kSecUseOperationPrompt (deprecated as of macOS 11 but still
// functional; the modern alternative requires LAContext Objective-C overhead).
// On success *outData / *outLen are set; caller must free(*outData).
// Returns OSStatus (errSecItemNotFound = -25300, errSecUserCanceled = -128,
//                   errSecAuthFailed = -25293).
OSStatus copyItemWithBiometricPrompt(const char *service, const char *account,
                                      const char *prompt,
                                      void **outData, CFIndex *outLen) {
    CFStringRef svcRef    = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
    CFStringRef accRef    = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);
    CFStringRef promptRef = CFStringCreateWithCString(kCFAllocatorDefault, prompt,  kCFStringEncodingUTF8);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    const void *keys[] = {
        kSecClass,
        kSecAttrService,
        kSecAttrAccount,
        kSecReturnData,
        kSecMatchLimit,
        kSecUseOperationPrompt,
    };
    const void *vals[] = {
        kSecClassGenericPassword,
        svcRef,
        accRef,
        kCFBooleanTrue,
        kSecMatchLimitOne,
        promptRef,
    };
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault,
        keys, vals, 6,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
#pragma clang diagnostic pop

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);

    CFRelease(query);
    CFRelease(promptRef);
    CFRelease(accRef);
    CFRelease(svcRef);

    if (status == errSecSuccess && result != NULL) {
        CFDataRef dataRef = (CFDataRef)result;
        CFIndex len = CFDataGetLength(dataRef);
        void *buf = malloc((size_t)len);
        if (buf == NULL) {
            CFRelease(result);
            return errSecMemoryError;
        }
        CFDataGetBytes(dataRef, CFRangeMake(0, len), (UInt8 *)buf);
        CFRelease(result);
        *outData = buf;
        *outLen  = len;
    }

    return status;
}

// deleteItem removes a generic-password item. Returns the OSStatus from
// SecItemDelete (errSecItemNotFound = -25300 if already absent).
OSStatus deleteItem(const char *service, const char *account) {
    CFStringRef svcRef = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
    CFStringRef accRef = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);

    const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount };
    const void *vals[] = { kSecClassGenericPassword, svcRef, accRef };
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault,
        keys, vals, 3,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    OSStatus status = SecItemDelete(query);

    CFRelease(query);
    CFRelease(accRef);
    CFRelease(svcRef);

    return status;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// OSStatus sentinel values from Security.framework.
const (
	errSecSuccess       C.OSStatus = 0
	errSecItemNotFound  C.OSStatus = -25300
	errSecDuplicateItem C.OSStatus = -25299
	errSecUserCanceled  C.OSStatus = -128
	errSecAuthFailed    C.OSStatus = -25293
)

// New creates a macOS Keychain implementation for SIGNED builds (-tags
// keychain_biometric). Items are stored with kSecAccessControlBiometryCurrentSet,
// so the OS itself requires Touch ID to read an item — no separate software
// biometric step. Requires a code-signed binary with a keychain-access-groups
// entitlement (see `make build-signed`); an unsigned binary gets
// errSecMissingEntitlement (-34018) on Save.
func New() Keychain {
	return &darwinKeychain{}
}

type darwinKeychain struct{}

// Save persists key with a biometric access-control object. Delete-then-add so
// key rotation always succeeds.
func (k *darwinKeychain) Save(key []byte, service, account string) error {
	_ = secItemDelete(service, account) // best-effort; ignore not-found
	return secItemAddBiometric(service, account, key)
}

// Load reads the key; the Keychain presents the native Touch ID dialog because
// the item carries a kSecAccessControlBiometryCurrentSet ACL.
func (k *darwinKeychain) Load(service, account string) ([]byte, error) {
	return secItemCopyBiometric(service, account, "Unlock SecVault")
}

// Delete removes the item. Returns nil if it was not present.
func (k *darwinKeychain) Delete(service, account string) error {
	return secItemDelete(service, account)
}

// secItemAddBiometric stores data in the Keychain protected by
// kSecAccessControlBiometryCurrentSet (Touch ID / Face ID only — no passcode
// fallback). Returns ErrNotFound if the item already exists (caller should
// delete first).
func secItemAddBiometric(service, account string, data []byte) error {
	cSvc := C.CString(service)
	defer C.free(unsafe.Pointer(cSvc))
	cAcc := C.CString(account)
	defer C.free(unsafe.Pointer(cAcc))

	var dataPtr unsafe.Pointer
	if len(data) > 0 {
		dataPtr = C.CBytes(data)
		defer C.free(dataPtr)
	}

	status := C.addItemWithBiometricACL(cSvc, cAcc, dataPtr, C.CFIndex(len(data)))
	return osStatusToError(status)
}

// secItemCopyBiometric reads the item from the Keychain. The Keychain will
// internally present the Touch ID prompt because the item was stored with
// kSecAccessControlBiometryCurrentSet. prompt is the reason string shown in
// the Touch ID dialog. Returns ErrNotFound if the item does not exist.
func secItemCopyBiometric(service, account, prompt string) ([]byte, error) {
	cSvc := C.CString(service)
	defer C.free(unsafe.Pointer(cSvc))
	cAcc := C.CString(account)
	defer C.free(unsafe.Pointer(cAcc))
	cPrompt := C.CString(prompt)
	defer C.free(unsafe.Pointer(cPrompt))

	var outData unsafe.Pointer
	var outLen C.CFIndex

	status := C.copyItemWithBiometricPrompt(cSvc, cAcc, cPrompt, &outData, &outLen)
	if status != errSecSuccess {
		return nil, osStatusToError(status)
	}

	// Copy bytes into Go-managed memory, then free the C buffer.
	n := int(outLen)
	result := make([]byte, n)
	if n > 0 {
		copy(result, (*[1 << 30]byte)(outData)[:n:n])
		C.free(outData)
	}
	return result, nil
}

// secItemDelete removes the item from the Keychain. Returns nil if the item
// was deleted or was not present.
func secItemDelete(service, account string) error {
	cSvc := C.CString(service)
	defer C.free(unsafe.Pointer(cSvc))
	cAcc := C.CString(account)
	defer C.free(unsafe.Pointer(cAcc))

	status := C.deleteItem(cSvc, cAcc)
	if status == errSecItemNotFound {
		return nil
	}
	return osStatusToError(status)
}

// osStatusToError maps Security.framework OSStatus codes to Go errors.
func osStatusToError(status C.OSStatus) error {
	switch status {
	case errSecSuccess:
		return nil
	case errSecItemNotFound:
		return ErrNotFound
	case errSecUserCanceled:
		return ErrBiometricCanceled
	case errSecAuthFailed:
		return ErrBiometricFailed
	case errSecDuplicateItem:
		return fmt.Errorf("keychain: duplicate item")
	default:
		return fmt.Errorf("keychain: Security.framework OSStatus %d", int32(status))
	}
}
