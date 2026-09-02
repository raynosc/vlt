//go:build darwin

package keychain

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
#include <LocalAuthentication/LocalAuthentication.h>
#include <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>

bool authenticateWithBiometrics(const char* reasonStr) {
    LAContext *context = [[LAContext alloc] init];
    NSError *authError = nil;
    NSString *reason = [NSString stringWithUTF8String:reasonStr];

    // LAPolicyDeviceOwnerAuthenticationWithBiometrics = biometrics ONLY (Touch
    // ID / Face ID). It does NOT offer the device password as a fallback, unlike
    // LAPolicyDeviceOwnerAuthentication. The app's master password remains the
    // ultimate fallback at the application layer.
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&authError]) {
        dispatch_semaphore_t sema = dispatch_semaphore_create(0);
        __block bool success_flag = false;

        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                localizedReason:reason
                          reply:^(BOOL success, NSError *error) {
            if (success) {
                success_flag = true;
            }
            dispatch_semaphore_signal(sema);
        }];

        dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
        return success_flag;
    }
    return false;
}
*/
import "C"
import "unsafe"

// PromptBiometric requests Touch ID / Face ID authentication.
func PromptBiometric(reason string) bool {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	return bool(C.authenticateWithBiometrics(cReason))
}
