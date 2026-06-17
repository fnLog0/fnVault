// fnVault Keychain + Touch ID shim.
//
// Design note on macOS code signing:
//   The biometric data-protection Keychain (SecAccessControl with
//   kSecAccessControlBiometry*) requires the `keychain-access-groups`
//   entitlement, which is *restricted* — an ad-hoc signature carrying it is
//   SIGKILLed by AMFI, and a real one needs a paid Apple Developer certificate.
//
//   So fnVault decouples the two halves that entitlement would have fused:
//     * Touch ID is enforced via LocalAuthentication `evaluatePolicy`
//       (LAPolicyDeviceOwnerAuthentication = biometrics, with passcode
//       fallback). This needs no entitlement and works in an unsigned/ad-hoc
//       binary.
//     * The master key + encrypted blobs live as plain generic-password items
//       in the login Keychain (no access group, no ACL) — also entitlement-free.
//
//   The daemon only reads the master key after a successful evaluatePolicy in
//   the current session. Tradeoff: the OS does not cryptographically bind the
//   key to biometrics, so a process running as the user could read the item
//   directly. See README "Security model". Upgrading to the hardware-bound path
//   only requires a Developer cert + restoring a SecAccessControl flag here.

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>

static NSString *const kMasterService = @"fnvault.masterkey";
static NSString *const kMasterAccount = @"master";
static NSString *const kDataService = @"fnvault.data";

// ---- Touch ID -----------------------------------------------------------

// Prompts Touch ID (with device-passcode fallback) and blocks until the user
// responds. Returns 0 on success, 1 on failure/cancel, 2 if no authentication
// method is available (e.g. no passcode set).
int fnvault_touchid_authenticate(const char *reason) {
    LAContext *ctx = [[LAContext alloc] init];
    NSError *avail = nil;
    LAPolicy policy = LAPolicyDeviceOwnerAuthentication;
    if (![ctx canEvaluatePolicy:policy error:&avail]) {
        return 2;
    }
    NSString *r = reason ? [NSString stringWithUTF8String:reason]
                         : @"Unlock fnVault";
    __block int result = 1;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    [ctx evaluatePolicy:policy
        localizedReason:r
                  reply:^(BOOL success, NSError *error) {
                    (void)error;
                    result = success ? 0 : 1;
                    dispatch_semaphore_signal(sema);
                  }];
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    return result;
}

// ---- master key (plain generic password) --------------------------------

int fnvault_master_key_exists(void) {
    NSDictionary *q = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kMasterService,
        (__bridge id)kSecAttrAccount: kMasterAccount,
        (__bridge id)kSecReturnData: @NO,
    };
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, NULL);
    return st == errSecSuccess ? 1 : 0;
}

int fnvault_store_master_key(const uint8_t *data, size_t len) {
    NSDictionary *del = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kMasterService,
        (__bridge id)kSecAttrAccount: kMasterAccount,
    };
    SecItemDelete((__bridge CFDictionaryRef)del);

    NSData *keyData = [NSData dataWithBytes:data length:len];
    NSDictionary *add = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kMasterService,
        (__bridge id)kSecAttrAccount: kMasterAccount,
        (__bridge id)kSecValueData: keyData,
    };
    OSStatus st = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    return st == errSecSuccess ? 0 : (int)st;
}

// Reads the master key bytes. No prompt — callers must gate this with
// fnvault_touchid_authenticate first.
int fnvault_read_master_key(uint8_t *out, size_t out_cap, size_t *out_len) {
    NSDictionary *q = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kMasterService,
        (__bridge id)kSecAttrAccount: kMasterAccount,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef result = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
    if (st != errSecSuccess) return (int)st;
    NSData *d = (__bridge_transfer NSData *)result;
    if (d.length > out_cap) return 5;
    memcpy(out, d.bytes, d.length);
    *out_len = d.length;
    return 0;
}

int fnvault_delete_master_key(void) {
    NSDictionary *del = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kMasterService,
        (__bridge id)kSecAttrAccount: kMasterAccount,
    };
    OSStatus st = SecItemDelete((__bridge CFDictionaryRef)del);
    return (st == errSecSuccess || st == errSecItemNotFound) ? 0 : 1;
}

// ---- generic data items -------------------------------------------------

int fnvault_set_item(const char *account, const uint8_t *data, size_t len) {
    NSString *acct = [NSString stringWithUTF8String:account];
    NSDictionary *del = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kDataService,
        (__bridge id)kSecAttrAccount: acct,
    };
    SecItemDelete((__bridge CFDictionaryRef)del);

    NSData *v = [NSData dataWithBytes:data length:len];
    NSDictionary *add = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kDataService,
        (__bridge id)kSecAttrAccount: acct,
        (__bridge id)kSecValueData: v,
    };
    OSStatus st = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    return st == errSecSuccess ? 0 : (int)st;
}

int fnvault_get_item(const char *account, uint8_t **out, size_t *out_len) {
    NSString *acct = [NSString stringWithUTF8String:account];
    NSDictionary *q = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kDataService,
        (__bridge id)kSecAttrAccount: acct,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef result = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
    if (st == errSecItemNotFound) {
        *out = NULL;
        *out_len = 0;
        return 1;
    }
    if (st != errSecSuccess) return 2;
    NSData *d = (__bridge_transfer NSData *)result;
    uint8_t *buf = (uint8_t *)malloc(d.length ? d.length : 1);
    memcpy(buf, d.bytes, d.length);
    *out = buf;
    *out_len = d.length;
    return 0;
}

int fnvault_delete_item(const char *account) {
    NSString *acct = [NSString stringWithUTF8String:account];
    NSDictionary *del = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kDataService,
        (__bridge id)kSecAttrAccount: acct,
    };
    OSStatus st = SecItemDelete((__bridge CFDictionaryRef)del);
    return (st == errSecSuccess || st == errSecItemNotFound) ? 0 : 1;
}

void fnvault_free(uint8_t *p) { free(p); }
