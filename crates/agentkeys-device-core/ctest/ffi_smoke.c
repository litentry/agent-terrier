// Smoke test for the agentkeys-device-core C ABI (issue #367). Links the SAME
// no_std staticlib the ESP32 firmware does and exercises the exact FFI the
// device's main/net/device_identity.c calls — so the C boundary is verified on
// any host, with no board and no Xtensa toolchain.
//
// Build + run via: bash crates/agentkeys-device-core/test-ffi.sh
#include <stdio.h>
#include <string.h>

#include "agentkeys_device.h"

static int g_fail = 0;

static void check(int cond, const char *msg)
{
    printf("%s %s\n", cond ? "ok  " : "FAIL", msg);
    if (!cond) {
        g_fail = 1;
    }
}

int main(void)
{
    // Fixed entropy → a deterministic identity (the same scalar the Rust unit
    // tests use), so the printed values are reproducible across runs/platforms.
    unsigned char entropy[32];
    memset(entropy, 0x11, sizeof(entropy));

    unsigned char priv[32];
    char addr[43], addr2[43], hash[67], sig[133], dsig[133];

    check(ak_device_keygen(entropy, priv, addr, sizeof(addr)) == AK_OK, "ak_device_keygen -> AK_OK");
    check(memcmp(priv, entropy, 32) == 0, "priv == entropy (valid scalar copied out)");
    check(strncmp(addr, "0x", 2) == 0 && strlen(addr) == 42, "address is 0x + 40 hex");

    check(ak_device_address(priv, addr2, sizeof(addr2)) == AK_OK && strcmp(addr, addr2) == 0,
          "ak_device_address (NVS load path) matches keygen address");

    check(ak_device_key_hash(addr, hash, sizeof(hash)) == AK_OK && strncmp(hash, "0x", 2) == 0 &&
              strlen(hash) == 66,
          "device_key_hash is 0x + 64 hex");

    check(ak_device_pop_sig(priv, sig, sizeof(sig)) == AK_OK && strncmp(sig, "0x", 2) == 0 &&
              strlen(sig) == 132,
          "pop_sig is 0x + 130 hex (r||s||v) — the broker's §10.2 input");

    // Device→sandbox delegation co-signature (#369): authorize a fixed sandbox key
    // (address of entropy 0x22*32) scoped + expiring, signed with THIS device's K10.
    const char *sandbox_key = "0x1563915e194d8cfba1943570603f7606a3115508";
    const char *scope = "memory:get memory:put";
    check(ak_device_delegation_sig(priv, sandbox_key, scope, 1767300000ULL, dsig, sizeof(dsig)) ==
                  AK_OK &&
              strncmp(dsig, "0x", 2) == 0 && strlen(dsig) == 132,
          "delegation_sig is 0x + 130 hex (r||s||v) — the worker's #369 input");

    // Error paths: a short buffer and a null pointer must report, not corrupt.
    char tiny[4];
    check(ak_device_key_hash(addr, tiny, sizeof(tiny)) == AK_BUFFER_TOO_SMALL,
          "short buffer -> AK_BUFFER_TOO_SMALL");
    check(ak_device_pop_sig(NULL, sig, sizeof(sig)) == AK_NULL_PTR, "null priv -> AK_NULL_PTR");
    check(ak_device_delegation_sig(priv, NULL, scope, 0ULL, dsig, sizeof(dsig)) == AK_NULL_PTR,
          "null sandbox_key -> AK_NULL_PTR");

    // Golden vectors for entropy = 0x11*32 — the secp256k1 / keccak / RFC6979-EIP191
    // outputs the broker also computes. Pinning the exact bytes makes ANY drift in
    // the shared derivation a hard failure (the whole point of the one-crate design).
    check(strcmp(addr, "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a") == 0, "address == golden vector");
    check(strcmp(hash, "0x8dd832049319556c1cd22ed66ae790d07fea25830a6151c2f0a9879b3ef61305") == 0,
          "device_key_hash == golden vector");
    check(strcmp(sig,
                 "0x548582e9b1db4a55358035e8d21361a0ced7f63d8f40796c3529fb8e64406aeb462e245c20389884eb4070cf2"
                 "ac9ea75ece6a9f37483afc9745dc71998c1b63d1c") == 0,
          "pop_sig == golden vector");
    check(strcmp(dsig,
                 "0xbbd09776536fb12816a0067f97deee22dbe2cfebf67b24450991aa8f7394f7620250d27d15c32efaeadbb111f4"
                 "b128bde385e019a6c36ef504d7dd1ea8688de71b") == 0,
          "delegation_sig == golden vector (matches the Rust unit test)");

    printf("\n%s\n", g_fail ? "DEVICE-CORE FFI: FAIL" : "DEVICE-CORE FFI: PASS");
    printf("addr  = %s\nhash  = %s\nsig   = %s\ndsig  = %s\n", addr, hash, sig, dsig);
    return g_fail;
}
