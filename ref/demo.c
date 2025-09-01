#include "kem.h"
#include <stdio.h>
#include <string.h>

// helper: print bytes as hex
void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0) printf("\n"); // newline every 32 bytes
    }
    if (len % 32 != 0) printf("\n");
    printf("\n");
}

int main(void) {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char ss_enc[CRYPTO_BYTES];
    unsigned char ss_dec[CRYPTO_BYTES];

    // Alice generates a keypair
    crypto_kem_keypair(pk, sk);
    print_hex("Public Key", pk, sizeof(pk));
    print_hex("Secret Key", sk, sizeof(sk));

    // Bob encapsulates to Alice’s public key
    crypto_kem_enc(ct, ss_enc, pk);
    print_hex("Ciphertext", ct, sizeof(ct));
    print_hex("Shared Secret (Bob)", ss_enc, sizeof(ss_enc));

    // Alice decapsulates using her secret key
    crypto_kem_dec(ss_dec, ct, sk);
    print_hex("Shared Secret (Alice)", ss_dec, sizeof(ss_dec));

    // Check match
    if (memcmp(ss_enc, ss_dec, CRYPTO_BYTES) == 0) {
        printf("✅ Shared secrets match!\n");
    } else {
        printf("❌ Shared secrets DO NOT match!\n");
    }

    return 0;
}
