#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "ed25519.h"

#define ED25519_NO_SEED  1

// Function required by ed25519.c for random number generation
void randombytes(unsigned char *x, size_t len) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        perror("Failed to open /dev/urandom");
        exit(1);
    }
    fread(x, 1, len, fp);
    fclose(fp);
}

void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {

    while (1) {
    gen_key();
    }


    return 0;
}

void gen_key() {
    unsigned char seed[32];
    unsigned char public_key[32];
    unsigned char private_key[64];
    unsigned long attempts = 0;

    do {
        randombytes(seed, sizeof(seed));
        ed25519_create_keypair(public_key, private_key, seed);
        attempts++;
    } while (!(public_key[0] == 0xde && public_key[1] == 0xad));

    printf("Found matching key after %lu attempts!\n", attempts);
    


    print_hex("Seed", seed, sizeof(seed));
    print_hex("Public Key", public_key, sizeof(public_key));
    print_hex("Private Key", private_key, sizeof(private_key));



}
