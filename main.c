#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "ed25519.h"

// RNG function required by ed25519.c
void randombytes(unsigned char *x, size_t len) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        perror("Unable to open /dev/urandom");
        exit(1);
    }
    fread(x, 1, len, fp);
    fclose(fp);
}

// Print bytes as hex
void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Convert hex digit char to number
int hex_char_to_val(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return 10 + c - 'a';
    if ('A' <= c && c <= 'F') return 10 + c - 'A';
    return -1;
}

// Convert hex string to bytes. Returns number of bytes or -1 if error
int hexstr_to_bytes(const char *hexstr, unsigned char *buf, size_t bufsize) {
    size_t len = strlen(hexstr);
    if (len % 2 != 0) return -1; // must be even length

    size_t bytes_len = len / 2;
    if (bytes_len > bufsize) return -1;

    for (size_t i = 0; i < bytes_len; i++) {
        int hi = hex_char_to_val(hexstr[2 * i]);
        int lo = hex_char_to_val(hexstr[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        buf[i] = (hi << 4) | lo;
    }
    return (int)bytes_len;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <hex_prefix>\n", argv[0]);
        fprintf(stderr, "Example: %s deadbeef\n", argv[0]);
        return 1;
    }

    const char *hex_prefix = argv[1];
    unsigned char prefix_bytes[32];
    int prefix_len = hexstr_to_bytes(hex_prefix, prefix_bytes, sizeof(prefix_bytes));
    if (prefix_len <= 0) {
        fprintf(stderr, "Invalid hex prefix provided.\n");
        return 1;
    }

    unsigned char seed[32];
    unsigned char public_key[32];
    unsigned char private_key[64];
    unsigned long attempts = 0;

    printf("Looking for public key starting with: %s\n", hex_prefix);

    do {
        randombytes(seed, sizeof(seed));
        ed25519_create_keypair(public_key, private_key, seed);
        attempts++;

        if (memcmp(public_key, prefix_bytes, prefix_len) == 0) {
            break;
        }

        // Optional: print progress every million attempts
        if (attempts % 1000000 == 0) {
            printf("Attempts: %lu\n", attempts);
        }

    } while (1);

    printf("Found matching key after %lu attempts!\n", attempts);

    print_hex("Seed", seed, sizeof(seed));
    print_hex("Public Key", public_key, sizeof(public_key));
    print_hex("Private Key", private_key, sizeof(private_key));

    return 0;
}

