#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
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

// Convert hex string to bytes. Returns number of bytes, sets half_byte flag if needed.
int hexstr_to_bytes(const char *hexstr, unsigned char *buf, size_t bufsize, int *half_byte) {
    size_t len = strlen(hexstr);
    *half_byte = (len % 2 == 1); // Odd number of characters?
    size_t bytes_len = (len + 1) / 2;
    if (bytes_len > bufsize) return -1;
    
    for (size_t i = 0; i < bytes_len; i++) {
        int hi = hex_char_to_val(hexstr[2 * i]);
        int lo = 0;
        if ((2 * i + 1) < len) {
            lo = hex_char_to_val(hexstr[2 * i + 1]);
        } else {
            lo = -1; // Indicates half-byte at end
        }
        if (hi < 0 || (lo < 0 && !*half_byte)) return -1;
        buf[i] = (hi << 4) | ((lo >= 0) ? lo : 0);
    }
    return (int)bytes_len;
}

// Check if public key matches prefix
int check_prefix_match(const unsigned char *public_key, const unsigned char *prefix_bytes, 
                      int prefix_len, int half_byte) {
    for (int i = 0; i < prefix_len; i++) {
        if (i == prefix_len - 1 && half_byte) {
            // Only compare high nibble
            if ((public_key[i] >> 4) != (prefix_bytes[i] >> 4)) {
                return 0;
            }
        } else {
            if (public_key[i] != prefix_bytes[i]) {
                return 0;
            }
        }
    }
    return 1;
}

// Check if public key matches suffix
int check_suffix_match(const unsigned char *public_key, const char *hex_pattern) {
    int key_len = 32; // Ed25519 public keys are always 32 bytes
    int pattern_len = strlen(hex_pattern);
    
    // Convert the end of the public key to hex string
    char key_hex[65]; // 32 bytes * 2 + null terminator
    for (int i = 0; i < key_len; i++) {
        sprintf(key_hex + i * 2, "%02x", public_key[i]);
    }
    key_hex[64] = '\0';
    
    // Check if the key ends with the pattern
    if (pattern_len > 64) return 0; // Pattern too long
    
    int key_suffix_start = 64 - pattern_len;
    return (strncmp(key_hex + key_suffix_start, hex_pattern, pattern_len) == 0);
}

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [OPTIONS] <hex_pattern>\n", prog_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --prefix    Match pattern as prefix (default)\n");
    fprintf(stderr, "  -s, --suffix    Match pattern as suffix\n");
    fprintf(stderr, "  -b, --both      Match pattern as both prefix and suffix\n");
    fprintf(stderr, "  -h, --help      Show this help message\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s deadbeef           # Find key with prefix 'deadbeef'\n", prog_name);
    fprintf(stderr, "  %s -s cafe            # Find key with suffix 'cafe'\n", prog_name);
    fprintf(stderr, "  %s -b abc             # Find key with both prefix and suffix 'abc'\n", prog_name);
}

int main(int argc, char *argv[]) {
    int match_prefix = 1;  // Default to prefix matching
    int match_suffix = 0;
    int match_both = 0;
    int opt;
    
    static struct option long_options[] = {
        {"prefix", no_argument, 0, 'p'},
        {"suffix", no_argument, 0, 's'},
        {"both", no_argument, 0, 'b'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "psbh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                match_prefix = 1;
                match_suffix = 0;
                match_both = 0;
                break;
            case 's':
                match_prefix = 0;
                match_suffix = 1;
                match_both = 0;
                break;
            case 'b':
                match_prefix = 0;
                match_suffix = 0;
                match_both = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (optind >= argc) {
        fprintf(stderr, "Error: No hex pattern provided.\n");
        print_usage(argv[0]);
        return 1;
    }
    
    const char *hex_pattern = argv[optind];
    unsigned char pattern_bytes[32];
    int half_byte = 0;
    int pattern_len = hexstr_to_bytes(hex_pattern, pattern_bytes, sizeof(pattern_bytes), &half_byte);
    
    if (pattern_len <= 0) {
        fprintf(stderr, "Invalid hex pattern provided.\n");
        return 1;
    }
    
    unsigned char seed[32];
    unsigned char public_key[32];
    unsigned char private_key[64];
    unsigned long attempts = 0;
    
    // Print what we're looking for
    if (match_both) {
        printf("Looking for public key with both prefix and suffix: %s\n", hex_pattern);
    } else if (match_suffix) {
        printf("Looking for public key ending with: %s\n", hex_pattern);
    } else {
        printf("Looking for public key starting with: %s\n", hex_pattern);
    }
    
    do {
        randombytes(seed, sizeof(seed));
        ed25519_create_keypair(public_key, private_key, seed);
        attempts++;
        
        int match = 0;
        
        if (match_both) {
            // Must match both prefix and suffix
            match = check_prefix_match(public_key, pattern_bytes, pattern_len, half_byte) &&
                   check_suffix_match(public_key, hex_pattern);
        } else if (match_suffix) {
            // Match suffix only
            match = check_suffix_match(public_key, hex_pattern);
        } else {
            // Match prefix only (default)
            match = check_prefix_match(public_key, pattern_bytes, pattern_len, half_byte);
        }
        
        if (match) break;
        
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
