#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <signal.h>
#include "ed25519.h"

// Global variable to handle SIGINT (Ctrl+C)
volatile sig_atomic_t keep_running = 1;

void signal_handler(int sig) {
    if (sig == SIGINT) {
        keep_running = 0;
        printf("\nStopping search... (Ctrl+C detected)\n");
    }
}

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

// Structure to hold pattern information
typedef struct {
    char *hex_string;
    unsigned char *bytes;
    int byte_len;
    int half_byte;
} pattern_t;

// Check multiple patterns for prefix match
int check_multiple_prefix_match(const unsigned char *public_key, pattern_t *patterns, int num_patterns, int *matched_index) {
    for (int i = 0; i < num_patterns; i++) {
        if (check_prefix_match(public_key, patterns[i].bytes, patterns[i].byte_len, patterns[i].half_byte)) {
            *matched_index = i;
            return 1;
        }
    }
    return 0;
}

// Check multiple patterns for suffix match
int check_multiple_suffix_match(const unsigned char *public_key, pattern_t *patterns, int num_patterns, int *matched_index) {
    for (int i = 0; i < num_patterns; i++) {
        if (check_suffix_match(public_key, patterns[i].hex_string)) {
            *matched_index = i;
            return 1;
        }
    }
    return 0;
}

// Enhanced "either" matching: checks prefix, suffix, AND both for each pattern
int check_multiple_either_match(const unsigned char *public_key, pattern_t *patterns, int num_patterns, int *matched_index, int *match_type) {
    for (int i = 0; i < num_patterns; i++) {
        int prefix_match = check_prefix_match(public_key, patterns[i].bytes, patterns[i].byte_len, patterns[i].half_byte);
        int suffix_match = check_suffix_match(public_key, patterns[i].hex_string);
        
        if (prefix_match && suffix_match) {
            // Both prefix and suffix match - highest priority
            *matched_index = i;
            *match_type = 3; // both
            return 1;
        } else if (prefix_match) {
            // Prefix only
            *matched_index = i;
            *match_type = 1; // prefix
            return 1;
        } else if (suffix_match) {
            // Suffix only
            *matched_index = i;
            *match_type = 2; // suffix
            return 1;
        }
    }
    return 0;
}

int check_multiple_both_match(const unsigned char *public_key, pattern_t *patterns, int num_patterns, int *matched_index) {
    for (int i = 0; i < num_patterns; i++) {
        if (check_prefix_match(public_key, patterns[i].bytes, patterns[i].byte_len, patterns[i].half_byte) &&
            check_suffix_match(public_key, patterns[i].hex_string)) {
            *matched_index = i;
            return 1;
        }
    }
    return 0;
}

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
    fprintf(stderr, "Usage: %s [OPTIONS] <hex_pattern1> [hex_pattern2] ...\n", prog_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --prefix    Match pattern as prefix (default)\n");
    fprintf(stderr, "  -s, --suffix    Match pattern as suffix\n");
    fprintf(stderr, "  -b, --both      Match pattern as both prefix and suffix\n");
    fprintf(stderr, "  -e, --either    Match pattern as prefix OR suffix OR both\n");
    fprintf(stderr, "  -c, --continue  Keep finding matches until Ctrl+C (don't stop at first)\n");
    fprintf(stderr, "  -h, --help      Show this help message\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s deadbeef           # Find key with prefix 'deadbeef'\n", prog_name);
    fprintf(stderr, "  %s -s cafe            # Find key with suffix 'cafe'\n", prog_name);
    fprintf(stderr, "  %s -b abc             # Find key with both prefix and suffix 'abc'\n", prog_name);
    fprintf(stderr, "  %s -e abc             # Find key with 'abc' as prefix OR suffix OR both\n", prog_name);
    fprintf(stderr, "  %s -c deadbeef        # Keep finding keys with prefix 'deadbeef' until Ctrl+C\n", prog_name);
    fprintf(stderr, "  %s -e -c dead beef    # Keep finding keys with 'dead' or 'beef' as prefix OR suffix OR both\n", prog_name);
}

int main(int argc, char *argv[]) {
    int match_prefix = 1;  // Default to prefix matching
    int match_suffix = 0;
    int match_both = 0;
    int match_either = 0;
    int continue_search = 0;  // New option to keep searching
    int opt;
    
    static struct option long_options[] = {
        {"prefix", no_argument, 0, 'p'},
        {"suffix", no_argument, 0, 's'},
        {"both", no_argument, 0, 'b'},
        {"either", no_argument, 0, 'e'},
        {"continue", no_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "psbech", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                match_prefix = 1;
                match_suffix = 0;
                match_both = 0;
                match_either = 0;
                break;
            case 's':
                match_prefix = 0;
                match_suffix = 1;
                match_both = 0;
                match_either = 0;
                break;
            case 'b':
                match_prefix = 0;
                match_suffix = 0;
                match_both = 1;
                match_either = 0;
                break;
            case 'e':
                match_prefix = 0;
                match_suffix = 0;
                match_both = 0;
                match_either = 1;
                break;
            case 'c':
                continue_search = 1;
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
        fprintf(stderr, "Error: No hex patterns provided.\n");
        print_usage(argv[0]);
        return 1;
    }
    
    int num_patterns = argc - optind;
    pattern_t *patterns = malloc(num_patterns * sizeof(pattern_t));
    if (!patterns) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }
    
    // Parse all patterns
    for (int i = 0; i < num_patterns; i++) {
        const char *hex_pattern = argv[optind + i];
        patterns[i].hex_string = strdup(hex_pattern);
        if (!patterns[i].hex_string) {
            fprintf(stderr, "Memory allocation failed.\n");
            return 1;
        }
        
        patterns[i].bytes = malloc(32);
        if (!patterns[i].bytes) {
            fprintf(stderr, "Memory allocation failed.\n");
            return 1;
        }
        
        patterns[i].byte_len = hexstr_to_bytes(hex_pattern, patterns[i].bytes, 32, &patterns[i].half_byte);
        
        if (patterns[i].byte_len <= 0) {
            fprintf(stderr, "Invalid hex pattern provided: %s\n", hex_pattern);
            return 1;
        }
    }
    
    unsigned char seed[32];
    unsigned char public_key[32];
    unsigned char private_key[64];
    unsigned long attempts = 0;
    unsigned long total_matches = 0;
    int matched_index = -1;
    int match_type = 0; // 1=prefix, 2=suffix, 3=both
    
    // Set up signal handler for Ctrl+C
    signal(SIGINT, signal_handler);
    
    // Print what we're looking for
    const char *mode_str;
    if (match_both) {
        mode_str = "both prefix and suffix";
    } else if (match_either) {
        mode_str = "prefix OR suffix OR both";
    } else if (match_suffix) {
        mode_str = "suffix";
    } else {
        mode_str = "prefix";
    }
    
    if (continue_search) {
        printf("Continuously searching for public keys with %s matching one of:\n", mode_str);
    } else {
        printf("Looking for public key with %s matching one of:\n", mode_str);
    }
    
    for (int i = 0; i < num_patterns; i++) {
        printf("  %s\n", patterns[i].hex_string);
    }
    
    if (continue_search) {
        printf("Press Ctrl+C to stop the search.\n\n");
    }
    
    do {
        if (!keep_running) break;  // Check if Ctrl+C was pressed
        
        randombytes(seed, sizeof(seed));
        ed25519_create_keypair(public_key, private_key, seed);
        attempts++;
        
        int match = 0;
        
        if (match_both) {
            // Must match both prefix and suffix
            match = check_multiple_both_match(public_key, patterns, num_patterns, &matched_index);
        } else if (match_either) {
            // Match prefix OR suffix OR both
            match = check_multiple_either_match(public_key, patterns, num_patterns, &matched_index, &match_type);
        } else if (match_suffix) {
            // Match suffix only
            match = check_multiple_suffix_match(public_key, patterns, num_patterns, &matched_index);
        } else {
            // Match prefix only (default)
            match = check_multiple_prefix_match(public_key, patterns, num_patterns, &matched_index);
        }
        
        if (match) {
            total_matches++;
            
            printf("\n=== MATCH #%lu found after %lu attempts ===\n", total_matches, attempts);
            printf("Matched pattern: %s", patterns[matched_index].hex_string);
            
            if (match_either) {
                switch (match_type) {
                    case 1:
                        printf(" (as prefix)");
                        break;
                    case 2:
                        printf(" (as suffix)");
                        break;
                    case 3:
                        printf(" (as both prefix and suffix)");
                        break;
                }
            }
            printf("\n");
            
            print_hex("Seed", seed, sizeof(seed));
            print_hex("Public Key", public_key, sizeof(public_key));
            print_hex("Private Key", private_key, sizeof(private_key));
            printf("\n");
            
            if (!continue_search) break;  // Stop after first match if not in continuous mode
        }
        
        // Optional: print progress every million attempts
        if (attempts % 1000000 == 0) {
            printf("Attempts: %lu, Matches found: %lu\n", attempts, total_matches);
        }
    } while (keep_running);
    
    if (continue_search) {
        printf("\n=== SEARCH SUMMARY ===\n");
        printf("Total attempts: %lu\n", attempts);
        printf("Total matches found: %lu\n", total_matches);
        if (total_matches > 0) {
            printf("Average attempts per match: %.1f\n", (double)attempts / total_matches);
        }
    } else if (total_matches == 0) {
        printf("No matches found after %lu attempts.\n", attempts);
    }
    
    // Cleanup
    for (int i = 0; i < num_patterns; i++) {
        free(patterns[i].hex_string);
        free(patterns[i].bytes);
    }
    free(patterns);
    
    return 0;
}
