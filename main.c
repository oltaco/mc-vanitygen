#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include "ed25519.h"

// Global variables for thread coordination
volatile sig_atomic_t keep_running = 1;
volatile sig_atomic_t match_found = 0;
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

// Global statistics
unsigned long total_attempts = 0;
unsigned long total_matches = 0;
time_t start_time;

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

// Print bytes as hex (thread-safe version)
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

// Convert hex string to bytes
int hexstr_to_bytes(const char *hexstr, unsigned char *buf, size_t bufsize, int *half_byte) {
    size_t len = strlen(hexstr);
    *half_byte = (len % 2 == 1);
    size_t bytes_len = (len + 1) / 2;
    if (bytes_len > bufsize) return -1;
    for (size_t i = 0; i < bytes_len; i++) {
        int hi = hex_char_to_val(hexstr[2 * i]);
        int lo = 0;
        if ((2 * i + 1) < len) {
            lo = hex_char_to_val(hexstr[2 * i + 1]);
        } else {
            lo = -1;
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
    unsigned char *suffix_bytes;
    int suffix_byte_len;
    int suffix_half_byte;
} pattern_t;

// Thread data structure
typedef struct {
    int thread_id;
    pattern_t *patterns;
    int num_patterns;
    int match_mode; // 1=prefix, 2=suffix, 3=both, 4=either
    int continue_search;
    unsigned long local_attempts;
    unsigned long local_matches;
} thread_data_t;

// Forward declarations
int check_prefix_match(const unsigned char *public_key, const unsigned char *prefix_bytes, int prefix_len, int half_byte);
int check_suffix_match_optimized(const unsigned char *public_key, const pattern_t *pattern);
int check_multiple_prefix_match(const unsigned char *public_key, pattern_t *patterns, int num_patterns, int *matched_index);
int check_multiple_suffix_match_optimized(const unsigned char *public_key, pattern_t *patterns, int num_patterns, int *matched_index);
int check_multiple_both_match_optimized(const unsigned char *public_key, pattern_t *patterns, int num_patterns, int *matched_index);
int check_multiple_either_match_optimized(const unsigned char *public_key, pattern_t *patterns, int num_patterns, int *matched_index, int *match_type);

// Suffix matching functions (same as before)
int preprocess_suffix_pattern(pattern_t *pattern) {
    const char *hex_str = pattern->hex_string;
    int hex_len = strlen(hex_str);
    
    pattern->suffix_half_byte = (hex_len % 2 == 1);
    pattern->suffix_byte_len = (hex_len + 1) / 2;
    
    pattern->suffix_bytes = malloc(pattern->suffix_byte_len);
    if (!pattern->suffix_bytes) {
        return -1;
    }
    
    for (int i = 0; i < pattern->suffix_byte_len; i++) {
        int hi_idx = 2 * i;
        int lo_idx = 2 * i + 1;
        
        int hi = 0, lo = 0;
        
        if (hi_idx < hex_len) {
            hi = hex_char_to_val(hex_str[hi_idx]);
            if (hi < 0) return -1;
        }
        
        if (lo_idx < hex_len) {
            lo = hex_char_to_val(hex_str[lo_idx]);
            if (lo < 0) return -1;
        }
        
        pattern->suffix_bytes[i] = (hi << 4) | lo;
    }
    
    return 0;
}

int check_suffix_match_optimized(const unsigned char *public_key, const pattern_t *pattern) {
    const int key_len = 32;
    const char *hex_str = pattern->hex_string;
    int hex_len = strlen(hex_str);
    
    if (hex_len > key_len * 2) {
        return 0;
    }
    
    int bytes_needed = (hex_len + 1) / 2;
    int key_start = key_len - bytes_needed;
    
    char key_hex[65];
    for (int i = 0; i < bytes_needed; i++) {
        sprintf(key_hex + i * 2, "%02x", public_key[key_start + i]);
    }
    
    if (hex_len % 2 == 1) {
        return (strncmp(key_hex + 1, hex_str, hex_len) == 0);
    } else {
        return (strncmp(key_hex, hex_str, hex_len) == 0);
    }
}

// All the matching functions (same as before)
int check_prefix_match(const unsigned char *public_key, const unsigned char *prefix_bytes,
                      int prefix_len, int half_byte) {
    for (int i = 0; i < prefix_len; i++) {
        if (i == prefix_len - 1 && half_byte) {
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

int check_multiple_prefix_match(const unsigned char *public_key, pattern_t *patterns, int num_patterns, int *matched_index) {
    for (int i = 0; i < num_patterns; i++) {
        if (check_prefix_match(public_key, patterns[i].bytes, patterns[i].byte_len, patterns[i].half_byte)) {
            *matched_index = i;
            return 1;
        }
    }
    return 0;
}

int check_multiple_suffix_match_optimized(const unsigned char *public_key, pattern_t *patterns, int num_patterns, int *matched_index) {
    for (int i = 0; i < num_patterns; i++) {
        if (check_suffix_match_optimized(public_key, &patterns[i])) {
            *matched_index = i;
            return 1;
        }
    }
    return 0;
}

int check_multiple_both_match_optimized(const unsigned char *public_key, pattern_t *patterns, int num_patterns, int *matched_index) {
    for (int i = 0; i < num_patterns; i++) {
        if (check_prefix_match(public_key, patterns[i].bytes, patterns[i].byte_len, patterns[i].half_byte) &&
            check_suffix_match_optimized(public_key, &patterns[i])) {
            *matched_index = i;
            return 1;
        }
    }
    return 0;
}

int check_multiple_either_match_optimized(const unsigned char *public_key, pattern_t *patterns, int num_patterns, int *matched_index, int *match_type) {
    int prefix_matches[num_patterns];
    int suffix_matches[num_patterns];
    
    for (int i = 0; i < num_patterns; i++) {
        prefix_matches[i] = check_prefix_match(public_key, patterns[i].bytes, patterns[i].byte_len, patterns[i].half_byte);
        suffix_matches[i] = check_suffix_match_optimized(public_key, &patterns[i]);
    }
    
    // Priority 1: Same-pattern both matches
    for (int i = 0; i < num_patterns; i++) {
        if (prefix_matches[i] && suffix_matches[i]) {
            *matched_index = i;
            *match_type = 3;
            return 1;
        }
    }
    
    // Priority 2: Cross-pattern matches
    if (num_patterns > 1) {
        for (int i = 0; i < num_patterns; i++) {
            if (prefix_matches[i]) {
                for (int j = 0; j < num_patterns; j++) {
                    if (j != i && suffix_matches[j]) {
                        *matched_index = i;
                        *match_type = 4;
                        return 1;
                    }
                }
            }
        }
    }
    
    // Priority 3: Single matches
    for (int i = 0; i < num_patterns; i++) {
        if (prefix_matches[i]) {
            *matched_index = i;
            *match_type = 1;
            return 1;
        }
    }
    
    for (int i = 0; i < num_patterns; i++) {
        if (suffix_matches[i]) {
            *matched_index = i;
            *match_type = 2;
            return 1;
        }
    }
    
    return 0;
}

// Thread function
void* worker_thread(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;
    unsigned char seed[32];
    unsigned char public_key[32];
    unsigned char private_key[64];
    int matched_index = -1;
    int match_type = 0;
    
    data->local_attempts = 0;
    data->local_matches = 0;
    
    while (keep_running && (!match_found || data->continue_search)) {
        randombytes(seed, sizeof(seed));
        ed25519_create_keypair(public_key, private_key, seed);
        data->local_attempts++;
        
        int match = 0;
        if (data->match_mode == 1) { // prefix
            match = check_multiple_prefix_match(public_key, data->patterns, data->num_patterns, &matched_index);
        } else if (data->match_mode == 2) { // suffix
            match = check_multiple_suffix_match_optimized(public_key, data->patterns, data->num_patterns, &matched_index);
        } else if (data->match_mode == 3) { // both
            match = check_multiple_both_match_optimized(public_key, data->patterns, data->num_patterns, &matched_index);
        } else if (data->match_mode == 4) { // either
            match = check_multiple_either_match_optimized(public_key, data->patterns, data->num_patterns, &matched_index, &match_type);
        }
        
        if (match) {
            pthread_mutex_lock(&print_mutex);
            
            // Update global stats
            pthread_mutex_lock(&stats_mutex);
            total_matches++;
            unsigned long current_total_matches = total_matches;
            pthread_mutex_unlock(&stats_mutex);
            
            data->local_matches++;
            
            time_t current_time = time(NULL);
            double elapsed_time = difftime(current_time, start_time);
            
            printf("\n=== MATCH #%lu found by thread %d after %lu local attempts ===\n", 
                   current_total_matches, data->thread_id, data->local_attempts);
            printf("Time elapsed: %.0f seconds\n", elapsed_time);
            
            printf("Matched pattern: %s", data->patterns[matched_index].hex_string);
            if (data->match_mode == 4) { // either mode
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
                    case 4: {
                        printf(" (as prefix, with ");
                        for (int k = 0; k < data->num_patterns; k++) {
                            if (k != matched_index && check_suffix_match_optimized(public_key, &data->patterns[k])) {
                                printf("%s as suffix", data->patterns[k].hex_string);
                                break;
                            }
                        }
                        printf(")");
                        break;
                    }
                }
            }
            printf("\n");
            
            print_hex("Seed", seed, sizeof(seed));
            print_hex("Public Key", public_key, sizeof(public_key));
            print_hex("Private Key", private_key, sizeof(private_key));
            printf("\n");
            
            pthread_mutex_unlock(&print_mutex);
            
            if (!data->continue_search) {
                match_found = 1;
                break;
            }
        }
        
        // Update global stats periodically
        if (data->local_attempts % 100000 == 0) {
            pthread_mutex_lock(&stats_mutex);
            total_attempts += 100000;
            pthread_mutex_unlock(&stats_mutex);
        }
    }
    
    // Final stats update
    pthread_mutex_lock(&stats_mutex);
    total_attempts += data->local_attempts % 100000;
    pthread_mutex_unlock(&stats_mutex);
    
    return NULL;
}

// Memory cleanup function
void cleanup_patterns(pattern_t *patterns, int num_patterns) {
    for (int i = 0; i < num_patterns; i++) {
        free(patterns[i].hex_string);
        free(patterns[i].bytes);
        free(patterns[i].suffix_bytes);
    }
    free(patterns);
}

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [OPTIONS] <hex_pattern1> [hex_pattern2] ...\n", prog_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --prefix    Match pattern as prefix (default)\n");
    fprintf(stderr, "  -s, --suffix    Match pattern as suffix\n");
    fprintf(stderr, "  -b, --both      Match pattern as both prefix and suffix\n");
    fprintf(stderr, "  -e, --either    Match pattern as prefix OR suffix OR both\n");
    fprintf(stderr, "  -c, --continue  Keep finding matches until Ctrl+C (don't stop at first)\n");
    fprintf(stderr, "  -t, --threads   Number of threads to use (default: number of CPU cores)\n");
    fprintf(stderr, "  -h, --help      Show this help message\n");
}

int main(int argc, char *argv[]) {
    int match_prefix = 1;
    int match_suffix = 0;
    int match_both = 0;
    int match_either = 0;
    int continue_search = 0;
    int num_threads = sysconf(_SC_NPROCESSORS_ONLN); // Default to number of CPU cores
    int opt;
    
    static struct option long_options[] = {
        {"prefix", no_argument, 0, 'p'},
        {"suffix", no_argument, 0, 's'},
        {"both", no_argument, 0, 'b'},
        {"either", no_argument, 0, 'e'},
        {"continue", no_argument, 0, 'c'},
        {"threads", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "psbect:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                match_prefix = 1; match_suffix = 0; match_both = 0; match_either = 0;
                break;
            case 's':
                match_prefix = 0; match_suffix = 1; match_both = 0; match_either = 0;
                break;
            case 'b':
                match_prefix = 0; match_suffix = 0; match_both = 1; match_either = 0;
                break;
            case 'e':
                match_prefix = 0; match_suffix = 0; match_both = 0; match_either = 1;
                break;
            case 'c':
                continue_search = 1;
                break;
            case 't':
                num_threads = atoi(optarg);
                if (num_threads <= 0) {
                    fprintf(stderr, "Invalid number of threads: %s\n", optarg);
                    return 1;
                }
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
    
    // Parse patterns (same as before)
    for (int i = 0; i < num_patterns; i++) {
        const char *hex_pattern = argv[optind + i];
        patterns[i].hex_string = strdup(hex_pattern);
        if (!patterns[i].hex_string) {
            fprintf(stderr, "Memory allocation failed.\n");
            cleanup_patterns(patterns, i);
            return 1;
        }
        
        patterns[i].bytes = malloc(32);
        if (!patterns[i].bytes) {
            fprintf(stderr, "Memory allocation failed.\n");
            cleanup_patterns(patterns, i + 1);
            return 1;
        }
        patterns[i].byte_len = hexstr_to_bytes(hex_pattern, patterns[i].bytes, 32, &patterns[i].half_byte);
        if (patterns[i].byte_len <= 0) {
            fprintf(stderr, "Invalid hex pattern provided: %s\n", hex_pattern);
            cleanup_patterns(patterns, i + 1);
            return 1;
        }
        
        if (preprocess_suffix_pattern(&patterns[i]) < 0) {
            fprintf(stderr, "Failed to preprocess suffix pattern: %s\n", hex_pattern);
            cleanup_patterns(patterns, i + 1);
            return 1;
        }
    }
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    
    // Print search information
    const char *mode_str;
    int match_mode;
    if (match_both) {
        mode_str = "both prefix and suffix";
        match_mode = 3;
    } else if (match_either) {
        mode_str = "prefix OR suffix OR both (including cross-pattern matches)";
        match_mode = 4;
    } else if (match_suffix) {
        mode_str = "suffix";
        match_mode = 2;
    } else {
        mode_str = "prefix";
        match_mode = 1;
    }
    
    printf("Using %d threads to search for public keys with %s matching one of:\n", num_threads, mode_str);
    for (int i = 0; i < num_patterns; i++) {
        printf("  %s\n", patterns[i].hex_string);
    }
    if (continue_search) {
        printf("Press Ctrl+C to stop the search.\n\n");
    }
    
    // Create threads
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    thread_data_t *thread_data = malloc(num_threads * sizeof(thread_data_t));
    
    start_time = time(NULL);
    
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].patterns = patterns;
        thread_data[i].num_patterns = num_patterns;
        thread_data[i].match_mode = match_mode;
        thread_data[i].continue_search = continue_search;
        
        if (pthread_create(&threads[i], NULL, worker_thread, &thread_data[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            return 1;
        }
    }
    
    // Progress reporting thread
    while (keep_running && (!match_found || continue_search)) {
        sleep(10); // Report every 10 seconds
        
        pthread_mutex_lock(&stats_mutex);
        unsigned long current_attempts = total_attempts;
        unsigned long current_matches = total_matches;
        pthread_mutex_unlock(&stats_mutex);
        
        time_t current_time = time(NULL);
        double elapsed = difftime(current_time, start_time);
        
        if (elapsed > 0) {
            printf("Progress: %lu attempts, %lu matches, %.1f att/sec (%.1f sec elapsed)\n",
                   current_attempts, current_matches, current_attempts / elapsed, elapsed);
        }
    }
    
    // Wait for all threads to finish
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Final statistics
    time_t end_time = time(NULL);
    double total_elapsed = difftime(end_time, start_time);
    
    printf("\n=== FINAL STATISTICS ===\n");
    printf("Total attempts: %lu\n", total_attempts);
    printf("Total matches: %lu\n", total_matches);
    printf("Total time: %.0f seconds\n", total_elapsed);
    if (total_elapsed > 0) {
        printf("Average rate: %.1f attempts/second\n", total_attempts / total_elapsed);
    }
    if (total_matches > 0) {
        printf("Average attempts per match: %.1f\n", (double)total_attempts / total_matches);
    }
    
    // Cleanup
    free(threads);
    free(thread_data);
    cleanup_patterns(patterns, num_patterns);
    
    return 0;
}