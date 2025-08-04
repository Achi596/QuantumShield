#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "benchmark.h"
#include "timer.h"
#include "xmss.h"
#include "wots.h"
#include "hash.h"
#include "xmss_config.h"
#include "xmss_eth.h"

/* Human readable size helper */
static void human_size(double bytes, char *out, size_t outlen) {
    const char *units[] = {"B","KiB","MiB","GiB"};
    int u = 0;
    double v = bytes;
    while (v >= 1024.0 && u < 3) { v /= 1024.0; u++; }
    snprintf(out, outlen, "%.3f %s", v, units[u]);
}

// Run the benchmark for key generation, signing, and verification.
void run_benchmark(const xmss_params *params, int keygen_runs, int sign_runs, int verify_runs) {
    printf("Benchmarking (h=%d, w=%d), this will take some time...\n", params->h, params->w);

    XMSSKey key;
    const char *msg = "benchmark message";

    double start, end;
    double keygen_total = 0.0, sign_total = 0.0, verify_total = 0.0;

    size_t key_size  = sizeof(XMSSKey);
    size_t sig_size  = xmss_eth_sig_size(params);
    size_t root_size = HASH_SIZE;

    /* KEYGEN benchmark */
    for (int i = 0; i < keygen_runs; i++) {
        start = hires_time_seconds();
        xmss_keygen(params, &key);
        end = hires_time_seconds();
        keygen_total += (end - start);
    }
    double keygen_avg = keygen_total / keygen_runs;

    /* SIGN benchmark (reusing indices cyclically) */
    XMSSSignature sig_sign;
    if (xmss_alloc_sig(&sig_sign, params) != 0) { fprintf(stderr, "Benchmark failed to alloc sig\n"); return; }
    for (int i = 0; i < sign_runs; i++) {
        int idx = i % params->max_keys;
        start = hires_time_seconds();
        xmss_sign_index(params, (const uint8_t*)msg, &key, &sig_sign, idx);
        end = hires_time_seconds();
        sign_total += (end - start);
    }
    double sign_avg = sign_total / sign_runs;
    xmss_free_sig(&sig_sign, params);


    /* VERIFY benchmark */
    double verify_avg = 0.0;
    if (verify_runs > 0) {
        XMSSSignature sig_verify;
        if (xmss_alloc_sig(&sig_verify, params) != 0) { fprintf(stderr, "Benchmark failed to alloc sig\n"); return; }
        for (int i = 0; i < verify_runs; i++) {
            int idx = i % params->max_keys;
            xmss_sign_index(params, (const uint8_t*)msg, &key, &sig_verify, idx);
            start = hires_time_seconds();
            xmss_verify(params, (const uint8_t*)msg, &sig_verify, key.root);
            end = hires_time_seconds();
            verify_total += (end - start);
        }
        verify_avg = verify_total / verify_runs;
        xmss_free_sig(&sig_verify, params);
    }


    char key_hr[32], sig_hr[32], root_hr[32];
    human_size((double)key_size, key_hr, sizeof key_hr);
    human_size((double)sig_size, sig_hr, sizeof sig_hr);
    human_size((double)root_size, root_hr, sizeof root_hr);

    printf("\n===== Benchmark (h=%d, w=%d, Averaged) =====\n", params->h, params->w);
    printf("Keygen runs : %d\n", keygen_runs);
    printf("Sign runs   : %d\n", sign_runs);
    printf("Verify runs : %d\n", verify_runs);
    printf("--------------------------------\n");
    printf("Keygen avg  : %.9f s\n", keygen_avg);
    printf("Sign avg    : %.9f s\n", sign_avg);
    printf("Verify avg  : %.9f s\n", verify_avg);
    printf("--------------------------------\n");
    printf("Key size    : %zu (%s)\n", key_size, key_hr);
    printf("Sig size    : %zu (%s)\n", sig_size, sig_hr);
    printf("Root size   : %zu (%s)\n", root_size, root_hr);
    printf("Msg used    : \"%s\"\n", msg);
    printf("================================\n");

    /* CSV logging */
    const char *csv_file = "bench.csv";
    FILE *chk = fopen(csv_file, "r");
    int need_header = (chk == NULL);
    if(chk) fclose(chk);

    FILE *csv = fopen(csv_file, "a");
    if (!csv) {
        fprintf(stderr, "Warning: could not open %s for append\n", csv_file);
        return;
    }
    if (need_header) {
        fprintf(csv,
            "timestamp,h,w,keygen_runs,sign_runs,verify_runs,"
            "keygen_avg_s,sign_avg_s,verify_avg_s,"
            "key_size_bytes,sig_size_bytes,root_size_bytes\n");
    }
    time_t t = time(NULL);
    fprintf(csv,
        "%lld,%d,%d,%d,%d,%d,%.9f,%.9f,%.9f,%zu,%zu,%zu\n",
        (long long)t,
        params->h, params->w,
        keygen_runs, sign_runs, verify_runs,
        keygen_avg, sign_avg, verify_avg,
        key_size, sig_size, root_size
    );
    fclose(csv);
    printf("Appended results to %s\n", csv_file);
}

void benchmark_print_csv_hint(void) {
    printf("CSV log: bench.csv (auto-appended)\n");
}