#ifndef BENCHMARK_H
#define BENCHMARK_H

#include "xmss_config.h"

/* Run benchmark with given iteration counts */
void run_benchmark(const xmss_params *params, int keygen_runs, int sign_runs, int verify_runs);

/* Prints a hint about CSV logging */
void benchmark_print_csv_hint(void);

#endif