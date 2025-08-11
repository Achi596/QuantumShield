#ifndef BENCHMARK_H
#define BENCHMARK_H

#include "xmss_config.h"

// Benchmark the XMSS operations
void run_benchmark(const xmss_params *params, int keygen_runs, int sign_runs, int verify_runs);

#endif