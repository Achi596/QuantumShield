# QuantumShield: XMSS + WOTS+ Hash-Based Signature Prototype

**QuantumShield** is a minimal, educational C implementation of **WOTS+** (Winternitz One-Time Signatures) wrapped in an **XMSS** (Merkle tree) many-time signature scheme. It’s intended for experimentation with **post-quantum hash-based signatures**, inspired by ideas explored in:

> **Hash-Based Multi-Signatures for Post-Quantum Ethereum**  
> ePrint 2025/055 – Drake, Khovratovich, Kudinov, Wagner  
> https://eprint.iacr.org/2025/055


---

## Table of Contents
- [Features](#features)
- [Build Requirements](#build-requirements)
- [Quick Build (Linux)](#quick-build-linux)
- [Quick Build (Windows / MSYS2 UCRT64)](#quick-build-windows--msys2-ucrt64)
- [CLI Usage](#cli-usage)
- [Arguments](#arguments)
- [Files Written](#files-written)
- [Implementation Details: How It Works](#implementation-details-how-it-works)
  - [Runtime Parameterization (`h` and `w`)](#runtime-parameterization-h-and-w)
  - [Side-Channel Hardening](#side-channel-hardening)
- [Advanced Testing: Demonstrating Side-Channel Hardening](#advanced-testing-demonstrating-side-channel-hardening)

---

## Features

## ✅ XMSS Implementation Feature Checklist

| **Feature**                              | **Status**                                                                                   |
|------------------------------------------|----------------------------------------------------------------------------------------------|
| **WOTS+ Chains**                         | ✅ Implemented                                                                               |
| **Merkle Root**                          | ✅ Derived from WOTS+ public key hashes                                                      |
| **Authentication Path in Signature**     | ✅ Included in signature; verifier recomputes Merkle root                                    |
| **Proper Root Reconstruction**           | ✅ Verified using the authentication path                                                    |
| **Index Reuse Protection**               | ✅ Persistent state via `xmss_state.dat`; auto key rotation when all leaves are used         |
| **Deterministic PRNG Seeding**           | ✅ Optional `--seed <N>` argument for reproducible testing                                   |
| **CSPRNG**                               | ✅ Backed by OpenSSL `RAND_bytes()` (ChaCha20/DRBG depending on build configuration)         |
| **Serialization**                        | ✅ Raw binary dumps to disk (`xmss_key.bin`, `sig.bin`)                                      |
| **Benchmark Mode**                       | ✅ Measures sign/verify performance and logs results in CSV format                           |
| **Quantum-Resistant Hashing**            | ✅ SHAKE256 used with fixed 32-byte output                                                   |
| **Runtime Parameterization**             | ✅ Parameters `w` and `h` configurable via CLI: `--wots <w>`, `--height <h>`                 |
| **Side-Channel Hardening**               | ✅ Constant-time WOTS+ chains; secure memory clearing of sensitive buffers                   |
| **Multi-Signature Aggregation (SNARK)**  | ✅ SNARK-export mode outputs JSON with `{message, index, root, WOTS sig, auth path}` for easy verification by validators         |



## Build Requirements

### Libraries / Tools
- C compiler (GCC or Clang)
- OpenSSL development headers & libraries (for RNG + hash)
- Make

---

## Quick Build (Linux)

```bash
git clone https://github.com/Achi596/QuantumShield
cd QuantumShield
make
./hashsig -e "hello world"
```

## Quick Build (Windows)
1. Install MSYS2, open **MSYS2 UCRT64** shell.
2. Install toolchain + OpenSSL:
    ```bash
    pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-jansson make
    ```
3. Clone & build:
    ```bash
    git clone https://github.com/Achi596/QuantumShield
    cd QuantumShield
    make
    ```
4. Run:
    ```bash
    ./hashsig -e "hello world"
    ```

## CLI Usage
```bash
Mode:
    ./hashsig -e "message"          # Sign: generate or load key, sign message, save state
    ./hashsig -v "message"          # Verify: load root + signature, check vs message
    ./hashsig -b [k s v]            # Benchmark: sign/verify loops (defaults 100 1000 1000)

Benchmarking Options:
    [k]       # Number of key generations
    [s]       # Number of sign operations
    [v]       # Number of verify operations

Optional Parameters (used with sign or benchmark):
    --height <h>                      # Set XMSS Merkle tree height (default = 5)
    --wots <w>                        # Set WOTS+ Winternitz parameter (default = 8, must be power of 2)
    --seed N                          # Deterministic RNG seed for reproducibility
    --export-snark <filename.json>    # Export SNARK data to JSON file
```

## Arguments

| Option      | Meaning                                             | Notes                                                              |
|-------------|-----------------------------------------------------|--------------------------------------------------------------------|
| `-e "msg"`  | Sign message string                                 | Creates/loads a key and advances XMSS index.                       |
| `-v "msg"`  | Verify signed message                               | Uses `root.hex` (root key in hex) and `sig.bin` (binary signature).|
| `-b [k s v]`| Benchmark operations: keygen, sign, verify runs     | Defaults to 100 keygen, 1000 sign, 1000 verify runs.               |
| `--seed N`  | Use deterministic RNG seed for reproducible testing | Optional; accepts uint64_t decimal values.                         |
| `--export-snark <file>` | Export SNARK data related to signatures to JSON file | Optional; outputs signature and proof data in JSON format.          |

## Files Written

| File             | Purpose                                                    | Created by                         |
|------------------|------------------------------------------------------------|------------------------------------|
| `xmss_key.bin`   | XMSS private key (seed) + parameters (`h`, `w`)            | First sign if no key present       |
| `xmss_state.dat` | Current XMSS leaf index (integer)                          | Updated on each sign               |
| `root.hex`       | Public root hash (hex string)                              | Saved on sign                      |
| `sig.bin`        | Last signature produced + parameters (`h`, `w`)            | Saved on sign                      |
| `bench.csv`      | Benchmark results append-log                               | Benchmark mode (`-b`)              |
| `<filename>.json`| Exported SNARK signature and proof data in JSON format | Created when using `--export-snark` option |

---

## Implementation Details: How It Works

Two major features were added to enhance the flexibility and security of the original codebase: Runtime Parameterization and Side-Channel Hardening. Here’s a brief overview of how they were implemented.

### Runtime Parameterization (`h` and `w`)

This feature allows the XMSS tree height (`h`) and WOTS+ parameter (`w`) to be set at runtime via command-line arguments, rather than being fixed at compile time.

*   **Configuration Module (`xmss_config.c`, `xmss_config.h`)**:
    *   A new `xmss_params` struct was introduced to hold `h`, `w`, and all parameters derived from them (like `wots_len`, `max_keys`, etc.).
    *   The `xmss_params_init()` function calculates all derived values, centralizing parameter management.

*   **Dynamic Memory Allocation**:
    *   Data structures that previously had fixed-size arrays (e.g., `WOTSKey`, `XMSSSignature`) were modified to use pointers (`uint8_t**`).
    *   Their memory is now allocated dynamically at runtime using `malloc` based on the values in the `xmss_params` struct.
    *   Helper functions like `wots_alloc_key()` and `xmss_alloc_sig()` were created to manage this memory.

*   **Function Signature Updates**:
    *   Nearly all core cryptographic functions (e.g., `xmss_keygen`, `wots_sign`) were updated to accept a `const xmss_params*` argument, giving them access to the runtime parameters.

*   **File Format Changes**:
    *   To allow for correct deserialization, key and signature files (`xmss_key.bin`, `sig.bin`) now store the `h` and `w` parameters at the beginning of the file, followed by the main data payload.

### Side-Channel Hardening

This feature protects the implementation against timing attacks, where an attacker could deduce secret information by measuring the time it takes to perform cryptographic operations.

*   **Constant-Time WOTS+ Chains (`wots.c`)**:
    *   The most critical vulnerability was in the WOTS+ signing function, where the number of hash operations depended on the message being signed.
    *   This was fixed by rewriting the hash chain logic in `wots_chain_ct()`. This new function **always** performs the maximum number of hash iterations (`w-1`), regardless of the input.
    *   It then uses a branchless, constant-time `conditional_select()` function (see `util.c`) to pick the correct intermediate hash result without leaking timing information through `if` statements.

*   **Secure Memory Wiping (`util.c`)**:
    *   A new utility function, `secure_zero_memory()`, was introduced.
    *   This function uses a `volatile` pointer to reliably erase sensitive data (like secret keys, seeds, and intermediate values) from memory after it is no longer needed.
    *   This prevents secrets from being recovered from a memory dump and mitigates certain classes of cold boot attacks. Calls to this function were added throughout the codebase where sensitive data is handled.

---

### Advanced Testing - Side-Channel Verification Program: time_test
This special program demonstrates the effectiveness of the side-channel hardening:

```bash
./time_test
```

A critical security feature of this implementation is its hardening against **timing attacks**. This is not something that can be observed through normal sign/verify operations. We have therefore created a dedicated `time_test` executable to prove its effectiveness.

### The Vulnerability

A naive implementation of WOTS+ signing would take a variable amount of time, depending on the message being signed. Signing a message whose hash contains many small numbers would be much faster than signing one with many large numbers. An attacker could exploit this time difference to learn information about the message hash, breaking the signature scheme.

### The Hardening

Our implementation uses a **constant-time** algorithm (`wots_chain_ct`). No matter what the message is, the signing function performs the exact same number of computationally expensive operations, and uses branchless, bitwise selections to pick the correct result. This eliminates the timing leak.

### How to Test It

1.  **Build the test program**: The `time_test` executable is built automatically when you run `make`.
2.  **Run the test**:
    ```bash
    ./time_test
    ```
3.  **Interpret the results**: The program will time the signing of two "extreme" messages ("easy" vs. "hard") using both our hardened function and an intentionally vulnerable one.

    **Expected Output:**
    ```
    --- Results (Average Time per Signature) ---
    [Hardened Function (wots_sign)]
      - 'Easy' Message (low digits):  0.000462038860 s
      - 'Hard' Message (high digits): 0.000461353100 s  <-- Almost identical time

    [Vulnerable Function (wots_sign_vulnerable)]
      - 'Easy' Message (low digits):  0.000192647710 s
      - 'Hard' Message (high digits): 0.000204254920 s  <-- Huge time difference
 
    ···
    ```
The near-zero time difference for the **Hardened Function** is the experimental proof that the side-channel protection is working correctly.
