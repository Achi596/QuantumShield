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

| Feature                                   | Status                                                                                     |
| ----------------------------------------- | ------------------------------------------------------------------------------------------ |
| WOTS+ Chains                              | ✅ Implemented                                                                              |
| Merkle Root                               | ✅ Computed from WOTS pk hashes                                                             |
| Auth Path in Signature                    | ✅ Included; signer builds path, verifier recomputes root                                   |
| Proper Root Reconstruction                | ✅ Working via Merkle auth path verification                                                |
| Index Reuse Protection                    | ✅ Persistent state (`xmss_state.dat`); auto key rotation when leaves exhausted             |
| Deterministic PRNG Seeding                | ✅ Optional `--seed N` argument for reproducible testing                                    |
| CSPRNG                                    | ✅ OpenSSL `RAND_bytes()` backend (ChaCha/DRBG depending on build)                          |
| Serialization                             | ✅ Raw struct dumps to disk (`xmss_key.bin`, `sig.bin`)                                     |
| Benchmark Mode                            | ✅ Measures sign/verify, logs CSV                                                           |
| SHAKE / Tweakable Hash                    | ✅ SHAKE256 used (fixed 32‑byte output) **no domain separation / tweak structure yet**      |
| Runtime Parameterization (`w`, `h`)       | ✅ Implemented. Set via `--height <h>` and `--wots <w>` command-line arguments.                                                |
| Side-channel Hardening                    | ✅ Implemented. Constant-time WOTS+ chains and secure memory wiping for sensitive data.                                                   |


---

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
    pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-openssl make
    ```
3. Clone & build:
    ```bash
    git https://github.com/Achi596/QuantumShield
    cd QuantumShield
    make
    ```
4. Run:
    ```bash
    ./hashsig --height 10 --wots 16 -e "hello world"
    ```

## CLI Usage
The project now builds two separate executables: `hashsig` for core functionality and `time_test` for security analysis.

### Main Program: hashsig
```bash
# Sign a message (generates a key on first run)
./hashsig --height <h> --wots <w> -e "your message"

# Verify a message (parameters are read from the signature file)
./hashsig -v "your message"

# Run a benchmark with custom parameters
./hashsig --height <h> --wots <w> -b [keygen_runs sign_runs verify_runs]

# Use a deterministic seed for reproducible results
./hashsig --height <h> --wots <w> --seed 12345 -e "a deterministic signature"
```
### Side-Channel Test Program: time_test
This special program demonstrates the effectiveness of the side-channel hardening.

```bash
./time_test
```
*(See the "Advanced Testing" section below for more details on how to interpret its output.)*

---

## Arguments

| Option                   | Meaning                                                         | Notes                                                                              |
|--------------------------|-----------------------------------------------------------------|------------------------------------------------------------------------------------|
| `--height <h>`           | Set the XMSS Merkle tree height to `h`.                         | Required for signing (`-e`) and benchmarking (`-b`). Larger `h` = more signatures per key. |
| `--wots <w>`             | Set the WOTS+ Winternitz parameter to `w`.                      | Required for signing and benchmarking. Must be a power of 2 (e.g., 4, 16, 256).      |
| `--seed N`               | Use a deterministic RNG seed `N` for reproducible testing.      | Optional. Accepts a 64-bit unsigned integer.                                         |
| `-e "message"`           | **Sign** the given message string.                              | Creates/loads a key, advances the state, and saves the signature.                    |
| `-v "message"`           | **Verify** the signature against the given message.             | Uses `root.hex` and `sig.bin`. Does not require `--height` or `--wots`.            |
| `-b [k s v]`             | **Benchmark** keygen, sign, and verify operations.              | Arguments for runs are optional. Defaults to 10 keygen, 100 sign, 100 verify runs. |

---

## Files Written

| File             | Purpose                                                    | Created by                         |
|------------------|------------------------------------------------------------|------------------------------------|
| `xmss_key.bin`   | XMSS private key (seed) + parameters (`h`, `w`)            | First sign if no key present       |
| `xmss_state.dat` | Current XMSS leaf index (integer)                          | Updated on each sign               |
| `root.hex`       | Public root hash (hex string)                              | Saved on sign                      |
| `sig.bin`        | Last signature produced + parameters (`h`, `w`)            | Saved on sign                      |
| `bench.csv`      | Benchmark results append-log                               | Benchmark mode (`-b`)              |

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

## Advanced Testing: Demonstrating Side-Channel Hardening

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
      - 'Easy' Message (low digits):  0.0000451... s
      - 'Hard' Message (high digits): 0.0000452... s  <-- Almost identical time

    [Vulnerable Function (wots_sign_vulnerable)]
      - 'Easy' Message (low digits):  0.0000031... s
      - 'Hard' Message (high digits): 0.0000429... s  <-- Huge time difference
    
    --- Analysis ---
    Conclusion: The hardened function shows almost no timing difference...
    Side-channel hardening is working as expected.
    ```
The near-zero time difference for the **Hardened Function** is the experimental proof that the side-channel protection is working correctly.
