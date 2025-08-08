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
| **Multi-Signature Aggregation (SNARK)**  | ✅ SNARK mode outputs a self validating JSON for easy verification of the XMSS signiture by validators         |



## Build Requirements

### Libraries / Tools
- C compiler (GCC or Clang)
- OpenSSL development headers & libraries (for RNG + hash)
- Jansson (JSON utilities library)
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
    --seed <N>                        # Deterministic RNG seed for reproducibility; accepts a uint64_t value
    --export-snark <filename.json>    # Export a SNARK containing signature and proof data to a JSON file
```

## Files Written

| File             | Purpose                                                    | Created by                         |
|------------------|------------------------------------------------------------|------------------------------------|
| `xmss_key.bin`   | XMSS private key (seed) + parameters (`h`, `w`)            | First sign if no key present       |
| `xmss_state.dat` | Current XMSS leaf index (integer)                          | Updated on each sign               |
| `root.hex`       | Public root hash (hex string)                              | Saved on sign                      |
| `sig.bin`        | Last signature produced + parameters (`h`, `w`)            | Saved on sign                      |
| `bench.csv`      | Benchmark results log in CSV format                        | Benchmark mode (`-b`)              |
| `<filename>.json`| Exported SNARK signature and proof data in JSON format | Created when using `--export-snark` option |

---

## Further Optimisation Details:

Major features wre added to enhance the functionality and performence of the original codebase including, SNARK generation, runtime parameterization and Side-Channel Hardening. Here’s a brief overview of their implementation.

### SNARK Signiture Generation

This feature exports the XMSS signiture for validation in a single convenient JSON file, alloing for easy intergration of the XMSS Signiture with Zero Knowledge Proof Circuits as the file contains both the message, the hash and data required to derive a self contained proof.

The structure of the SNARK is comprised as per below:

```JSON
{
  "message": "74657374",
  "root": "2B142669EBAE3ED2524A262051A2F82B33FA8CB3117CB836394854D740CC32F8",
  "index": 0,
  "wots_signature": [
    "0074036CC8010000904C076CC80100004054036CC80100009055036CC8010000",
    "904C076CC8010000F064026CC801000000000000000000000000000000000000",
    "020000006F736F660100000000000000B0BF066CC80100000800000000000000",
    "010000006D342B81010000000000000008000000000000000300000000000000",
    "02000000D2EC3DC20100000000000000E0BA026CC80100004000000000000000",
    "D350C9CC8307EBD6184F9E5DF2479BC1CF37654F640054821339D820A1794AB9",
    "020000009416A87F0100000000000000F0C3026CC80100004000000000000000",
    "02000000EC9D27840100000000000000B0BD026CC80100004000000000000000"
  ],
  "auth_path": [
    "4669966D9E12B325123B611754F93EEAFFB2D72A5F995529197770F8EFE6E3F7",
    "EC08D2CDAE5F13FFFFD65C8ACB8AD7632E656F3CAFA69DD42A962E1413C9BC9E",
    "3F167AA04390CEC42F025F3112AE03CDB891E681EC0019AC3FA7C9E555614F76",
    "7AD8431774610606ED12A1CD8D483E15888E49F7C09779B33746CC6C031115DF",
    "00A30099ECA89B9A90EEC01C4EBC9B61B46A71AF96D529AAA515F5BB094CB7BF"
  ]
}
```

*   **message**: The original signed message as a hexadecimal string.

*   **root**: The XMSS public key root hash.

*   **index**: The XMSS leaf index used for the signature.

*   **wots_signature**: An array of WOTS+ signature chains (each hex-encoded).

*   **auth_path**: The Merkle authentication path corresponding to the leaf index.

### Runtime Parameterization (`h` and `w`)

The entire encryption circuit has been redesigned to allow the XMSS tree height (`h`) and WOTS+ parameter (`w`) to be set at runtime via command-line arguments, rather than being fixed at compile time. This drastically improves scalability and allows users to fine tune the parameters as required.

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

## Advanced Testing:

### Side-Channel Verification Program: time_test
A dedicated testing program was created to test amd demonstrates the effectiveness of side-channel hardening:

```bash
./time_test
```

A critical security feature of this implementation is its hardening against **timing attacks**. This is not something that can be observed through normal sign/verify operations. We have therefore created a dedicated `time_test` executable to prove its effectiveness.

#### The Vulnerability

A naive implementation of WOTS+ signing would take a variable amount of time, depending on the message being signed. Signing a message whose hash contains many small numbers would be much faster than signing one with many large numbers. An attacker could exploit this time difference to learn information about the message hash, breaking the signature scheme.

#### The Hardening

Our implementation uses a **constant-time** algorithm (`wots_chain_ct`). No matter what the message is, the signing function performs the exact same number of computationally expensive operations, and uses branchless, bitwise selections to pick the correct result. This eliminates the timing leak.

#### How to Test It

1.  **Build the test program**:
    ```bash
    cd tests
    make
    ```
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
The near-zero time difference for the **Hardened Function** is the experimental proof that the side-channel protection is working correctly. The hardened function shows almost no timing difference between easy and hard messages. The vulnerable function is significantly faster for the 'easy' message, leaking timing information. Side-channel hardening is working as expected.

### Automated Benchmarking Suite
An inbuilt benchmarking system was implemented to accurately measure the perfomance of the system. This benchmark evaluates the entire program stack and reports the time taken by each submodule (Key Generation, Encryption and Verification) as well as the time taken for entire system flow. The benchmarking script allows users to also manually specify the number of iterations to run for each submodule if so desired and will output the average of all the runs. By default the number of iterations run are 100, 1000 & 1000 respectively. The test data is then exported as a CSV file for easy aggregation, following the format shown below:

| timestamp   | h | w | keygen_runs | sign_runs | verify_runs | keygen_avg_s | sign_avg_s  | verify_avg_s | key_size_bytes | sig_size_bytes | root_size_bytes |
|-------------|---|---|-------------|-----------|-------------|--------------|-------------|--------------|----------------|-----------------|-----------------|
| 1754617748  | 5 | 8 | 1           | 1         | 1           | 0.026792800  | 0.024597800 | 0.000384600  | 64             | 3012            | 32              |

## Credits ヾ(≧▽≦*)o

- Achintha Namaratne | z5413821 | z5413821@ad.unsw.edu.au
- Sam Marinovich | z5480700 | z5363908@ad.unsw.edu.au
- Yifei Jia | z5665143 | z5363900@ad.unsw.edu.au
- Zihan Xu | z5489858 | z5361951@ad.unsw.edu.au
- Jinye Hu | z5513840 | z5359974@ad.unsw.edu.au
