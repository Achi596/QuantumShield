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
| Runtime Parameterization (`w`, `h`)       | ❌ Current build uses compile-time constants                                                |
| Side-channel Hardening                    | ❌ Not constant-time; no memory cleansing                                                   |


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
    ./hashsig -e "hello world"
    ```

## CLI Usage
```bash
hashsig [--seed N] -e "message"          # Sign: generate or load key, sign message, save state
hashsig [--seed N] -v "message"          # Verify: load root + signature, check vs message
hashsig [--seed N] -b [k s v]            # Benchmark: sign/verify loops (defaults 100 1000 1000)
```

## Arguments

| Option      | Meaning                                             | Notes                                                              |
|-------------|-----------------------------------------------------|--------------------------------------------------------------------|
| `--seed N`  | Use deterministic RNG seed for reproducible testing | Optional; accepts uint64_t decimal values.                         |
| `-e "msg"`  | Sign message string                                 | Creates/loads a key and advances XMSS index.                       |
| `-v "msg"`  | Verify signed message                               | Uses `root.hex` (root key in hex) and `sig.bin` (binary signature).|
| `-b [k s v]`| Benchmark operations: keygen, sign, verify runs     | Defaults to 100 keygen, 1000 sign, 1000 verify runs.               |

## Files Written

| File             | Purpose                            | Created by                   |
|------------------|------------------------------------|------------------------------|
| `xmss_key.bin`   | XMSS private key (raw struct dump) | First sign if no key present |
| `xmss_state.dat` | Current XMSS leaf index (int)      | Updated each sign            |
| `root.hex`       | Public root hash (hex)             | Saved on sign                |
| `sig.bin`        | Last signature produced            | Saved on sign                |
| `bench.csv`      | Benchmark results append log       | Benchmark mode               |


