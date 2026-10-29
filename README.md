# 🔐 Hybrid Crypto (Rust)

A modular hybrid encryption system implemented in Rust (2024 edition). It combines the flexibility of asymmetric elliptic curve key exchange (**X25519**) with the high performance and security of authenticated symmetric encryption (**AES-256-GCM**), integrating secure private key storage via the operating system's native credential manager (**Keyring / Keychain**).

---

## 📋 Table of Contents

- [Key Features](#-key-features)
- [Cryptographic Architecture](#-cryptographic-architecture)
  - [Digital Envelope Layout (`envelope.bin`)](#-digital-envelope-layout-envelopebin)
  - [Encryption and Decryption Workflow](#-encryption-and-decryption-workflow)
- [Project Structure](#-project-structure)
- [Prerequisites](#-prerequisites)
- [Usage Guide](#-usage-guide)
  - [1. Secure Flow with OS Keyring (Recommended)](#1-secure-flow-with-os-keyring-recommended)
  - [2. Basic File-Based Flow](#2-basic-file-based-flow)
  - [3. Cleaning Credentials and Artifacts](#3-cleaning-credentials-and-artifacts)
- [Security Considerations](#-security-considerations)
- [Dependencies](#-dependencies)
- [License](#-license)

---

## ✨ Key Features

- **Modern Hybrid Encryption**: Employs Diffie-Hellman over Curve25519 (X25519) to agree on a shared secret, and AES-256-GCM for high-speed symmetric data encryption.
- **Ephemeral Key Pairs (Sender PFS)**: The sender generates a fresh ephemeral key pair for each message, ensuring the shared secret and AES key are unique per envelope.
- **Authenticated Encryption (AEAD)**: AES-256-GCM guarantees both confidentiality and ciphertext integrity; any tampering with the envelope header, nonce, or payload is detected immediately.
- **Secure Key Storage**: Out-of-the-box support for persisting private keys inside the native OS credential manager (Linux Secret Service / GNOME Keyring / KWallet, macOS Keychain, and Windows Credential Manager).
- **Self-Contained Digital Envelope**: All metadata necessary for decryption (except the recipient's private key) is packaged into a single compact binary format.

---

## 🧠 Cryptographic Architecture

### Digital Envelope Layout (`envelope.bin`)

The digital envelope packs all necessary components contiguously to allow the recipient to reconstruct the shared secret and decrypt the payload:

```text
+-----------------------------+--------------------+---------------------------------------+
| Sender Ephemeral Public Key | Nonce (IV)         | Ciphertext + Authentication Tag       |
| 32 bytes                    | 12 bytes           | N bytes                               |
| (X25519 Public Key)         | (AES-GCM Nonce)    | (AES-256-GCM Ciphertext + 16-byte MAC)|
+-----------------------------+--------------------+---------------------------------------+
0                             32                   44                                    44 + N
```

### Encryption and Decryption Workflow

```text
[Sender]                                                  [Recipient]
    |                                                           |
    |-- 1. Generate ephemeral pair (sk_e, pk_e)                 |
    |-- 2. Diffie-Hellman(sk_e, pk_recipient)                   |
    |      => shared_secret (32 bytes)                          |
    |-- 3. Derive AES-256 key from shared secret                |
    |-- 4. Generate random Nonce (12 bytes via OsRng)           |
    |-- 5. Encrypt: AES-256-GCM(shared_key, nonce, plaintext)   |
    |-- 6. Pack [pk_e (32B) + nonce (12B) + ciphertext]         |
    |                                                           |
    |==================== Digital Envelope ====================>|
    |                                                           |
    |                                  7. Extract pk_e & nonce -|
    |                                  8. Retrieve sk_recipient |
    |                                     (from Keyring or disk)|
    |                                  9. Diffie-Hellman(sk_rec,|
    |                                     pk_e) => shared_secret|
    |                                 10. Decrypt & verify tag  |
    |                                     via AES-256-GCM       |
    v                                                           v
```

---

## 📁 Project Structure

```text
hybrid_crypto/
├── Cargo.toml            # Package configuration and dependencies
├── .gitignore            # Excludes build binaries and artifact files (*.bin)
├── README.md             # Project documentation
└── src/
    ├── main.rs           # Base implementation storing keys on disk
    └── bin/
        ├── keychain.rs   # Production-ready implementation with OS Keyring
        └── cleankey.rs   # Maintenance utility to revoke keys and clean files
```

- **`src/main.rs`** (`hybrid_crypto`): Educational / testing implementation where `public_key.bin` and `private_key.bin` are stored directly on the local filesystem.
- **`src/bin/keychain.rs`** (`keychain`): Production-grade variant that safeguards the recipient's private key inside the operating system's credential store under service `hybrid_crypto_rust` and user `recipient_private_key`.
- **`src/bin/cleankey.rs`** (`cleankey`): Utility to remove credentials stored in the OS Keyring and clean up generated `public_key.bin` and `envelope.bin` files.

---

## 🛠 Prerequisites

1. **Rust and Cargo**: A modern Rust toolchain (2024 edition compatible).
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
2. **System Dependencies for Keyring (Linux headless / minimal installations)**:
   The `keyring` crate uses D-Bus and the Secret Service API on Linux (GNOME Keyring, KWallet). If you are running on a minimal or headless environment, ensure `pkg-config` and `libdbus-1-dev` are installed:
   ```bash
   sudo apt update && sudo apt install -y libdbus-1-dev pkg-config
   ```

---

## 🚀 Usage Guide

### 1. Secure Flow with OS Keyring (Recommended)

Run the `keychain` binary:

```bash
cargo run --bin keychain
```

**Lifecycle:**
1. Checks for an existing private key in the OS Keyring and the public key in `public_key.bin`.
2. If absent, generates a new X25519 key pair, securely saves the private key into the OS credential store, and writes `public_key.bin`.
3. Encrypts a demonstration message into `envelope.bin`.
4. Reads the digital envelope, retrieves the private key from the OS Keyring, and decrypts the message.

---

### 2. Basic File-Based Flow

For quick local experiments where keys are stored as raw binary files on disk:

```bash
cargo run --bin hybrid_crypto
# or simply:
cargo run
```

**Generated files:**
- `private_key.bin`: Raw X25519 private key (32 bytes).
- `public_key.bin`: Raw X25519 public key (32 bytes).
- `envelope.bin`: Encrypted digital envelope.

---

### 3. Cleaning Credentials and Artifacts

To reset your environment, revoke the private key from the OS Keyring, and remove any leftover `.bin` files:

```bash
cargo run --bin cleankey
```

Expected output:
```text
[-] Llave privada eliminada exitosamente del Keyring del S.O.
[-] Archivo 'public_key.bin' eliminado localmente.
[-] Archivo 'envelope.bin' de prueba eliminado.
```

---

## 🔒 Security Considerations

- **Private Key Protection**: Storing raw private keys on disk (`private_key.bin`) poses significant risks from accidental exposure and unauthorized process access. The `keychain.rs` implementation delegates private key storage to the OS-level credential vault.
- **Git Hygiene**: Generated `.bin` files are explicitly included in `.gitignore` to prevent committing cryptographic secrets or test envelopes.
- **Cryptographically Secure Entropy**: All key material and initialization nonces are generated using `rand::rngs::OsRng`, sourcing hardware entropy directly from the OS kernel (`/dev/urandom` / `getrandom`).
- **Integrity and Authenticity**: Using AES-256-GCM authenticated encryption guarantees that tampering with any portion of the envelope (including the ephemeral public key or nonce) will cause decryption to fail immediately, preventing chosen-ciphertext attacks.

---

## 📦 Dependencies

| Crate | Version | Purpose |
|---|---|---|
| [`x25519-dalek`](https://crates.io/crates/x25519-dalek) | `2.0` | Diffie-Hellman key exchange over Curve25519 |
| [`aes-gcm`](https://crates.io/crates/aes-gcm) | `0.10` | Authenticated symmetric encryption (AES-256-GCM) |
| [`rand`](https://crates.io/crates/rand) | `0.8` | Cryptographically secure random number generator (`OsRng`) |
| [`keyring`](https://crates.io/crates/keyring) | `2.0` | Cross-platform integration with OS credential storage |
| [`hex`](https://crates.io/crates/hex) | `0.4` | Hexadecimal encoding/decoding for Keyring storage |
| [`serde`](https://crates.io/crates/serde) / [`serde_json`](https://crates.io/crates/serde_json) | `1.0` | Serialization and data handling |

---

## 📄 License

This project is open-source and available under the MIT or Apache-2.0 license.
