# DCPcrypt

**Cryptographic Component Library for Free Pascal/Lazarus**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](src/Docs/MIT_license.txt)
[![Free Pascal](https://img.shields.io/badge/Free%20Pascal-3.2%2B-orange.svg)](https://www.freepascal.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()

---

## Overview

DCPcrypt is a collection of cryptographic components originally written for Borland Delphi by David Barton, ported to Lazarus/Free Pascal and maintained by multiple contributors.

The idea behind DCPcrypt is that it should be possible to "drop in" any algorithm implementation to replace another with minimum or no code changes. All cryptographic components are descended from one of several base classes: `TDCP_cipher` for encryption algorithms and `TDCP_hash` for message digest algorithms.

### Key Features

- **20 Cipher Algorithms** - Rijndael (AES), Blowfish, Twofish, Serpent, DES, 3DES, RC4, and more
- **10 Hash Algorithms** - SHA-1, SHA-256, SHA-384, SHA-512, MD5, RipeMD-160, Tiger, and more
- **6 Block Cipher Modes** - ECB, CBC, CFB8bit, CFBblock, OFB, CTR
- **Stream Encryption** - Salt+IV EncryptStream/DecryptStream with progress callbacks
- **Base64** - Encoding and decoding
- **Cross-Platform** - Linux, Windows, and macOS support
- **No External Dependencies** - Pure Pascal implementation

---

## Quick Start

### Installation

**Option 1 - Packages (IDE)**

Open `src/dcpcrypt.lpk` (runtime) and `src/dcpcrypt_laz.lpk` (design-time) in the Lazarus IDE. Cipher and hash components will appear on the component palette.

**Option 2 - Direct use (no IDE)**

Add the source paths to your project:
```
-Mdelphi -Fupath/to/dcpcrypt-lazarus/src -Fupath/to/dcpcrypt-lazarus/src/Ciphers -Fupath/to/dcpcrypt-lazarus/src/Hashes
```

### Basic Usage

```pascal
program QuickDemo;

{$mode Delphi}

uses
  DCPrijndael, DCPsha256, DCPcrypt2;

var
  Cipher: TDCP_rijndael;
  Encrypted, Decrypted: string;
begin
  Cipher := TDCP_rijndael.Create(nil);
  try
    // Initialize with a passphrase (hashed with SHA-256)
    Cipher.InitStr('my secret passphrase', TDCP_sha256);

    // Encrypt a string (result is Base64-encoded)
    Encrypted := Cipher.EncryptString('Hello World');
    WriteLn('Encrypted: ', Encrypted);

    // Decrypt
    Cipher.Reset;
    Decrypted := Cipher.DecryptString(Encrypted);
    WriteLn('Decrypted: ', Decrypted);

    Cipher.Burn;
  finally
    Cipher.Free;
  end;
end.
```

Compile with:
```bash
fpc -Mdelphi -Fusrc -Fusrc/Ciphers -Fusrc/Hashes quickdemo.lpr
```

---

## Algorithms

### Ciphers

| Name | Block Size | Max Key Size |
|------|-----------|--------------|
| Rijndael (AES) | 128 bits | 256 bits |
| Blowfish | 64 bits | 448 bits |
| Twofish | 128 bits | 256 bits |
| Serpent | 128 bits | 256 bits |
| Cast128 | 64 bits | 128 bits |
| Cast256 | 128 bits | 256 bits |
| DES | 64 bits | 64 bits |
| 3DES | 64 bits | 192 bits |
| RC2 | 64 bits | 1024 bits |
| RC4 | N/A (stream) | 2048 bits |
| RC5 | 64 bits | 2048 bits |
| RC6 | 128 bits | 2048 bits |
| MARS | 128 bits | 1248 bits |
| IDEA | 64 bits | 128 bits |
| Misty1 | 64 bits | 128 bits |
| Ice / Thin Ice / Ice2 | 64 bits | 64-128 bits |
| Gost | 64 bits | 256 bits |
| TEA | 64 bits | 128 bits |

### Hash Algorithms

| Name | Digest Size |
|------|-------------|
| SHA-1 | 160 bits |
| SHA-256 | 256 bits |
| SHA-384 | 384 bits |
| SHA-512 | 512 bits |
| MD4 | 128 bits |
| MD5 | 128 bits |
| RipeMD-128 | 128 bits |
| RipeMD-160 | 160 bits |
| Haval | 128-256 bits |
| Tiger | 192 bits |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Full Documentation](docs/README.md) | Detailed project documentation |
| [Ciphers API](docs/Ciphers.md) | TDCP_cipher reference |
| [Block Ciphers API](docs/BlockCiphers.md) | TDCP_blockcipher reference |
| [Hashes API](docs/Hashes.md) | TDCP_hash reference |
| [Changelog](docs/CHANGELOG.md) | Version history |
| [Building](BUILDING.md) | Compilation instructions |
| [Table of Contents](TOC.md) | Full documentation index |

---

## Examples

### Console

| Example | Description |
|---------|-------------|
| `demo_encrypt_string` | Salt+IV string encryption/decryption |
| `demo_file_encrypt` | File encryption with progress callback |

```bash
cd examples/console
fpc -Mdelphi -Fusrc -Fusrc/Ciphers -Fusrc/Hashes demo_encrypt_string.lpr
./demo_encrypt_string
```

### GUI (Lazarus LCL)

| Example | Description |
|---------|-------------|
| `EncryptStrings` | String encryption/decryption using EncryptStream |
| `FileEncrypt` | File encryption/decryption with thread support |

```bash
lazbuild examples/gui/EncryptStrings/EncryptStringsViaEncryptStream.lpi
```

---

## Testing

A functional test suite (282 tests) is provided in `tests/`. It requires only `fpc` and no IDE.

```bash
make test             # build and run all tests
make build-examples   # compile all examples (console + GUI)
make build-all        # compile everything (tests + examples)
make check            # clean, build and run (full verification)
```

| Program | Tests | Coverage |
|---------|-------|----------|
| `test_hashes` | 90 | SelfTest, digest, determinism, Burn for 10 hashes |
| `test_ciphers` | 139 | SelfTest, roundtrip, Burn, properties for 20 ciphers |
| `test_block_modes` | 28 | ECB, CBC, CFB8bit, CFBblock, OFB, CTR |
| `test_base64` | 11 | RFC 4648, binary data, edge cases |
| `test_stream_encrypt` | 14 | Salt+IV, PartialEncryptStream, OnProgressEvent |

---

## Requirements

- **Compiler:** Free Pascal 3.2.0 or later
- **IDE:** Lazarus 2.0+ (optional, for GUI examples and packages)
- **Dependencies:** None (pure Pascal)

---

## Project Structure

```
dcpcrypt-lazarus/
├── src/                    # Source code
│   ├── Ciphers/            # 17 cipher units
│   ├── Hashes/             # 9 hash units
│   ├── Docs/               # Original HTML docs and license
│   ├── dcpcrypt2.pas       # Base classes (TDCP_cipher, TDCP_hash)
│   ├── dcpblockciphers.pas # Block cipher modes
│   ├── dcpbase64.pas       # Base64 encoding/decoding
│   ├── dcpcrypt.lpk        # Runtime package
│   └── dcpcrypt_laz.lpk    # Design-time package
├── tests/                  # Functional test suite (282 tests)
├── examples/               # Console and GUI examples
│   ├── console/            # 2 console demos
│   └── gui/                # 2 GUI examples (LCL)
├── docs/                   # Markdown documentation
├── .github/workflows/      # CI/CD configuration
└── Makefile                # Build, test, clean targets
```

---

## Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| Linux | x86_64, aarch64 | Supported |
| Windows | x86, x64 | Supported |
| macOS | Intel, Apple Silicon | Supported |
| Linux Snap | x86_64 | Supported |
| Linux Flatpak | x86_64 | Supported |

---

## Contributing

Contributions are welcome. Please ensure:

1. Code compiles without warnings
2. All 282 tests pass (`make test`)
3. Examples compile correctly
4. Documentation is updated

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## License

MIT License - See [LICENSE](src/Docs/MIT_license.txt) for details.

---

## Contributors

| Name | Contribution |
|------|-------------|
| David Barton | Original DCPcrypt author (1999-2003) |
| Barko | Lazarus port (2006) |
| Graeme Geldenhuys | Package split, 64-bit support (2009-2010) |
| Werner Pamler | Large file hash fix (2022) |
| Nicolas Deoux | GUI examples VCL-to-LCL port, console demos, test suite, Makefile, CI/CD, docs (2026) |

---

## Author (v2.0.5)

**Nicolas DEOUX**

- [NDXDev@gmail.com](mailto:NDXDev@gmail.com)
- [LinkedIn](https://www.linkedin.com/in/nicolas-deoux-ab295980/)
- [GitHub](https://github.com/NDXDeveloper)

---

*DCPcrypt is copyrighted by its respective authors.*
*Released under the MIT license. All trademarks are property of their respective owners.*
