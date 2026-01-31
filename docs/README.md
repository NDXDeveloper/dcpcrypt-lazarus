# DCPcrypt Cryptographic Component Library v2.0.5

**Lazarus / Free Pascal edition**
Originally written by David Barton

## Introduction

DCPcrypt is a collection of cryptographic components originally written for Borland Delphi by David Barton, ported to Lazarus/Free Pascal and maintained by multiple contributors.

The idea behind DCPcrypt is that it should be possible to "drop in" any algorithm implementation to replace another with minimum or no code changes. To aid in this goal all cryptographic components are descended from one of several base classes, `TDCP_cipher` for encryption algorithms and `TDCP_hash` for message digest algorithms.

DCPcrypt is open source software released under the [MIT license](../src/Docs/MIT_license.txt). There is no charge for inclusion in other software.

This software is OSI Certified Open Source Software. OSI Certified is a certification mark of the [Open Source Initiative](http://www.opensource.org/).

## What's New

**Changes in v2.0.5** by Nicolas Deoux (2026):

- Added GUI examples ported from Delphi VCL to Lazarus LCL:
  - EncryptStrings - String encryption/decryption using EncryptStream
  - FileEncrypt - File encryption/decryption with thread support
- Added functional test suite (282 tests) with Makefile
- Added GitHub Actions CI/CD pipeline (Linux, Windows, macOS)
- Added console demo examples (string and file encryption)

**Changes in v2.0.4.2** by Werner Pamler (2022):

- Fix hashes for files >4 GB (issue #31934)

**Changes in v2.0.4.1** by Graeme Geldenhuys (2010):

- More fixes for 64-bit support
- Removed a lot of compiler warnings - tested with FPC 2.4.1

**Changes in v2.0.4** by Graeme Geldenhuys (2009):

- Split the Lazarus package into two separate packages (runtime and design-time)
- Updated code to be compilable with FPC 2.4.0-rc1
- Updated code to be compilable with 64-bit FPC 2.4.0-rc1

Ported to Lazarus by Barko in 2006.

## Installation

| | |
|---|---|
| **Option 1 - Packages** | Open `src/dcpcrypt.lpk` (runtime) and `src/dcpcrypt_laz.lpk` (design-time) in the Lazarus IDE and install them. Cipher and hash components will appear on the component palette. |
| **Option 2 - Direct use** | Add `src/`, `src/Ciphers/` and `src/Hashes/` to your project unit search paths. Create cipher and hash instances in code. See the GUI examples. |

## Examples

| | |
|---|---|
| **Console examples** | `examples/console/` - String and file encryption tests |
| **GUI examples** | `examples/gui/EncryptStrings/` - String encryption with EncryptStream |
| | `examples/gui/FileEncrypt/` - File encryption with thread support |
| | Build with: `lazbuild <project>.lpi` |

## Testing

A functional test suite is provided in `tests/`. It requires only Free Pascal (`fpc`) and no IDE.

```
make test             # build and run all tests
make build-examples   # compile all examples (console + GUI)
make build-all        # compile everything (tests + examples)
make check            # clean, build and run (full verification)
make clean            # remove compiled binaries and objects
make info             # show project information
```

The suite contains 5 test programs (282 individual checks):

| Program | Coverage |
|---------|----------|
| `test_hashes` | SelfTest, digest correctness, determinism, Burn for all 10 hashes |
| `test_ciphers` | SelfTest, encrypt/decrypt roundtrip, Burn, properties for all 20 ciphers |
| `test_block_modes` | ECB, CBC, CFB8bit, CFBblock, OFB, CTR for Rijndael (128-bit) and Blowfish (64-bit) |
| `test_base64` | Encode/decode roundtrips, RFC 4648 known values, binary data |
| `test_stream_encrypt` | Salt+IV stream encryption, empty/long strings, PartialEncryptStream, OnProgressEvent |

## CI/CD

A GitHub Actions pipeline is provided in `.github/workflows/ci.yml`. It runs automatically on push and pull requests.

| Stage | Platforms | Purpose |
|-------|-----------|---------|
| `build-and-test` | Linux, Windows, macOS | Compile and run all 282 tests |
| `build-examples` | Linux, Windows, macOS | Verify console and GUI examples compile |
| `release` | Linux | Create GitHub release (on `v*` tags only) |

See [.github/workflows/README.md](../.github/workflows/README.md) for details.

## Usage

Please note that an appreciation of the basic principles of encryption/decryption and key management is needed to ensure the correct usage of the ciphers implemented within this package. A good introduction on this subject is provided by Bruce Schneier's "Applied Cryptography" (ISBN: 0-471-11709-9) also see the NIST publication SP800-38A for information on the block cipher chaining modes.

- [Ciphers](Ciphers.md) - the basic building block of DCPcrypt, the TDCP_cipher component.
- [Block Ciphers](BlockCiphers.md) - the base of all block ciphers, the TDCP_blockcipher component.
- [Hashes](Hashes.md) - the base of all hash algorithms, the TDCP_hash component.

DCPcrypt contains the following ciphers and hash algorithms:

### Ciphers

| Name | Patents | Block Size | Max Key Size\* |
|------|---------|-----------|---------------|
| Blowfish | None | 64 bits | 448 bits |
| Cast128 | None | 64 bits | 128 bits |
| Cast256 | Patented? | 128 bits | 256 bits |
| DES | None | 64 bits | 64 bits\*\* |
| 3DES | None | 64 bits | 192 bits |
| Ice | None? | 64 bits | 64 bits |
| Thin Ice | None? | 64 bits | 64 bits |
| Ice2 | None? | 64 bits | 128 bits |
| Gost | None | 64 bits | 256 bits |
| IDEA | Free for non-commercial use | 64 bits | 128 bits |
| MARS | Patented? | 128 bits | 1248 bits |
| Misty1 | Free for non-commercial use | 64 bits | 128 bits |
| RC2 | None | 64 bits | 1024 bits |
| RC4 | None | N/A | 2048 bits |
| RC5 | Patented | 64 bits | 2048 bits |
| RC6 | Patented | 128 bits | 2048 bits |
| Rijndael (AES) | None | 128 bits | 256 bits |
| Serpent | None | 128 bits | 256 bits |
| TEA | None | 64 bits | 128 bits |
| Twofish | None | 128 bits | 256 bits |

\* Although the quoted maximum key size may be extremely large it doesn't mean that the algorithm is secure to the same level.

\*\* A 64bit key is used for DES then every 8th bit is discarded (parity) so the effective size is 56 bits.

### Hash Algorithms

| Name | Patents | Digest Size |
|------|---------|-------------|
| Haval | None | 128, 160, 192, 224, 256 bits\* |
| MD4 | None | 128 bits |
| MD5 | None | 128 bits |
| RipeMD-128 | None | 128 bits |
| RipeMD-160 | None | 160 bits |
| SHA1 | None | 160 bits |
| SHA256 | None | 256 bits |
| SHA384 | None | 384 bits |
| SHA512 | None | 512 bits |
| Tiger | None | 192 bits |

\* The different digest sizes of Haval can be accessed by uncommenting the `$defines` at the start of `DCPhaval.pas`.

## See Also

- [Project README](../README.md) - Project overview and quick start
- [Building from Source](../BUILDING.md) - Compilation instructions
- [Contributing](../CONTRIBUTING.md) - Contribution guidelines
- [Table of Contents](../TOC.md) - Full documentation index
- [CI/CD Pipeline](../.github/workflows/README.md) - GitHub Actions workflow

## Contributors

| Name | Contribution |
|------|-------------|
| David Barton | Original DCPcrypt author (1999-2003) |
| Barko | Lazarus port (2006) |
| Graeme Geldenhuys | Package split, 64-bit support (2009-2010) |
| Werner Pamler | Large file hash fix (2022) |
| Nicolas Deoux | GUI examples VCL→LCL port, console demos, test suite, Makefile, docs (2026) - NDXDev@gmail.com |

---

*DCPcrypt is copyrighted by its respective authors.*
*Released under the MIT license. All trademarks are property of their respective owners.*
