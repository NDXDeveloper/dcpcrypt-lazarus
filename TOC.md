# DCPcrypt Documentation

**Version 2.0.5** | **License:** MIT

---

## Table of Contents

### Getting Started

- [README](README.md) - Project overview and quick start
- [Full Documentation](docs/README.md) - Detailed project documentation
- [Building from Source](BUILDING.md) - Compilation instructions
- [Contributing](CONTRIBUTING.md) - Contribution guidelines

### API Reference

- [Ciphers](docs/Ciphers.md) - TDCP_cipher base class reference
  - Init, InitStr, Burn, Reset
  - Encrypt, Decrypt
  - EncryptStream, DecryptStream
  - PartialEncryptStream, PartialDecryptStream
  - EncryptString, DecryptString
  - OnProgressEvent, CancelByCallingThread
- [Block Ciphers](docs/BlockCiphers.md) - TDCP_blockcipher reference
  - CipherMode, BlockSize
  - SetIV, GetIV
  - EncryptECB, DecryptECB
  - EncryptCBC, DecryptCBC
  - EncryptCFB8bit, DecryptCFB8bit
  - EncryptCFBblock, DecryptCFBblock
  - EncryptOFB, DecryptOFB
  - EncryptCTR, DecryptCTR
- [Hashes](docs/Hashes.md) - TDCP_hash base class reference
  - Init, Final, Burn
  - Update, UpdateStream, UpdateStr
  - HashSize, SelfTest

### Version History

- [Changelog](docs/CHANGELOG.md) - All versions from v2.0.4 to v2.0.5

### CI/CD

- [CI/CD Pipeline](.github/workflows/README.md) - GitHub Actions workflow documentation

### Examples

4 examples covering common encryption scenarios:

| Example | Type | Description |
|---------|------|-------------|
| [demo_encrypt_string](examples/console/demo_encrypt_string.lpr) | Console | Salt+IV string encryption/decryption |
| [demo_file_encrypt](examples/console/demo_file_encrypt.lpr) | Console | File encryption with progress callback |
| [EncryptStrings](examples/gui/EncryptStrings/) | GUI (LCL) | String encryption using EncryptStream |
| [FileEncrypt](examples/gui/FileEncrypt/) | GUI (LCL) | File encryption with thread support |

### Algorithms

#### 20 Ciphers

| Cipher | Unit | Block Size | Max Key Size |
|--------|------|-----------|--------------|
| Blowfish | `dcpblowfish.pas` | 64 bits | 448 bits |
| Cast128 | `dcpcast128.pas` | 64 bits | 128 bits |
| Cast256 | `dcpcast256.pas` | 128 bits | 256 bits |
| DES | `dcpdes.pas` | 64 bits | 64 bits |
| 3DES | `dcpdes.pas` | 64 bits | 192 bits |
| Ice | `dcpice.pas` | 64 bits | 64 bits |
| Thin Ice | `dcpice.pas` | 64 bits | 64 bits |
| Ice2 | `dcpice.pas` | 64 bits | 128 bits |
| Gost | `dcpgost.pas` | 64 bits | 256 bits |
| IDEA | `dcpidea.pas` | 64 bits | 128 bits |
| MARS | `dcpmars.pas` | 128 bits | 1248 bits |
| Misty1 | `dcpmisty1.pas` | 64 bits | 128 bits |
| RC2 | `dcprc2.pas` | 64 bits | 1024 bits |
| RC4 | `dcprc4.pas` | N/A (stream) | 2048 bits |
| RC5 | `dcprc5.pas` | 64 bits | 2048 bits |
| RC6 | `dcprc6.pas` | 128 bits | 2048 bits |
| Rijndael (AES) | `dcprijndael.pas` | 128 bits | 256 bits |
| Serpent | `dcpserpent.pas` | 128 bits | 256 bits |
| TEA | `dcptea.pas` | 64 bits | 128 bits |
| Twofish | `dcptwofish.pas` | 128 bits | 256 bits |

#### 10 Hashes

| Hash | Unit | Digest Size |
|------|------|-------------|
| Haval | `dcphaval.pas` | 128-256 bits |
| MD4 | `dcpmd4.pas` | 128 bits |
| MD5 | `dcpmd5.pas` | 128 bits |
| RipeMD-128 | `dcpripemd128.pas` | 128 bits |
| RipeMD-160 | `dcpripemd160.pas` | 160 bits |
| SHA-1 | `dcpsha1.pas` | 160 bits |
| SHA-256 | `dcpsha256.pas` | 256 bits |
| SHA-384 | `dcpsha512.pas` | 384 bits |
| SHA-512 | `dcpsha512.pas` | 512 bits |
| Tiger | `dcptiger.pas` | 192 bits |

### Test Suite

| Program | Tests | Coverage |
|---------|-------|----------|
| `test_hashes` | 90 | SelfTest, digest correctness, determinism, Burn |
| `test_ciphers` | 139 | SelfTest, encrypt/decrypt roundtrip, Burn, properties |
| `test_block_modes` | 28 | ECB, CBC, CFB8bit, CFBblock, OFB, CTR |
| `test_base64` | 11 | RFC 4648, binary data, edge cases |
| `test_stream_encrypt` | 14 | Salt+IV, PartialEncryptStream, OnProgressEvent |

**Total: 282 tests**

---

## Project Structure

```
dcpcrypt-lazarus/
├── src/
│   ├── Ciphers/            # 17 cipher units (20 algorithms)
│   ├── Hashes/             # 9 hash units (10 algorithms)
│   ├── Docs/               # Original HTML docs and license
│   ├── dcpcrypt2.pas       # Base classes
│   ├── dcpblockciphers.pas # Block cipher modes
│   ├── dcpbase64.pas       # Base64 encoding/decoding
│   ├── dcpconst.pas        # Algorithm ID constants
│   ├── dcpcrypt.lpk        # Runtime package
│   └── dcpcrypt_laz.lpk    # Design-time package
├── tests/                  # Functional test suite
├── examples/               # Console and GUI examples
├── docs/                   # Markdown documentation
├── .github/workflows/      # CI/CD configuration
├── Makefile                # Build, test, clean targets
├── BUILDING.md             # Build instructions
├── CONTRIBUTING.md         # Contribution guidelines
└── TOC.md                  # This file
```

---

*For support or to report issues, visit the project repository.*
