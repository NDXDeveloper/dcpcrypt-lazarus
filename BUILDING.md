# Building DCPcrypt

This document describes how to build DCPcrypt from source on different platforms.

## Requirements

### Compiler

- **Free Pascal Compiler (FPC)** 3.2.0 or later
- **Lazarus IDE** 2.0 or later (optional, for GUI examples and package installation)

### No External Dependencies

DCPcrypt is a pure Pascal cryptographic library. It has no runtime dependencies on any external library - all algorithms are implemented in Pascal source code.

## Building

### Using Makefile (Linux/macOS/Windows with MSYS2)

Run `make help` to see all available targets:

```
BUILD:
  make build            - Compile all test programs
  make build-examples   - Compile all examples (console + GUI)
  make build-console    - Compile console examples
  make build-gui        - Compile GUI examples (requires lazbuild)
  make build-all        - Compile everything (tests + examples)
  make rebuild          - Clean and rebuild tests

TEST:
  make test             - Build and run all tests

VERIFY:
  make check            - Full verification (clean, build, test)
  make info             - Show project information

CLEANUP:
  make clean            - Remove compiled test binaries and objects
  make clean-examples   - Clean examples/ build artifacts
  make clean-all        - Clean tests, examples and source build artifacts
```

Common workflows:

```bash
# Quick build and test
make test

# Build all examples (console + GUI)
make build-examples

# Build everything (tests + examples)
make build-all

# Full verification before commit
make check

# Show project info
make info
```

### Using fpc (Command Line)

Build tests directly with the Free Pascal Compiler:

```bash
# Build a test program
fpc -Mdelphi -FEtests -Fusrc -Fusrc/Ciphers -Fusrc/Hashes -Futests tests/test_hashes.lpr

# Build a console example
fpc -Mdelphi -FEexamples/console -Fusrc -Fusrc/Ciphers -Fusrc/Hashes examples/console/demo_encrypt_string.lpr
```

**Important:** The `-Mdelphi` flag is required because `dcpbase64.pas` uses Delphi-style `Result` syntax without an explicit `{$MODE Delphi}` directive.

### Using Lazarus IDE

1. Open `src/dcpcrypt.lpk` (runtime package)
2. Click "Compile" to build the package
3. Open `src/dcpcrypt_laz.lpk` (design-time package)
4. Click "Use > Install" to install in the IDE
5. Cipher and hash components appear on the component palette

### Using lazbuild (Command Line)

```bash
# Build a GUI example
lazbuild examples/gui/EncryptStrings/EncryptStringsViaEncryptStream.lpi
lazbuild examples/gui/FileEncrypt/EncryptFileUsingThread.lpi
```

## Compiler Flags

| Flag | Purpose |
|------|---------|
| `-Mdelphi` | Required: Delphi compatibility mode |
| `-Fusrc` | Unit search path: core units |
| `-Fusrc/Ciphers` | Unit search path: cipher implementations |
| `-Fusrc/Hashes` | Unit search path: hash implementations |
| `-Futests` | Unit search path: shared test utilities |
| `-FE<dir>` | Output directory for compiled binaries |

## Platform-Specific Notes

### Linux (Debian/Ubuntu)

No additional dependencies for tests and console examples. For GUI examples:

```bash
# GUI dependencies (for LCL compilation)
sudo apt-get install libgtk2.0-0 libgtk2.0-dev
```

### Linux (Fedora/RHEL)

```bash
# GUI dependencies
sudo dnf install gtk2 gtk2-devel
```

### Linux (Arch)

```bash
# GUI dependencies
sudo pacman -S gtk2
```

### Windows

No additional dependencies. FPC produces `.exe` binaries automatically.

### macOS

No additional dependencies. LCL uses Cocoa backend.

## Running Tests

```bash
# Using Makefile
make test

# Or manually
fpc -Mdelphi -FEtests -Fusrc -Fusrc/Ciphers -Fusrc/Hashes -Futests tests/test_hashes.lpr
tests/test_hashes
```

The test suite contains 5 programs (282 individual checks):

| Program | Coverage |
|---------|----------|
| `test_hashes` | SelfTest, digest correctness, determinism, Burn for all 10 hashes |
| `test_ciphers` | SelfTest, encrypt/decrypt roundtrip, Burn, properties for all 20 ciphers |
| `test_block_modes` | ECB, CBC, CFB8bit, CFBblock, OFB, CTR for Rijndael and Blowfish |
| `test_base64` | Encode/decode roundtrips, RFC 4648 known values, binary data |
| `test_stream_encrypt` | Salt+IV stream encryption, PartialEncryptStream, OnProgressEvent |

## CI/CD

The project uses GitHub Actions for continuous integration. See `.github/workflows/ci.yml`.

Tests and examples build automatically on:
- Ubuntu (latest)
- Windows (latest)
- macOS (latest)

## Troubleshooting

### "Identifier not found: Result"

The `-Mdelphi` compiler flag is missing. Add it to your fpc command:
```bash
fpc -Mdelphi ...
```

### GUI examples fail to compile on Linux

Install GTK2 development packages:
```bash
sudo apt-get install libgtk2.0-dev
```

### "Unit not found: DCPrijndael"

The unit search paths are missing. Add all three source directories:
```bash
fpc -Fusrc -Fusrc/Ciphers -Fusrc/Hashes ...
```

### Gost SelfTest warning

The Gost cipher's built-in SelfTest returns False due to a known upstream test vector mismatch. Encrypt/decrypt roundtrips work correctly. This is reported as a warning (not a failure) in the test suite.
