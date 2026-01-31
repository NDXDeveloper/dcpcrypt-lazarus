# Contributing to DCPcrypt

Thank you for your interest in contributing to DCPcrypt. This document provides guidelines for contributing to the project.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Environment](#development-environment)
4. [Coding Standards](#coding-standards)
5. [Commit Conventions](#commit-conventions)
6. [Pull Request Process](#pull-request-process)
7. [Testing Requirements](#testing-requirements)
8. [Documentation](#documentation)

---

## Code of Conduct

- Be respectful and constructive in all interactions
- Focus on the technical merits of contributions
- Help newcomers learn and contribute effectively

---

## Getting Started

### Prerequisites

- **Free Pascal 3.2.0** or later
- **Lazarus 2.0** or later (optional, for IDE and GUI examples)
- **Git** for version control

No external libraries are required - DCPcrypt is a pure Pascal implementation.

### Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/dcpcrypt-lazarus.git
cd dcpcrypt-lazarus

# Add upstream remote
git remote add upstream https://github.com/ORIGINAL_OWNER/dcpcrypt-lazarus.git
```

### Build Verification

```bash
# Run all tests
make test

# Or manually
fpc -Mdelphi -FEtests -Fusrc -Fusrc/Ciphers -Fusrc/Hashes -Futests tests/test_hashes.lpr
tests/test_hashes
```

---

## Development Environment

### Recommended Setup

1. **Lazarus IDE** - For package management and GUI examples
2. **VS Code** or **Vim** - For lightweight editing with Pascal extensions
3. **Git** - Command line or GUI client

### Directory Structure

```
dcpcrypt-lazarus/
├── src/                    # Source code (modify here)
│   ├── Ciphers/            # 17 cipher implementations
│   ├── Hashes/             # 9 hash implementations
│   ├── dcpcrypt2.pas       # Base classes (TDCP_cipher, TDCP_hash)
│   ├── dcpblockciphers.pas # Block cipher modes (ECB, CBC, etc.)
│   ├── dcpbase64.pas       # Base64 encoding/decoding
│   └── dcpconst.pas        # Algorithm ID constants
├── tests/                  # Functional test suite (add tests here)
│   ├── testutils.pas       # Shared test utilities
│   └── test_*.lpr          # 5 test programs
├── examples/               # Working examples (update as needed)
│   ├── console/            # 2 console demos
│   └── gui/                # 2 GUI examples
└── docs/                   # Documentation
```

### Building Individual Components

```bash
# Build a specific test
fpc -Mdelphi -FEtests -Fusrc -Fusrc/Ciphers -Fusrc/Hashes -Futests tests/test_hashes.lpr

# Build a console example
fpc -Mdelphi -FEexamples/console -Fusrc -Fusrc/Ciphers -Fusrc/Hashes examples/console/demo_encrypt_string.lpr

# Build a GUI example
lazbuild examples/gui/EncryptStrings/EncryptStringsViaEncryptStream.lpi
```

---

## Coding Standards

### Pascal Style Guide

DCPcrypt uses **Delphi syntax mode** (`{$MODE Delphi}` or `-Mdelphi` flag).

#### Naming Conventions

| Element | Convention | Example |
|---------|------------|---------|
| Units | `DCP` prefix, lowercase | `dcprijndael.pas` |
| Cipher classes | `TDCP_` prefix | `TDCP_rijndael` |
| Hash classes | `TDCP_` prefix | `TDCP_sha256` |
| Methods | PascalCase | `EncryptString`, `SelfTest` |
| Properties | PascalCase | `MaxKeySize`, `BlockSize` |
| Private fields | `f` prefix | `fInitialized` |
| Constants | PascalCase | `DCPmaxRC2keysize` |

#### Code Formatting

```pascal
unit dcpexample;

{$MODE Delphi}

interface

uses
  Classes, SysUtils, DCPcrypt2;

type
  TDCP_example = class(TDCP_blockcipher128)
  private
    fKeyData: array[0..31] of byte;
  protected
    procedure InitKey(const Key; Size: longword); override;
  public
    class function GetId: integer; override;
    class function GetAlgorithm: string; override;
    class function GetMaxKeySize: integer; override;
    class function SelfTest: boolean; override;

    procedure Init(const Key; Size: longword; InitVector: pointer); override;
    procedure Burn; override;
    procedure EncryptECB(const InData; var OutData); override;
    procedure DecryptECB(const InData; var OutData); override;
  end;

implementation

class function TDCP_example.GetAlgorithm: string;
begin
  Result := 'Example';
end;

class function TDCP_example.GetMaxKeySize: integer;
begin
  Result := 256;
end;

// ...

end.
```

#### Formatting Rules

- **Indentation:** 2 spaces (no tabs)
- **Line length:** Maximum 100 characters
- **Braces:** `begin`/`end` on separate lines
- **Comments:** Use `//` for single-line, `{ }` for multi-line

#### Error Handling

```pascal
// Use try-finally for resource cleanup
Cipher := TDCP_rijndael.Create(nil);
try
  Cipher.InitStr(Password, TDCP_sha256);
  Cipher.EncryptStream(InStream, OutStream, InStream.Size);
  Cipher.Burn;
finally
  Cipher.Free;
end;
```

---

## Commit Conventions

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Formatting, no code change |
| `refactor` | Code restructuring |
| `perf` | Performance improvement |
| `test` | Adding or updating tests |
| `chore` | Maintenance tasks |

### Scopes

| Scope | Description |
|-------|-------------|
| `cipher` | Cipher implementations |
| `hash` | Hash implementations |
| `modes` | Block cipher modes (ECB, CBC, etc.) |
| `stream` | EncryptStream/DecryptStream |
| `base64` | Base64 encoding/decoding |
| `core` | Base classes (dcpcrypt2.pas) |
| `examples` | Example code |
| `tests` | Test suite |
| `docs` | Documentation |
| `ci` | CI/CD pipeline |

### Examples

```bash
# Feature
feat(cipher): add ChaCha20 stream cipher

# Bug fix
fix(modes): correct CTR counter overflow for large data

# Documentation
docs(api): add examples for PartialEncryptStream

# Tests
test(hash): add SHA-256 known-answer tests from NIST
```

### Commit Best Practices

- Keep commits focused and atomic
- Write clear, descriptive messages
- Reference issues when applicable: `Fixes #123`
- Avoid commits that break the build

---

## Pull Request Process

### Before Submitting

1. **Sync with upstream:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run all tests:**
   ```bash
   make test
   ```

3. **Build examples:**
   ```bash
   make clean-examples
   # Verify affected examples compile
   fpc -Mdelphi -FEexamples/console -Fusrc -Fusrc/Ciphers -Fusrc/Hashes examples/console/demo_encrypt_string.lpr
   ```

4. **Update documentation** if adding/changing public API

### PR Requirements

- [ ] Code compiles without warnings
- [ ] All 282 tests pass (`make test`)
- [ ] New features have tests
- [ ] Documentation updated for API changes
- [ ] Examples updated if applicable
- [ ] Commit messages follow conventions

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Existing tests pass
- [ ] New tests added for new features
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No warnings on compilation
```

### Review Process

1. Submit PR with clear description
2. CI pipeline runs automatically
3. Maintainer reviews code
4. Address feedback if any
5. Squash and merge when approved

---

## Testing Requirements

### Test Coverage

All new features must include tests:

| Feature Type | Required Tests |
|--------------|----------------|
| New cipher | SelfTest, encrypt/decrypt roundtrip, Burn, properties |
| New hash | SelfTest, digest correctness, determinism, Burn |
| New mode | Encrypt/decrypt roundtrip on both 64-bit and 128-bit block ciphers |
| Bug fix | Test that reproduces the bug |
| API change | Updated existing tests |

### Writing Tests

Tests go in `tests/` directory. Use the shared `testutils.pas` unit:

```pascal
uses
  testutils, DCPrijndael, DCPsha256, DCPcrypt2;

procedure TestNewFeature;
var
  Cipher: TDCP_rijndael;
begin
  Cipher := TDCP_rijndael.Create(nil);
  try
    Cipher.InitStr('test key', TDCP_sha256);

    Check('NewFeature works', Cipher.SomeMethod = ExpectedValue);

    Cipher.Burn;
  finally
    Cipher.Free;
  end;
end;
```

### Running Tests

```bash
# All tests
make test

# Full verification (clean + build + test)
make check
```

### CI Pipeline

The GitHub Actions CI runs:
1. Build all 5 test programs on Linux, Windows, macOS
2. Execute all 282 tests on all platforms
3. Build console and GUI examples on all platforms

All checks must pass before merge.

---

## Documentation

### When to Update Docs

- Adding new cipher or hash algorithm
- Adding new block cipher mode
- Changing method signatures
- Adding new example
- Fixing incorrect documentation

### Documentation Files

| File | Content |
|------|---------|
| `docs/README.md` | Full project documentation |
| `docs/Ciphers.md` | TDCP_cipher API reference |
| `docs/BlockCiphers.md` | TDCP_blockcipher API reference |
| `docs/Hashes.md` | TDCP_hash API reference |
| `docs/CHANGELOG.md` | Version history |
| `README.md` | Project overview |

### Documentation Style

- Use clear, concise language
- Include code examples for all public methods
- Document parameters and return values
- Note which cipher modes apply to which methods

---

## Questions?

- Open an issue for questions or discussion
- Tag maintainers for urgent matters
- Check existing issues before creating new ones

---

*Thank you for contributing to DCPcrypt!*
