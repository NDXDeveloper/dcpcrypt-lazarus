# Changelog

## v2.0.5 - Nicolas Deoux (2026)

NDXDev@gmail.com
https://www.linkedin.com/in/nicolas-deoux-ab295980/

- Version number bumped to 2.0.5
- Added GUI examples ported from Delphi VCL to Lazarus LCL:
  - `examples/gui/EncryptStrings`: String encryption/decryption using EncryptStream
  - `examples/gui/FileEncrypt`: File encryption/decryption with thread support
- Added console demo examples:
  - `examples/console/demo_encrypt_string.lpr`: Salt+IV string encryption
  - `examples/console/demo_file_encrypt.lpr`: File encryption with progress callback
- Added functional test suite (`tests/`, 282 tests, 5 programs):
  - `test_hashes`: 10 hash algorithms (SelfTest, digest, determinism, Burn)
  - `test_ciphers`: 20 cipher algorithms (SelfTest, roundtrip, Burn, properties)
  - `test_block_modes`: 6 modes (ECB, CBC, CFB8bit, CFBblock, OFB, CTR) on Rijndael and Blowfish
  - `test_base64`: Base64 encode/decode (RFC 4648, binary data, edge cases)
  - `test_stream_encrypt`: Stream encryption (Salt+IV, PartialEncryptStream, OnProgressEvent)
  - Shared unit `testutils.pas` (Check, CheckEquals, TestSummary)
- Added `Makefile` at project root (`make test`, `make build-examples`, `make build-all`, `make check`, `make clean`, `make info`)
- Added GitHub Actions CI/CD pipeline (`.github/workflows/ci.yml`):
  - Build and test on Linux, Windows and macOS
  - Build console and GUI examples on all platforms
  - Automatic GitHub release on version tags
- Added project root documentation (`README.md`, `BUILDING.md`, `CONTRIBUTING.md`, `TOC.md`)
- VCL to LCL adaptations:
  - Replaced Windows-specific units (Windows, Messages, SHFolder, ShellAPI, System.IOUtils) with cross-platform equivalents
  - Replaced Vcl.ComCtrls/ExtCtrls/ImgList with ComCtrls/ExtCtrls
  - Replaced TSpeedButton with TButton
  - Replaced TEncoding.Unicode (Delphi) with UTF-8 byte-level hex conversion
  - Replaced TPath.HasValidFileNameChars with manual filename validation
  - Replaced Windows drag-drop (WM_DROPFILES) with LCL AllowDropFiles/OnDropFiles
  - Replaced Thread.Resume with Thread.Start
  - Removed Application.OnMessage (Windows-specific)
  - Crypto components created in code (no design-time package required)

## v2.0.4.2 - Werner Pamler (2022)

- Version number bumped to 2.0.4.2
- Fix hashes for files >4 GB (issue #31934)

## v2.0.4.1 - Graeme Geldenhuys (2010)

- Version number bumped to v2.0.4.1
- More fixes for 64-bit support
- Removed a lot of compiler warnings - tested with FPC 2.4.1

## v2.0.4 - Graeme Geldenhuys (2009)

- Version number bumped to v2.0.4
- Split the Lazarus package into two separate packages
  - One is runtime only package and GUI toolkit independent.
  - One is Lazarus design-time only package which installs components in component palette.
- Updated code to be compilable with FPC 2.4.0-rc1
- Updated code to be compilable with 64-bit FPC 2.4.0-rc1
  - Tested under 32-bit & 64-bit Linux on x86 systems.

## DCPCrypt v2 Beta 3 to Lazarus

- Ported DCPCrypt to Lazarus by Barko in 2006
