     =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
     =   DCPcrypt Cryptographic Component Library v2.0.6      =
     =          Lazarus / Free Pascal edition                 =
     =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


Introduction:

DCPcrypt is a collection of cryptographic components originally written
by David Barton for Borland Delphi. This is the Lazarus/Free Pascal
port, maintained and extended by multiple contributors.

The idea behind DCPcrypt is that it should be possible to "drop in"
any algorithm implementation to replace another with minimum or no
code changes. To aid in this goal all cryptographic components are
descended from one of several base classes, TDCP_cipher for encryption
algorithms and TDCP_hash for message digest algorithms.

DCPcrypt is open source software released under the MIT license.
See the LICENSE file for full terms.


Available algorithms:

  Ciphers:  Blowfish, CAST-128, CAST-256, DES, 3DES, GOST, ICE,
            IDEA, MARS, MISTY1, RC2, RC4, RC5, RC6, Rijndael (AES),
            Serpent, TEA, Twofish

  Hashes:   HAVAL, MD4, MD5, RipeMD-128, RipeMD-160, SHA-1,
            SHA-256, SHA-384, SHA-512, Tiger


Installation:

  Option 1 - Install as Lazarus packages:
    Open src/dcpcrypt.lpk (runtime) and src/dcpcrypt_laz.lpk
    (design-time) in the Lazarus IDE and install them. Cipher and
    hash components will appear on the component palette.

  Option 2 - Use directly in your project:
    Add src/, src/Ciphers/ and src/Hashes/ to your project unit
    search paths. Create cipher and hash instances in code (no
    package install needed). See the GUI examples.


Examples:

  examples/console/
    demo_encrypt_string.lpr  - Console string encrypt/decrypt test
    demo_file_encrypt.lpr    - Console file encrypt/decrypt test
    demo_hash_file.lpr       - Hash files using all 10 hash algorithms
    demo_hash_large_file.lpr - Hash large files (>5 GB) with progress (--size, --dir)

  examples/gui/
    EncryptStrings/          - GUI string encryption using EncryptStream
    FileEncrypt/             - GUI file encryption with thread support

  The GUI examples were ported from the original Delphi VCL to
  Lazarus LCL by Nicolas Deoux (NDXDev@gmail.com) in 2026.
  Build with: lazbuild <project>.lpi


Documentation:

See the HTML documentation in src/Docs/.


Contributors:

  David Barton          - Original DCPcrypt author (1999-2003)
  Barko                 - Lazarus port (2006)
  Graeme Geldenhuys     - Package split, 64-bit support (2009-2010)
  Werner Pamler         - Large file hash fix (2022)
  Nicolas Deoux         - GUI examples VCL to LCL port (2026)
                          NDXDev@gmail.com
                          https://www.linkedin.com/in/nicolas-deoux-ab295980/


DCPcrypt is copyrighted by its respective authors.
Released under the MIT license. All trademarks are property of their
respective owners.
