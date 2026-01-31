# Block Ciphers - TDCP_blockcipher

**DCPcrypt Cryptographic Component Library v2.0.5**
Lazarus / Free Pascal edition

All block ciphers are inherited from the TDCP_blockcipher component via either the TDCP_blockcipher64 and TDCP_blockcipher128 components (the latter implement the block size specific code).

The TDCP_blockcipher component extends the TDCP_cipher component to provide chaining mode functions. Functions available are:

```
property Initialized: boolean;
property Id: integer;
property Algorithm: string;
property MaxKeySize: integer;
property BlockSize: integer;
property CipherMode: TDCP_ciphermode;

class function SelfTest: boolean;

procedure SetIV(const Value);
procedure GetIV(var Value);

procedure Init(const Key; Size: longword; InitVector: pointer);
procedure InitStr(const Key: string; HashType: TDCP_hashclass);
procedure Burn;
procedure Reset;
procedure Encrypt(const Indata; var Outdata; Size: longword);
procedure Decrypt(const Indata; var Outdata; Size: longword);
function EncryptStream(InStream, OutStream: TStream; Size: Int64): longword;
function DecryptStream(InStream, OutStream: TStream; Size: Int64): longword;
function EncryptString(const Str: string): string;
function DecryptString(const Str: string): string;
procedure EncryptECB(const Indata; var Outdata);
procedure DecryptECB(const Indata; var Outdata);
procedure EncryptCBC(const Indata; var Outdata; Size: longword);
procedure DecryptCBC(const Indata; var Outdata; Size: longword);
procedure EncryptCFB8bit(const Indata; var Outdata; Size: longword);
procedure DecryptCFB8bit(const Indata; var Outdata; Size: longword);
procedure EncryptCFBblock(const Indata; var Outdata; Size: longword);
procedure DecryptCFBblock(const Indata; var Outdata; Size: longword);
procedure EncryptOFB(const Indata; var Outdata; Size: longword);
procedure DecryptOFB(const Indata; var Outdata; Size: longword);
procedure EncryptCTR(const Indata; var Outdata; Size: longword);
procedure DecryptCTR(const Indata; var Outdata; Size: longword);
```

Properties and methods inherited from TDCP_cipher are documented in [Ciphers](Ciphers.md). Only the additions specific to TDCP_blockcipher are described below.

---

## Function descriptions

### <a id="blocksize"></a>`property BlockSize: integer`

This contains the block size of the cipher in BITS.

### <a id="ciphermode"></a>`property CipherMode: TDCP_ciphermode`

This is the current chaining mode used when [Encrypt](Ciphers.md#encrypt) is called. The available modes are:

- **cmCBC** - Cipher block chaining.
- **cmCFB8bit** - 8bit cipher feedback.
- **cmCFBblock** - Cipher feedback (using the block size of the algorithm).
- **cmOFB** - Output feedback.
- **cmCTR** - Counter.

Each chaining mode has it's own pro's and cons. See any good book on cryptography or the NIST publication SP800-38A for details on each.

### <a id="setiv"></a>`procedure SetIV(const Value)`

Use this procedure to set the current chaining mode information to Value. This variable should be the same size as the block size. When [Reset](Ciphers.md#reset) is called subsequent to this, the chaining information will be set back to Value.

### <a id="getiv"></a>`procedure GetIV(var Value)`

This returns in Value the current chaining mode information, to get the initial chaining mode information you need to call [Reset](Ciphers.md#reset) before calling GetIV. The variable passed in Value must be at least the same size as the block size otherwise you will get a buffer overflow.

### <a id="encryptecb"></a>`procedure EncryptECB(const Indata; var Outdata)`
### <a id="decryptecb"></a>`procedure DecryptECB(const Indata; var Outdata)`

These procedures encrypt/decrypt a single block of data (the size of which is determined by the [BlockSize](#blocksize) property). Indata and Outdata must each be at least BlockSize div 8 bytes. ECB (Electronic Codebook) mode encrypts each block independently with no chaining. These are the lowest-level encryption primitives and are used internally by the chaining mode methods below. Direct use of ECB mode is generally discouraged because identical plaintext blocks produce identical ciphertext blocks.

### <a id="encryptcbc"></a>`procedure EncryptCBC(const Indata; var Outdata; Size: longword)`
### <a id="decryptcbc"></a>`procedure DecryptCBC(const Indata; var Outdata; Size: longword)`
### <a id="encryptcfb8bit"></a>`procedure EncryptCFB8bit(const Indata; var Outdata; Size: longword)`
### <a id="decryptcfb8bit"></a>`procedure DecryptCFB8bit(const Indata; var Outdata; Size: longword)`
### <a id="encryptcfbblock"></a>`procedure EncryptCFBblock(const Indata; var Outdata; Size: longword)`
### <a id="decryptcfbblock"></a>`procedure DecryptCFBblock(const Indata; var Outdata; Size: longword)`
### <a id="encryptofb"></a>`procedure EncryptOFB(const Indata; var Outdata; Size: longword)`
### <a id="decryptofb"></a>`procedure DecryptOFB(const Indata; var Outdata; Size: longword)`
### <a id="encryptctr"></a>`procedure EncryptCTR(const Indata; var Outdata; Size: longword)`
### <a id="decryptctr"></a>`procedure DecryptCTR(const Indata; var Outdata; Size: longword)`

These procedures encrypt/decrypt Size bytes of data from Indata and places the result in Outdata. These all employ chaining mode methods of encryption/decryption and so may need to be used in conjunction with [Reset](Ciphers.md#reset). The CBC method uses short block encryption as specified in Bruce Schneier's "Applied Cryptography" for data blocks that are not multiples of the block size.

---

[Index](README.md) | [Ciphers](Ciphers.md) | [Hashes](Hashes.md)

---

*DCPcrypt is copyrighted by its respective authors.*
*Released under the MIT license. All trademarks are property of their respective owners.*
