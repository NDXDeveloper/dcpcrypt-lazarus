# Ciphers - TDCP_cipher

**DCPcrypt Cryptographic Component Library v2.0.5**
Lazarus / Free Pascal edition

All ciphers are inherited from the TDCP_cipher component either directly for stream ciphers (such as RC4) or via the TDCP_blockcipher component.

The TDCP_cipher component implements key initialisation features and the basic encryption/decryption interface. Functions available are:

```
property Initialized: boolean;
property Id: integer;
property Algorithm: string;
property MaxKeySize: integer;

class function SelfTest: boolean;

procedure Init(const Key; Size: longword; InitVector: pointer);
procedure InitStr(const Key: string; HashType: TDCP_hashclass);
procedure Burn;
procedure Reset;
procedure Encrypt(const Indata; var Outdata; Size: longword);
procedure Decrypt(const Indata; var Outdata; Size: longword);
function EncryptStream(InStream, OutStream: TStream; Size: Int64): longword;
function DecryptStream(InStream, OutStream: TStream; Size: Int64): longword;
function PartialEncryptStream(AStream: TMemoryStream; Size: longword): longword;
function PartialDecryptStream(AStream: TMemoryStream; Size: longword): longword;
function EncryptString(const Str: string): string;
function DecryptString(const Str: string): string;

property OnProgressEvent: TProgressEvent;
property CancelByCallingThread: boolean;
```

Example usage:

- [Example 1](#example-1-string-encryption) - String encryption.
- [Example 2](#example-2-file-encryption) - File encryption.
- [Example 3](#example-3-general-encryption) - General encryption.

---

## Function descriptions

### <a id="initialized"></a>`property Initialized: boolean`

Once key initialization has been performed this property is set to true, otherwise it is set to false. Calling [Burn](#burn) will immediately set this to false.

### <a id="id"></a>`property Id: integer`

Every algorithm I implement gets given a unique ID number so that if I use several different algorithms within a program I can determine which one was used. This is a purely arbitrary numbering system.

### <a id="algorithm"></a>`property Algorithm: string`

This contains the name of the algorithm implemented within the component.

### <a id="maxkeysize"></a>`property MaxKeySize: integer`

This is the maximum size of key you can pass to the cipher (in bits!).

### <a id="selftest"></a>`class function SelfTest: boolean`

In order to test whether the implementations have all been compiled correctly you can call the SelfTest function. This compares the results of several encryption/decryption operations with known results for the algorithms (so called test vectors). If all the tests are passed then true is returned. If ANY of the tests are failed then false is returned. You may want to run this function for all the components when you first install the DCPcrypt package and again if you modify any of the source files, you don't need to run this everytime your program is run. Note: this only performs a selection of tests, it is not exhaustive.

### <a id="init"></a>`procedure Init(const Key; Size: longword; InitVector: pointer)`

This procedure initializes the cipher with the keying material supplied in Key. The Size of the keying material is specified in **BITS**. The InitVector is a pointer to chaining information (only used for block ciphers). The variable that this points to should be equal to the block size of the algorithm. If *nil* is specified then (if necessary) an initialization vector is automatically generated from the key. Note: the method for generating automatic IVs is different from DCPcrypt v1.31, if this is a problem uncomment the DCPcrypt v1.31 compatibility mode line in DCPcrypt2.pas.

Init example: use the hash of a string to initialize the cipher

```pascal
procedure TForm1.Button1Click(Sender: TObject);
var
  Cipher: TDCP_rc4;
  Hash: TDCP_sha1;
  Digest: array[0..19] of byte;  // SHA-1 produces a 160bit (20byte) output
begin
  Hash:= TDCP_sha1.Create(Self);
  Hash.Init;                     // initialize the hash
  Hash.UpdateStr(Edit1.Text);    // generate a hash of Edit1.Text
  Hash.Final(Digest);            // save the hash in Digest
  Hash.Free;
  Cipher:= TDCP_rc4.Create(Self);
  Cipher.Init(Digest,Sizeof(Digest)*8,nil);  // remember size is in BITS (hence sizeof*8)
  ...
```

### <a id="initstr"></a>`procedure InitStr(const Key: string; HashType: TDCP_hashclass)`

This procedure initializes the cipher with a hash of the key string using the specified hash type (in a way similar to the example above). To replicate the behaviour from DCPcrypt v2 Beta 1 use `Cipher.InitStr(KeyStr,TDCP_sha1)`.

InitStr example: prompt the user for a passphrase to initialize the cipher

```pascal
procedure TForm1.Button1Click(Sender: TObject);
var
  Cipher: TDCP_rc4;
begin
  Cipher:= TDCP_rc4.Create(Self);
  Cipher.InitStr(InputBox('Passphrase','Enter a passphrase',''),TDCP_sha1); // prompt for a passphrase
  ...
```

### <a id="burn"></a>`procedure Burn`

Once you have finished encrypting/decrypting all your data call Burn to erase all keying information. This is automatically called once the cipher is freed, however it is a good habit to call this procedure explicitly.

### <a id="reset"></a>`procedure Reset`

Stream ciphers (and block ciphers in chaining modes) generally store chaining information that is dependant on the information already encrypted. Consequently decrypting a block of information immediately after encrypting it won't result in the original information because when you called the decrypt procedure the chaining information was different from when you called the encrypt procedure. Hence use Reset to restore the chaining information to it's original state.

Remember that calling [EncryptString](#encryptstring), [DecryptString](#decryptstring), [EncryptStream](#encryptstream) and [DecryptStream](#decryptstream) will also affect the chaining information.

Reset example: encrypting and decrypting

```pascal
function TestCipher: boolean;
const
  InData: array[0..9] of byte= ($01,$23,$45,$56,$67,$78,$89,$10,$AB,$FF);
var
  Cipher: TDCP_rc4;
  Data: array[0..9] of byte;
begin
  Cipher:= TDCP_rc4.Create(nil);
  Cipher.InitStr('Hello World',TDCP_sha1);   // initialize the cipher
  Cipher.Encrypt(InData,Data,Sizeof(Data));  // encrypt some known data
  Cipher.Decrypt(Data,Data,Sizeof(Data));    // now decrypt it
  Cipher.Burn;                               // clear keying information
  Cipher.Free;
  Result:= CompareMem(@InData,@Data,Sizeof(Data));  // compare input and output
end;
```

The above will ALWAYS result in false due to the chaining information.

```pascal
function TestCipher: boolean;
const
  InData: array[0..9] of byte= ($01,$23,$45,$56,$67,$78,$89,$10,$AB,$FF);
var
  Cipher: TDCP_rc4;
  Data: array[0..9] of byte;
begin
  Cipher:= TDCP_rc4.Create(nil);
  Cipher.InitStr('Hello World',TDCP_sha1);   // initialize the cipher
  Cipher.Encrypt(InData,Data,Sizeof(Data));  // encrypt some known data
  Cipher.Reset;                              // **reset chaining information**
  Cipher.Decrypt(Data,Data,Sizeof(Data));    // now decrypt it
  Cipher.Burn;                               // clear keying information
  Cipher.Free;
  Result:= CompareMem(@InData,@Data,Sizeof(Data));  // compare input and output
end;
```

The above *should* always return true.

### <a id="encrypt"></a>`procedure Encrypt(const Indata; var Outdata; Size: longword)`

Encrypt Size bytes from Indata and place it in Outdata. Block ciphers encrypt the data using the method specified by the [CipherMode](BlockCiphers.md#ciphermode) property. Also see the notes on [Reset](#reset).

### <a id="decrypt"></a>`procedure Decrypt(const Indata; var Outdata; Size: longword)`

Decrypt Size bytes from Indata and place it in Outdata. Block ciphers decrypt the data using the method specified by the [CipherMode](BlockCiphers.md#ciphermode) property. Also see the notes on [Reset](#reset).

### <a id="encryptstream"></a>`function EncryptStream(InStream, OutStream: TStream; Size: Int64): longword`

Encrypt Size bytes from the InStream and place it in the OutStream, returns the number of bytes read from the InStream. Encryption is done by calling the [Encrypt](#encrypt) procedure. The Size parameter is Int64 to support files larger than 4 GB. If the [OnProgressEvent](#onprogressevent) property is assigned, a progress callback is fired during processing. The operation can be interrupted by setting [CancelByCallingThread](#cancelbycallingthread) to true. Also see the notes on [Reset](#reset).

### <a id="decryptstream"></a>`function DecryptStream(InStream, OutStream: TStream; Size: Int64): longword`

Decrypt Size bytes from the InStream and place it in the OutStream, returns the number of bytes read from the InStream. Decryption is done by calling the [Decrypt](#decrypt) procedure. The Size parameter is Int64 to support files larger than 4 GB. If the [OnProgressEvent](#onprogressevent) property is assigned, a progress callback is fired during processing. The operation can be interrupted by setting [CancelByCallingThread](#cancelbycallingthread) to true. Also see the notes on [Reset](#reset).

### <a id="partialencryptstream"></a>`function PartialEncryptStream(AStream: TMemoryStream; Size: longword): longword`

Encrypt Size bytes from AStream in place (the stream is both input and output). Returns the number of bytes processed.

### <a id="partialdecryptstream"></a>`function PartialDecryptStream(AStream: TMemoryStream; Size: longword): longword`

Decrypt Size bytes from AStream in place (the stream is both input and output). Returns the number of bytes processed.

### <a id="encryptstring"></a>`function EncryptString(const Str: string): string`

Encrypt the string Str then Base64 encode it and return the result. For stream ciphers the [Encrypt](#encrypt) procedure is called to do the encryption, for block ciphers the [CFB8bit](BlockCiphers.md#encryptcfb8bit) method is always used. Base64 encoding is used to ensure that the output string doesn't contain non-printing characters.

### <a id="decryptstring"></a>`function DecryptString(const Str: string): string`

Base64 decode the string then decrypt it and return the result. For stream ciphers the [Decrypt](#decrypt) procedure is called to do the decryption, for block ciphers the [CFB8bit](BlockCiphers.md#decryptcfb8bit) method is always used.

### <a id="onprogressevent"></a>`property OnProgressEvent: TProgressEvent`

Assign a handler of type `TProgressEvent = procedure(Sender: TObject; Progress: integer) of object` to receive progress callbacks during [EncryptStream](#encryptstream) and [DecryptStream](#decryptstream) operations. The Progress parameter is a percentage (0..100).

### <a id="cancelbycallingthread"></a>`property CancelByCallingThread: boolean`

Set this property to true to interrupt an ongoing [EncryptStream](#encryptstream) or [DecryptStream](#decryptstream) operation. This is useful when running encryption/decryption in a separate thread and the user requests cancellation.

---

## Example 1: String encryption

This example shows how you can encrypt the contents of a TMemo and leave the contents printable.

```pascal
procedure TForm1.btnEncryptClick(Sender: TObject);
var
  i: integer;
  Cipher: TDCP_rc4;
  KeyStr: string;
begin
  KeyStr:= '';
  if InputQuery('Passphrase','Enter passphrase',KeyStr) then  // get the passphrase
  begin
    Cipher:= TDCP_rc4.Create(Self);
    Cipher.InitStr(KeyStr,TDCP_sha1);         // initialize the cipher with a hash of the passphrase
    for i:= 0 to Memo1.Lines.Count-1 do       // encrypt the contents of the memo
      Memo1.Lines[i]:= Cipher.EncryptString(Memo1.Lines[i]);
    Cipher.Burn;
    Cipher.Free;
  end;
end;

procedure TForm1.btnDecryptClick(Sender: TObject);
var
  i: integer;
  Cipher: TDCP_rc4;
  KeyStr: string;
begin
  KeyStr:= '';
  if InputQuery('Passphrase','Enter passphrase',KeyStr) then  // get the passphrase
  begin
    Cipher:= TDCP_rc4.Create(Self);
    Cipher.InitStr(KeyStr,TDCP_sha1);         // initialize the cipher with a hash of the passphrase
    for i:= 0 to Memo1.Lines.Count-1 do       // decrypt the contents of the memo
      Memo1.Lines[i]:= Cipher.DecryptString(Memo1.Lines[i]);
    Cipher.Burn;
    Cipher.Free;
  end;
end;
```

---

## Example 2: File encryption

This example shows how you can encrypt the contents of a file, takes the input and output file names from two edit boxes: boxInputFile and boxOutputFile.

```pascal
procedure TForm1.btnEncryptClick(Sender: TObject);
var
  Cipher: TDCP_rc4;
  KeyStr: string;
  Source, Dest: TFileStream;
begin
  KeyStr:= '';
  if InputQuery('Passphrase','Enter passphrase',KeyStr) then  // get the passphrase
  begin
    try
      Source:= TFileStream.Create(boxInputFile.Text,fmOpenRead);
      Dest:= TFileStream.Create(boxOutputFile.Text,fmCreate);
      Cipher:= TDCP_rc4.Create(Self);
      Cipher.InitStr(KeyStr,TDCP_sha1);              // initialize the cipher with a hash of the passphrase
      Cipher.EncryptStream(Source,Dest,Source.Size); // encrypt the contents of the file
      Cipher.Burn;
      Cipher.Free;
      Dest.Free;
      Source.Free;
      MessageDlg('File encrypted',mtInformation,[mbOK],0);
    except
      MessageDlg('File IO error',mtError,[mbOK],0);
    end;
  end;
end;

procedure TForm1.btnDecryptClick(Sender: TObject);
var
  Cipher: TDCP_rc4;
  KeyStr: string;
  Source, Dest: TFileStream;
begin
  KeyStr:= '';
  if InputQuery('Passphrase','Enter passphrase',KeyStr) then  // get the passphrase
  begin
    try
      Source:= TFileStream.Create(boxInputFile.Text,fmOpenRead);
      Dest:= TFileStream.Create(boxOutputFile.Text,fmCreate);
      Cipher:= TDCP_rc4.Create(Self);
      Cipher.InitStr(KeyStr,TDCP_sha1);              // initialize the cipher with a hash of the passphrase
      Cipher.DecryptStream(Source,Dest,Source.Size); // decrypt the contents of the file
      Cipher.Burn;
      Cipher.Free;
      Dest.Free;
      Source.Free;
      MessageDlg('File decrypted',mtInformation,[mbOK],0);
    except
      MessageDlg('File IO error',mtError,[mbOK],0);
    end;
  end;
end;
```

---

## Example 3: General encryption

This hypothetical example shows how you might encrypt a packet of information before transmission across a network.

```pascal
type
  TSomePacket= record
    Date: double;
    ToUserID: integer;
    FromUserID: integer;
    MsgLen: integer;
    Msg: string;
  end;

procedure EncryptPacket(Cipher: TDCP_cipher; var Packet: TSomePacket);
// encrypt the information packet with the cipher
// if the cipher isn't initialized then prompt for passphrase
begin
  if Cipher= nil then
    raise Exception.Create('Cipher hasn''t been created!')
  else
  begin
    if not Cipher.Initialized then        // check the cipher has been initialized
      Cipher.InitStr(InputBox('Passphrase','Enter passphrase',''),TDCP_sha1);
    if Cipher is TDCP_blockcipher then    // if a block cipher use CFB 8bit as encrypting small packets
      TDCP_blockcipher(Cipher).CipherMode:= cmCFB8bit;
    // encrypt the record part by part, could do this in one go if it was a packed record
    Cipher.Encrypt(Packet.Date,Packet.Date,Sizeof(Packet.Date));
    Cipher.Encrypt(Packet.ToUserID,Packet.ToUserID,Sizeof(Packet.ToUserID));
    Cipher.Encrypt(Packet.FromUserID,Packet.FromUserID,Sizeof(Packet.FromUserID));
    Cipher.Encrypt(Packet.MsgLen,Packet.MsgLen,Sizeof(Packet.MsgLen));
    Cipher.Encrypt(Packet.Msg[1],Packet.Msg[1],Length(Packet.Msg));  // slightly different for strings
    // don't bother resetting the cipher, instead keep the chaining information
  end;
end;
```

---

[Index](README.md) | [Block Ciphers](BlockCiphers.md) | [Hashes](Hashes.md)

---

*DCPcrypt is copyrighted by its respective authors.*
*Released under the MIT license. All trademarks are property of their respective owners.*
