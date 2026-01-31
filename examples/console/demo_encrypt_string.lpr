{******************************************************************************}
{* Demo: Encrypt/Decrypt strings using EncryptStream                        *}
{* Adapted from the Delphi VCL demo to a Lazarus/FPC console application    *}
{* Tests the same crypto logic: Salt + IV + EncryptStream/DecryptStream      *}
{******************************************************************************}
program demo_encrypt_string;

{$MODE Delphi}

uses
  Classes, SysUtils,
  DCPcrypt2, DCPblockciphers,
  DCPrijndael, DCPblowfish, DCPtwofish, DCPdes, DCPrc4,
  DCPsha256, DCPsha1, DCPmd5;

function Min(a, b: integer): integer;
begin
  if a < b then Result := a else Result := b;
end;

function StringToHex(const S: string): string;
var
  i: integer;
begin
  Result := '';
  for i := 1 to Length(S) do
    Result := Result + IntToHex(Ord(S[i]), 2);
end;

function HexToString(const H: string): string;
var
  i: integer;
begin
  Result := '';
  i := 1;
  while i < Length(H) do
  begin
    Result := Result + Chr(StrToInt('$' + Copy(H, i, 2)));
    Inc(i, 2);
  end;
end;

function DoEncryptStringStream(const PlainText, Passphrase: string;
  Hash: TDCP_hash; Cipher: TDCP_cipher): string;
var
  CipherIV: array of byte;
  HashDigest: array of byte;
  Salt: array[0..7] of byte;
  strmInput, strmOutput: TStringStream;
  i: integer;
begin
  Result := '';
  strmInput := nil;
  strmOutput := nil;
  try
    strmInput := TStringStream.Create(PlainText);
    strmOutput := TStringStream.Create('');

    SetLength(HashDigest, Hash.HashSize div 8);
    for i := 0 to 7 do
      Salt[i] := Random(256);
    strmOutput.WriteBuffer(Salt, SizeOf(Salt));
    Hash.Init;
    Hash.Update(Salt[0], SizeOf(Salt));
    Hash.UpdateStr(Passphrase);
    Hash.Final(HashDigest[0]);

    if Cipher is TDCP_blockcipher then
    begin
      SetLength(CipherIV, TDCP_blockcipher(Cipher).BlockSize div 8);
      for i := 0 to Length(CipherIV) - 1 do
        CipherIV[i] := Random(256);
      strmOutput.WriteBuffer(CipherIV[0], Length(CipherIV));
      Cipher.Init(HashDigest[0], Min(Cipher.MaxKeySize, Hash.HashSize), @CipherIV[0]);
      TDCP_blockcipher(Cipher).CipherMode := cmCBC;
    end
    else
      Cipher.Init(HashDigest[0], Min(Cipher.MaxKeySize, Hash.HashSize), nil);

    Cipher.EncryptStream(strmInput, strmOutput, strmInput.Size);
    Cipher.Burn;

    strmOutput.Position := 0;
    Result := StringToHex(strmOutput.DataString);
  finally
    strmInput.Free;
    strmOutput.Free;
  end;
end;

function DoDecryptStringStream(const HexCipherText, Passphrase: string;
  Hash: TDCP_hash; Cipher: TDCP_cipher): string;
var
  CipherIV: array of byte;
  HashDigest: array of byte;
  Salt: array[0..7] of byte;
  strmInput, strmOutput: TStringStream;
begin
  Result := '';
  strmInput := nil;
  strmOutput := nil;
  try
    strmInput := TStringStream.Create(HexToString(HexCipherText));
    strmOutput := TStringStream.Create('');

    SetLength(HashDigest, Hash.HashSize div 8);
    strmInput.ReadBuffer(Salt[0], SizeOf(Salt));
    Hash.Init;
    Hash.Update(Salt[0], SizeOf(Salt));
    Hash.UpdateStr(Passphrase);
    Hash.Final(HashDigest[0]);

    if Cipher is TDCP_blockcipher then
    begin
      SetLength(CipherIV, TDCP_blockcipher(Cipher).BlockSize div 8);
      strmInput.ReadBuffer(CipherIV[0], Length(CipherIV));
      Cipher.Init(HashDigest[0], Min(Cipher.MaxKeySize, Hash.HashSize), @CipherIV[0]);
      TDCP_blockcipher(Cipher).CipherMode := cmCBC;
    end
    else
      Cipher.Init(HashDigest[0], Min(Cipher.MaxKeySize, Hash.HashSize), nil);

    Cipher.DecryptStream(strmInput, strmOutput, strmInput.Size - strmInput.Position);
    Cipher.Burn;

    strmOutput.Position := 0;
    Result := strmOutput.DataString;
  finally
    strmInput.Free;
    strmOutput.Free;
  end;
end;

procedure TestCipher(const CipherName: string; Cipher: TDCP_cipher;
  Hash: TDCP_hash; const PlainText, Passphrase: string);
var
  Encrypted, Decrypted: string;
begin
  Write('  ', CipherName:16, ' ... ');
  try
    Encrypted := DoEncryptStringStream(PlainText, Passphrase, Hash, Cipher);
    Decrypted := DoDecryptStringStream(Encrypted, Passphrase, Hash, Cipher);
    if Decrypted = PlainText then
      WriteLn('OK  (encrypted length: ', Length(Encrypted), ' hex chars)')
    else
      WriteLn('FAIL - decrypted text does not match original');
  except
    on E: Exception do
      WriteLn('ERROR: ', E.Message);
  end;
end;

var
  Rijndael: TDCP_rijndael;
  Blowfish: TDCP_blowfish;
  Twofish: TDCP_twofish;
  DES: TDCP_des;
  TripleDES: TDCP_3des;
  RC4: TDCP_rc4;
  SHA256: TDCP_sha256;
  SHA1: TDCP_sha1;
  MD5: TDCP_md5;
  PlainText, Passphrase: string;

begin
  Randomize;

  PlainText := 'Hello, World! This is a test of DCPcrypt string encryption via EncryptStream.';
  Passphrase := 'MySecretPassphrase123';

  WriteLn('=== DCPcrypt String Encryption Demo (Lazarus/FPC) ===');
  WriteLn;
  WriteLn('Plain text : "', PlainText, '"');
  WriteLn('Passphrase : "', Passphrase, '"');
  WriteLn;

  // Create cipher and hash instances
  Rijndael := TDCP_rijndael.Create(nil);
  Blowfish := TDCP_blowfish.Create(nil);
  Twofish := TDCP_twofish.Create(nil);
  DES := TDCP_des.Create(nil);
  TripleDES := TDCP_3des.Create(nil);
  RC4 := TDCP_rc4.Create(nil);
  SHA256 := TDCP_sha256.Create(nil);
  SHA1 := TDCP_sha1.Create(nil);
  MD5 := TDCP_md5.Create(nil);

  try
    // Test block ciphers with SHA-256
    WriteLn('--- Block ciphers with SHA-256 ---');
    TestCipher('Rijndael (AES)', Rijndael, SHA256, PlainText, Passphrase);
    TestCipher('Blowfish', Blowfish, SHA256, PlainText, Passphrase);
    TestCipher('Twofish', Twofish, SHA256, PlainText, Passphrase);
    TestCipher('DES', DES, SHA256, PlainText, Passphrase);
    TestCipher('3DES', TripleDES, SHA256, PlainText, Passphrase);
    WriteLn;

    // Test stream cipher (RC4) with SHA-256
    WriteLn('--- Stream cipher with SHA-256 ---');
    TestCipher('RC4', RC4, SHA256, PlainText, Passphrase);
    WriteLn;

    // Test Rijndael with different hashes
    WriteLn('--- Rijndael with different hashes ---');
    TestCipher('+ SHA-256', Rijndael, SHA256, PlainText, Passphrase);
    TestCipher('+ SHA-1', Rijndael, SHA1, PlainText, Passphrase);
    TestCipher('+ MD5', Rijndael, MD5, PlainText, Passphrase);
    WriteLn;

    // Test with empty string
    WriteLn('--- Edge case: empty string ---');
    TestCipher('Rijndael empty', Rijndael, SHA256, '', Passphrase);
    WriteLn;

    // Test with long string
    WriteLn('--- Edge case: long string (10000 chars) ---');
    TestCipher('Rijndael long', Rijndael, SHA256,
      StringOfChar('A', 10000), Passphrase);

    WriteLn;
    WriteLn('All tests completed.');
  finally
    Rijndael.Free;
    Blowfish.Free;
    Twofish.Free;
    DES.Free;
    TripleDES.Free;
    RC4.Free;
    SHA256.Free;
    SHA1.Free;
    MD5.Free;
  end;

  WriteLn;
  Write('Press Enter to exit...');
  ReadLn;
end.
