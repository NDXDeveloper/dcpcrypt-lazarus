{******************************************************************************}
{* test_stream_encrypt.lpr - Functional tests for stream encryption          *}
{* Adapted from demo_encrypt_string.lpr and demo_file_encrypt.lpr            *}
{******************************************************************************}
program test_stream_encrypt;

{$MODE Delphi}

uses
  Classes, SysUtils,
  DCPcrypt2, DCPblockciphers,
  DCPrijndael, DCPblowfish, DCPrc4,
  DCPsha256, DCPsha1,
  testutils;

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

procedure TestStreamRoundtrip(const TestName, PlainText, Passphrase: string;
  Hash: TDCP_hash; Cipher: TDCP_cipher);
var
  Encrypted, Decrypted: string;
begin
  try
    Encrypted := DoEncryptStringStream(PlainText, Passphrase, Hash, Cipher);
    Decrypted := DoDecryptStringStream(Encrypted, Passphrase, Hash, Cipher);
    Check(TestName, Decrypted = PlainText);
  except
    on E: Exception do
    begin
      Check(TestName + ' (exception: ' + E.Message + ')', False);
    end;
  end;
end;

type
  TProgressHelper = class
    CallCount: integer;
    LastProgress: integer;
    procedure OnProgress(Sender: TObject; Progress: integer);
  end;

procedure TProgressHelper.OnProgress(Sender: TObject; Progress: integer);
begin
  Inc(CallCount);
  LastProgress := Progress;
end;

procedure TestMemoryStreamPartial;
var
  Cipher: TDCP_rijndael;
  Stream: TMemoryStream;
  PlainData: array[0..255] of byte;
  EncryptedData: array[0..255] of byte;
  i: integer;
  Match: boolean;
  BytesProcessed: longword;
begin
  WriteLn;
  WriteLn('--- PartialEncryptStream / PartialDecryptStream ---');

  for i := 0 to 255 do
    PlainData[i] := Byte(i);

  Cipher := TDCP_rijndael.Create(nil);
  Stream := TMemoryStream.Create;
  try
    { Write data to stream }
    Stream.WriteBuffer(PlainData, 256);

    { Encrypt in place }
    Cipher.InitStr('PartialTestKey', TDCP_sha1);
    Stream.Position := 0;
    BytesProcessed := Cipher.PartialEncryptStream(Stream, 256);
    Check('PartialEncryptStream processed 256 bytes', BytesProcessed = 256);

    { Save encrypted data }
    Stream.Position := 0;
    Stream.ReadBuffer(EncryptedData, 256);

    { Verify encrypted data differs from plain }
    Match := True;
    for i := 0 to 255 do
      if PlainData[i] <> EncryptedData[i] then begin Match := False; Break; end;
    Check('PartialEncryptStream changed data', not Match);

    { Reset and decrypt in place }
    Cipher.Reset;
    Stream.Position := 0;
    BytesProcessed := Cipher.PartialDecryptStream(Stream, 256);
    Check('PartialDecryptStream processed 256 bytes', BytesProcessed = 256);
    Cipher.Burn;

    { Read back and verify }
    Stream.Position := 0;
    Stream.ReadBuffer(EncryptedData, 256); { reuse buffer }
    Match := True;
    for i := 0 to 255 do
      if PlainData[i] <> EncryptedData[i] then begin Match := False; Break; end;
    Check('PartialEncrypt/Decrypt roundtrip', Match);
  finally
    Stream.Free;
    Cipher.Free;
  end;
end;

procedure TestProgressEvent;
var
  Cipher: TDCP_rijndael;
  SHA256: TDCP_sha256;
  InStream, OutStream: TStringStream;
  HashDigest: array of byte;
  Salt: array[0..7] of byte;
  CipherIV: array[0..15] of byte;
  ProgressHelper: TProgressHelper;
  LargeData: string;
  i: integer;
begin
  WriteLn;
  WriteLn('--- OnProgressEvent ---');

  { Create a string larger than EncryptBufSize (8 MB) to trigger multiple
    progress callbacks. We use a smaller size but still > 0 to verify
    at least one callback. }
  SetLength(LargeData, 100000);
  for i := 1 to Length(LargeData) do
    LargeData[i] := Chr(32 + (i mod 95));

  Cipher := TDCP_rijndael.Create(nil);
  SHA256 := TDCP_sha256.Create(nil);
  ProgressHelper := TProgressHelper.Create;
  InStream := nil;
  OutStream := nil;
  try
    InStream := TStringStream.Create(LargeData);
    OutStream := TStringStream.Create('');

    SetLength(HashDigest, SHA256.HashSize div 8);
    for i := 0 to 7 do Salt[i] := Random(256);
    for i := 0 to 15 do CipherIV[i] := Random(256);
    SHA256.Init;
    SHA256.Update(Salt[0], SizeOf(Salt));
    SHA256.UpdateStr('ProgressTestKey');
    SHA256.Final(HashDigest[0]);

    Cipher.Init(HashDigest[0], Min(Cipher.MaxKeySize, SHA256.HashSize), @CipherIV[0]);
    Cipher.CipherMode := cmCBC;

    ProgressHelper.CallCount := 0;
    ProgressHelper.LastProgress := -1;
    Cipher.OnProgressEvent := ProgressHelper.OnProgress;

    Cipher.EncryptStream(InStream, OutStream, InStream.Size);
    Cipher.Burn;

    Check('OnProgressEvent was called', ProgressHelper.CallCount > 0);
    Check('OnProgressEvent reached 100%', ProgressHelper.LastProgress = 100);
  finally
    InStream.Free;
    OutStream.Free;
    SHA256.Free;
    Cipher.Free;
    ProgressHelper.Free;
  end;
end;

var
  Rijndael: TDCP_rijndael;
  Blowfish: TDCP_blowfish;
  RC4: TDCP_rc4;
  SHA256: TDCP_sha256;
  Passphrase: string;
  LongStr: string;
  i: integer;
begin
  Randomize;
  Passphrase := 'StreamTestPassphrase';

  WriteLn('=== DCPcrypt Stream Encryption Tests ===');

  Rijndael := TDCP_rijndael.Create(nil);
  Blowfish := TDCP_blowfish.Create(nil);
  RC4 := TDCP_rc4.Create(nil);
  SHA256 := TDCP_sha256.Create(nil);
  try
    { Block ciphers + SHA256 }
    WriteLn;
    WriteLn('--- Block ciphers via EncryptStream ---');
    TestStreamRoundtrip('Rijndael+SHA256 normal string',
      'Hello, World! Testing stream encryption.', Passphrase, SHA256, Rijndael);
    TestStreamRoundtrip('Blowfish+SHA256 normal string',
      'Hello, World! Testing stream encryption.', Passphrase, SHA256, Blowfish);

    { Stream cipher + SHA256 }
    WriteLn;
    WriteLn('--- Stream cipher via EncryptStream ---');
    TestStreamRoundtrip('RC4+SHA256 normal string',
      'Hello, World! Testing stream encryption.', Passphrase, SHA256, RC4);

    { Empty string }
    WriteLn;
    WriteLn('--- Empty string ---');
    TestStreamRoundtrip('Rijndael+SHA256 empty string',
      '', Passphrase, SHA256, Rijndael);
    TestStreamRoundtrip('RC4+SHA256 empty string',
      '', Passphrase, SHA256, RC4);

    { Long string (10000 chars) }
    WriteLn;
    WriteLn('--- Long string (10000 chars) ---');
    SetLength(LongStr, 10000);
    for i := 1 to 10000 do
      LongStr[i] := Chr(32 + (i mod 95));
    TestStreamRoundtrip('Rijndael+SHA256 long string',
      LongStr, Passphrase, SHA256, Rijndael);
    TestStreamRoundtrip('Blowfish+SHA256 long string',
      LongStr, Passphrase, SHA256, Blowfish);
    TestStreamRoundtrip('RC4+SHA256 long string',
      LongStr, Passphrase, SHA256, RC4);
  finally
    Rijndael.Free;
    Blowfish.Free;
    RC4.Free;
    SHA256.Free;
  end;

  { PartialEncryptStream / PartialDecryptStream }
  TestMemoryStreamPartial;

  { OnProgressEvent }
  TestProgressEvent;

  WriteLn;
  Halt(TestSummary);
end.
