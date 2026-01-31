{******************************************************************************}
{* test_block_modes.lpr - Functional tests for block cipher modes            *}
{* Tests CBC, CFB8bit, CFBblock, OFB, CTR and ECB for both 64-bit and       *}
{* 128-bit block ciphers (Blowfish and Rijndael)                             *}
{******************************************************************************}
program test_block_modes;

{$MODE Delphi}

uses
  SysUtils,
  DCPcrypt2, DCPblockciphers,
  DCPrijndael, DCPblowfish,
  DCPsha1,
  testutils;

const
  TestKey = 'BlockModeTestKey';

procedure TestDirectModes(Cipher: TDCP_blockcipher; const CipherName: string;
  BlockBytes: integer);
var
  Plain, Encrypted, Decrypted: array of byte;
  PlainECB, EncECB, DecECB: array of byte;
  DataSize: integer;
  i: integer;
  Match: boolean;
begin
  DataSize := BlockBytes * 4; { 4 blocks }

  { Prepare test data }
  SetLength(Plain, DataSize);
  SetLength(Encrypted, DataSize);
  SetLength(Decrypted, DataSize);
  for i := 0 to DataSize - 1 do
    Plain[i] := Byte(i mod 256);

  { --- ECB (single block) --- }
  SetLength(PlainECB, BlockBytes);
  SetLength(EncECB, BlockBytes);
  SetLength(DecECB, BlockBytes);
  for i := 0 to BlockBytes - 1 do
    PlainECB[i] := Byte((i + 42) mod 256);

  Cipher.InitStr(TestKey, TDCP_sha1);
  Cipher.EncryptECB(PlainECB[0], EncECB[0]);
  Cipher.DecryptECB(EncECB[0], DecECB[0]);
  Cipher.Burn;

  Match := True;
  for i := 0 to BlockBytes - 1 do
    if PlainECB[i] <> DecECB[i] then begin Match := False; Break; end;
  Check(CipherName + ' ECB roundtrip', Match);

  { --- CBC --- }
  Cipher.InitStr(TestKey, TDCP_sha1);
  Cipher.EncryptCBC(Plain[0], Encrypted[0], DataSize);
  Cipher.Reset;
  Cipher.DecryptCBC(Encrypted[0], Decrypted[0], DataSize);
  Cipher.Burn;

  Match := True;
  for i := 0 to DataSize - 1 do
    if Plain[i] <> Decrypted[i] then begin Match := False; Break; end;
  Check(CipherName + ' CBC roundtrip', Match);

  { --- CFB8bit --- }
  Cipher.InitStr(TestKey, TDCP_sha1);
  Cipher.EncryptCFB8bit(Plain[0], Encrypted[0], DataSize);
  Cipher.Reset;
  Cipher.DecryptCFB8bit(Encrypted[0], Decrypted[0], DataSize);
  Cipher.Burn;

  Match := True;
  for i := 0 to DataSize - 1 do
    if Plain[i] <> Decrypted[i] then begin Match := False; Break; end;
  Check(CipherName + ' CFB8bit roundtrip', Match);

  { --- CFBblock --- }
  Cipher.InitStr(TestKey, TDCP_sha1);
  Cipher.EncryptCFBblock(Plain[0], Encrypted[0], DataSize);
  Cipher.Reset;
  Cipher.DecryptCFBblock(Encrypted[0], Decrypted[0], DataSize);
  Cipher.Burn;

  Match := True;
  for i := 0 to DataSize - 1 do
    if Plain[i] <> Decrypted[i] then begin Match := False; Break; end;
  Check(CipherName + ' CFBblock roundtrip', Match);

  { --- OFB --- }
  Cipher.InitStr(TestKey, TDCP_sha1);
  Cipher.EncryptOFB(Plain[0], Encrypted[0], DataSize);
  Cipher.Reset;
  Cipher.DecryptOFB(Encrypted[0], Decrypted[0], DataSize);
  Cipher.Burn;

  Match := True;
  for i := 0 to DataSize - 1 do
    if Plain[i] <> Decrypted[i] then begin Match := False; Break; end;
  Check(CipherName + ' OFB roundtrip', Match);

  { --- CTR --- }
  Cipher.InitStr(TestKey, TDCP_sha1);
  Cipher.EncryptCTR(Plain[0], Encrypted[0], DataSize);
  Cipher.Reset;
  Cipher.DecryptCTR(Encrypted[0], Decrypted[0], DataSize);
  Cipher.Burn;

  Match := True;
  for i := 0 to DataSize - 1 do
    if Plain[i] <> Decrypted[i] then begin Match := False; Break; end;
  Check(CipherName + ' CTR roundtrip', Match);
end;

procedure TestCipherModeProperty(Cipher: TDCP_blockcipher; const CipherName: string;
  BlockBytes: integer);
var
  Plain, Encrypted, Decrypted: array of byte;
  DataSize: integer;
  i: integer;
  Match: boolean;
  Mode: TDCP_ciphermode;
  ModeNames: array[TDCP_ciphermode] of string;
begin
  ModeNames[cmCBC] := 'CBC';
  ModeNames[cmCFB8bit] := 'CFB8bit';
  ModeNames[cmCFBblock] := 'CFBblock';
  ModeNames[cmOFB] := 'OFB';
  ModeNames[cmCTR] := 'CTR';

  DataSize := BlockBytes * 3;
  SetLength(Plain, DataSize);
  SetLength(Encrypted, DataSize);
  SetLength(Decrypted, DataSize);
  for i := 0 to DataSize - 1 do
    Plain[i] := Byte((i * 7 + 13) mod 256);

  for Mode := cmCBC to cmCTR do
  begin
    Cipher.InitStr(TestKey, TDCP_sha1);
    Cipher.CipherMode := Mode;
    Cipher.Encrypt(Plain[0], Encrypted[0], DataSize);
    Cipher.Reset;
    Cipher.Decrypt(Encrypted[0], Decrypted[0], DataSize);
    Cipher.Burn;

    Match := True;
    for i := 0 to DataSize - 1 do
      if Plain[i] <> Decrypted[i] then begin Match := False; Break; end;
    Check(CipherName + ' CipherMode=' + ModeNames[Mode] + ' roundtrip', Match);
  end;
end;

procedure TestNonAlignedData(Cipher: TDCP_blockcipher; const CipherName: string;
  BlockBytes: integer);
var
  Plain, Encrypted, Decrypted: array of byte;
  DataSize: integer;
  i: integer;
  Match: boolean;
begin
  { Test with data size not aligned to block size }
  DataSize := BlockBytes * 2 + 3;
  SetLength(Plain, DataSize);
  SetLength(Encrypted, DataSize);
  SetLength(Decrypted, DataSize);
  for i := 0 to DataSize - 1 do
    Plain[i] := Byte((i * 11 + 5) mod 256);

  { CFB8bit handles non-aligned data natively }
  Cipher.InitStr(TestKey, TDCP_sha1);
  Cipher.EncryptCFB8bit(Plain[0], Encrypted[0], DataSize);
  Cipher.Reset;
  Cipher.DecryptCFB8bit(Encrypted[0], Decrypted[0], DataSize);
  Cipher.Burn;

  Match := True;
  for i := 0 to DataSize - 1 do
    if Plain[i] <> Decrypted[i] then begin Match := False; Break; end;
  Check(CipherName + ' CFB8bit non-aligned roundtrip', Match);

  { OFB handles non-aligned data }
  Cipher.InitStr(TestKey, TDCP_sha1);
  Cipher.EncryptOFB(Plain[0], Encrypted[0], DataSize);
  Cipher.Reset;
  Cipher.DecryptOFB(Encrypted[0], Decrypted[0], DataSize);
  Cipher.Burn;

  Match := True;
  for i := 0 to DataSize - 1 do
    if Plain[i] <> Decrypted[i] then begin Match := False; Break; end;
  Check(CipherName + ' OFB non-aligned roundtrip', Match);

  { CTR handles non-aligned data }
  Cipher.InitStr(TestKey, TDCP_sha1);
  Cipher.EncryptCTR(Plain[0], Encrypted[0], DataSize);
  Cipher.Reset;
  Cipher.DecryptCTR(Encrypted[0], Decrypted[0], DataSize);
  Cipher.Burn;

  Match := True;
  for i := 0 to DataSize - 1 do
    if Plain[i] <> Decrypted[i] then begin Match := False; Break; end;
  Check(CipherName + ' CTR non-aligned roundtrip', Match);
end;

var
  Rijndael: TDCP_rijndael;
  Blowfish: TDCP_blowfish;
begin
  WriteLn('=== DCPcrypt Block Cipher Mode Tests ===');

  Rijndael := TDCP_rijndael.Create(nil);
  Blowfish := TDCP_blowfish.Create(nil);
  try
    WriteLn;
    WriteLn('--- Rijndael (128-bit block) - Direct mode methods ---');
    TestDirectModes(Rijndael, 'Rijndael', 16);

    WriteLn;
    WriteLn('--- Rijndael (128-bit block) - CipherMode property ---');
    TestCipherModeProperty(Rijndael, 'Rijndael', 16);

    WriteLn;
    WriteLn('--- Rijndael (128-bit block) - Non-aligned data ---');
    TestNonAlignedData(Rijndael, 'Rijndael', 16);

    WriteLn;
    WriteLn('--- Blowfish (64-bit block) - Direct mode methods ---');
    TestDirectModes(Blowfish, 'Blowfish', 8);

    WriteLn;
    WriteLn('--- Blowfish (64-bit block) - CipherMode property ---');
    TestCipherModeProperty(Blowfish, 'Blowfish', 8);

    WriteLn;
    WriteLn('--- Blowfish (64-bit block) - Non-aligned data ---');
    TestNonAlignedData(Blowfish, 'Blowfish', 8);
  finally
    Rijndael.Free;
    Blowfish.Free;
  end;

  WriteLn;
  Halt(TestSummary);
end.
