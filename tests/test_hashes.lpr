{******************************************************************************}
{* test_hashes.lpr - Functional tests for all DCPcrypt hash algorithms       *}
{******************************************************************************}
program test_hashes;

{$MODE Delphi}

uses
  Classes, SysUtils,
  DCPcrypt2,
  DCPhaval, DCPmd4, DCPmd5, DCPripemd128, DCPripemd160,
  DCPsha1, DCPsha256, DCPsha512, DCPtiger,
  testutils;

type
  THashInfo = record
    HashClass: TDCP_hashclass;
    Name: string;
  end;

const
  HashCount = 10;
  Hashes: array[0..HashCount-1] of THashInfo = (
    (HashClass: TDCP_haval;      Name: 'Haval'),
    (HashClass: TDCP_md4;        Name: 'MD4'),
    (HashClass: TDCP_md5;        Name: 'MD5'),
    (HashClass: TDCP_ripemd128;  Name: 'RipeMD-128'),
    (HashClass: TDCP_ripemd160;  Name: 'RipeMD-160'),
    (HashClass: TDCP_sha1;       Name: 'SHA-1'),
    (HashClass: TDCP_sha256;     Name: 'SHA-256'),
    (HashClass: TDCP_sha384;     Name: 'SHA-384'),
    (HashClass: TDCP_sha512;     Name: 'SHA-512'),
    (HashClass: TDCP_tiger;      Name: 'Tiger')
  );

function DigestToHex(const Digest: array of byte): string;
var
  i: integer;
begin
  Result := '';
  for i := 0 to Length(Digest) - 1 do
    Result := Result + LowerCase(IntToHex(Digest[i], 2));
end;

function DigestsEqual(const A, B: array of byte): boolean;
var
  i: integer;
begin
  Result := False;
  if Length(A) <> Length(B) then Exit;
  for i := 0 to Length(A) - 1 do
    if A[i] <> B[i] then Exit;
  Result := True;
end;

procedure WriteStringToFile(const FileName, Content: string);
var
  f: TFileStream;
begin
  f := TFileStream.Create(FileName, fmCreate);
  try
    if Length(Content) > 0 then
      f.WriteBuffer(Content[1], Length(Content));
  finally
    f.Free;
  end;
end;

procedure TestHashFile(const Info: THashInfo);
var
  Hash: TDCP_hash;
  DigestStr, DigestStream, DigestEmpty, DigestLarge: array of byte;
  DigestSize: integer;
  TempFile: string;
  Stream: TFileStream;
  TestData: string;
  i: integer;
begin
  Hash := Info.HashClass.Create(nil);
  try
    DigestSize := Hash.HashSize div 8;

    { Test 1: UpdateStream produces same digest as UpdateStr for 'abc' }
    SetLength(DigestStr, DigestSize);
    Hash.Init;
    Hash.UpdateStr('abc');
    Hash.Final(DigestStr[0]);

    TempFile := GetTempDir + 'dcp_test_hash_' + Info.Name + '.tmp';
    try
      WriteStringToFile(TempFile, 'abc');
      SetLength(DigestStream, DigestSize);
      Stream := TFileStream.Create(TempFile, fmOpenRead);
      try
        Hash.Init;
        Hash.UpdateStream(Stream, Stream.Size);
        Hash.Final(DigestStream[0]);
      finally
        Stream.Free;
      end;
      Check(Info.Name + ' UpdateStream matches UpdateStr for "abc"',
        DigestsEqual(DigestStr, DigestStream));
    finally
      if FileExists(TempFile) then DeleteFile(TempFile);
    end;

    { Test 2: Empty file produces a valid (non-crash) digest }
    TempFile := GetTempDir + 'dcp_test_hash_empty_' + Info.Name + '.tmp';
    try
      WriteStringToFile(TempFile, '');
      SetLength(DigestEmpty, DigestSize);
      Stream := TFileStream.Create(TempFile, fmOpenRead);
      try
        Hash.Init;
        Hash.UpdateStream(Stream, Stream.Size);
        Hash.Final(DigestEmpty[0]);
      finally
        Stream.Free;
      end;
      Check(Info.Name + ' empty file hash differs from "abc"',
        not DigestsEqual(DigestEmpty, DigestStr));
    finally
      if FileExists(TempFile) then DeleteFile(TempFile);
    end;

    { Test 3: Large file (>8192 bytes) to test multi-block streaming }
    TestData := '';
    for i := 1 to 1000 do
      TestData := TestData + 'TestData!_';  { 10000 bytes }

    SetLength(DigestStr, DigestSize);
    Hash.Init;
    Hash.UpdateStr(TestData);
    Hash.Final(DigestStr[0]);

    TempFile := GetTempDir + 'dcp_test_hash_large_' + Info.Name + '.tmp';
    try
      WriteStringToFile(TempFile, TestData);
      SetLength(DigestLarge, DigestSize);
      Stream := TFileStream.Create(TempFile, fmOpenRead);
      try
        Hash.Init;
        Hash.UpdateStream(Stream, Stream.Size);
        Hash.Final(DigestLarge[0]);
      finally
        Stream.Free;
      end;
      Check(Info.Name + ' UpdateStream matches UpdateStr for 10000-byte data',
        DigestsEqual(DigestStr, DigestLarge));
    finally
      if FileExists(TempFile) then DeleteFile(TempFile);
    end;
  finally
    Hash.Free;
  end;
end;

procedure TestKnownHashValues;
var
  Hash: TDCP_hash;
  Digest: array of byte;
  DigestSize: integer;
begin
  WriteLn;
  WriteLn('--- Known reference values ---');

  { MD5('abc') = 900150983cd24fb0d6963f7d28e17f72 }
  Hash := TDCP_md5.Create(nil);
  try
    DigestSize := Hash.HashSize div 8;
    SetLength(Digest, DigestSize);
    Hash.Init;
    Hash.UpdateStr('abc');
    Hash.Final(Digest[0]);
    CheckEquals('MD5("abc") matches RFC 1321 reference',
      '900150983cd24fb0d6963f7d28e17f72', DigestToHex(Digest));
  finally
    Hash.Free;
  end;

  { SHA-1('abc') = a9993e364706816aba3e25717850c2d09114d897 }
  Hash := TDCP_sha1.Create(nil);
  try
    DigestSize := Hash.HashSize div 8;
    SetLength(Digest, DigestSize);
    Hash.Init;
    Hash.UpdateStr('abc');
    Hash.Final(Digest[0]);
    CheckEquals('SHA-1("abc") matches FIPS 180 reference',
      'a9993e364706816aba3e25717850c26c9cd0d89d', DigestToHex(Digest));
  finally
    Hash.Free;
  end;

  { SHA-256('abc') = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad }
  Hash := TDCP_sha256.Create(nil);
  try
    DigestSize := Hash.HashSize div 8;
    SetLength(Digest, DigestSize);
    Hash.Init;
    Hash.UpdateStr('abc');
    Hash.Final(Digest[0]);
    CheckEquals('SHA-256("abc") matches FIPS 180 reference',
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      DigestToHex(Digest));
  finally
    Hash.Free;
  end;

  { SHA-512('abc') = ddaf35a193617aba...  }
  Hash := TDCP_sha512.Create(nil);
  try
    DigestSize := Hash.HashSize div 8;
    SetLength(Digest, DigestSize);
    Hash.Init;
    Hash.UpdateStr('abc');
    Hash.Final(Digest[0]);
    CheckEquals('SHA-512("abc") matches FIPS 180 reference',
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
      '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
      DigestToHex(Digest));
  finally
    Hash.Free;
  end;
end;

procedure TestHash(const Info: THashInfo);
var
  Hash: TDCP_hash;
  Digest1, Digest2, Digest3: array of byte;
  DigestSize: integer;
  i: integer;
  AllZero, Same, Different: boolean;
begin
  WriteLn;
  WriteLn('--- ', Info.Name, ' ---');

  { SelfTest }
  Check(Info.Name + ' SelfTest', Info.HashClass.SelfTest);

  { Create instance }
  Hash := Info.HashClass.Create(nil);
  try
    DigestSize := Hash.HashSize div 8;

    { Hash 'abc' and verify digest is non-zero and correct size }
    SetLength(Digest1, DigestSize);
    Hash.Init;
    Hash.UpdateStr('abc');
    Hash.Final(Digest1[0]);

    AllZero := True;
    for i := 0 to DigestSize - 1 do
      if Digest1[i] <> 0 then
      begin
        AllZero := False;
        Break;
      end;
    Check(Info.Name + ' digest of "abc" is non-zero', not AllZero);
    Check(Info.Name + ' digest size = ' + IntToStr(DigestSize) + ' bytes',
      DigestSize > 0);

    { Hash 'abc' again => same digest (determinism) }
    SetLength(Digest2, DigestSize);
    Hash.Init;
    Hash.UpdateStr('abc');
    Hash.Final(Digest2[0]);

    Same := True;
    for i := 0 to DigestSize - 1 do
      if Digest1[i] <> Digest2[i] then
      begin
        Same := False;
        Break;
      end;
    Check(Info.Name + ' determinism (same input => same digest)', Same);

    { Hash 'xyz' => different digest }
    SetLength(Digest3, DigestSize);
    Hash.Init;
    Hash.UpdateStr('xyz');
    Hash.Final(Digest3[0]);

    Different := False;
    for i := 0 to DigestSize - 1 do
      if Digest1[i] <> Digest3[i] then
      begin
        Different := True;
        Break;
      end;
    Check(Info.Name + ' different input => different digest', Different);

    { Burn resets Initialized to False }
    Hash.Init;
    Hash.Burn;
    Check(Info.Name + ' Burn resets Initialized', not Hash.Initialized);

    { Properties }
    Check(Info.Name + ' Algorithm non-empty', Hash.Algorithm <> '');
    Check(Info.Name + ' HashSize > 0', Hash.HashSize > 0);
    Check(Info.Name + ' Id > 0', Hash.Id > 0);
  finally
    Hash.Free;
  end;
end;

var
  i: integer;
begin
  WriteLn('=== DCPcrypt Hash Tests ===');

  for i := 0 to HashCount - 1 do
    TestHash(Hashes[i]);

  WriteLn;
  WriteLn('=== File/Stream Hashing Tests ===');
  for i := 0 to HashCount - 1 do
  begin
    WriteLn;
    WriteLn('--- ', Hashes[i].Name, ' (file) ---');
    TestHashFile(Hashes[i]);
  end;

  TestKnownHashValues;

  WriteLn;
  Halt(TestSummary);
end.
