{******************************************************************************}
{* test_hashes.lpr - Functional tests for all DCPcrypt hash algorithms       *}
{******************************************************************************}
program test_hashes;

{$MODE Delphi}

uses
  SysUtils,
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
  Halt(TestSummary);
end.
