{******************************************************************************}
{* test_base64.lpr - Functional tests for DCPcrypt Base64 encoding/decoding  *}
{******************************************************************************}
program test_base64;

{$MODE Delphi}

uses
  SysUtils,
  DCPbase64,
  testutils;

procedure TestStringRoundtrips;
var
  Encoded, Decoded: string;
  LongStr: string;
  i: integer;
begin
  WriteLn;
  WriteLn('--- String roundtrips ---');

  { Empty string }
  Encoded := Base64EncodeStr('');
  Decoded := Base64DecodeStr(Encoded);
  CheckEquals('Empty string roundtrip', '', Decoded);

  { "Hello" roundtrip }
  Encoded := Base64EncodeStr('Hello');
  Decoded := Base64DecodeStr(Encoded);
  CheckEquals('Hello roundtrip', 'Hello', Decoded);

  { Known value: "Man" => "TWFu" (RFC 4648) }
  Encoded := Base64EncodeStr('Man');
  CheckEquals('Encode "Man" = "TWFu"', 'TWFu', Encoded);
  Decoded := Base64DecodeStr('TWFu');
  CheckEquals('Decode "TWFu" = "Man"', 'Man', Decoded);

  { Known value: "Ma" => "TWE=" (1 pad) }
  Encoded := Base64EncodeStr('Ma');
  CheckEquals('Encode "Ma" = "TWE="', 'TWE=', Encoded);

  { Known value: "M" => "TQ==" (2 pads) }
  Encoded := Base64EncodeStr('M');
  CheckEquals('Encode "M" = "TQ=="', 'TQ==', Encoded);

  { Long string roundtrip (1000 chars) }
  LongStr := '';
  for i := 1 to 1000 do
    LongStr := LongStr + Chr(32 + (i mod 95)); { printable ASCII }
  Encoded := Base64EncodeStr(LongStr);
  Decoded := Base64DecodeStr(Encoded);
  CheckEquals('Long string (1000 chars) roundtrip', LongStr, Decoded);
end;

procedure TestBinaryData;
var
  InputBuf, OutputBuf, DecodedBuf: array[0..255] of byte;
  EncSize, DecSize: longint;
  EncodedStr: string;
  i: integer;
  Match: boolean;
begin
  WriteLn;
  WriteLn('--- Binary data ---');

  { Fill buffer with all byte values 0..255 }
  for i := 0 to 255 do
    InputBuf[i] := Byte(i);

  { Encode via raw API }
  SetLength(EncodedStr, ((256 + 2) div 3) * 4);
  EncSize := Base64Encode(@InputBuf[0], @EncodedStr[1], 256);
  Check('Binary encode returns correct size', EncSize = ((256 + 2) div 3) * 4);

  { Decode via raw API }
  FillChar(DecodedBuf, SizeOf(DecodedBuf), 0);
  DecSize := Base64Decode(@EncodedStr[1], @DecodedBuf[0], EncSize);
  Check('Binary decode returns correct size', DecSize = 256);

  Match := True;
  for i := 0 to 255 do
    if InputBuf[i] <> DecodedBuf[i] then
    begin
      Match := False;
      Break;
    end;
  Check('Binary data roundtrip (bytes 0..255)', Match);
end;

procedure TestStringBinaryRoundtrip;
var
  InputStr, Encoded, Decoded: string;
  i: integer;
begin
  WriteLn;
  WriteLn('--- String with binary content ---');

  { Create string with bytes 1..255 (avoid 0 in Pascal strings) }
  SetLength(InputStr, 255);
  for i := 1 to 255 do
    InputStr[i] := Chr(i);

  Encoded := Base64EncodeStr(InputStr);
  Decoded := Base64DecodeStr(Encoded);
  CheckEquals('Binary string (bytes 1..255) roundtrip', InputStr, Decoded);
end;

begin
  WriteLn('=== DCPcrypt Base64 Tests ===');

  TestStringRoundtrips;
  TestBinaryData;
  TestStringBinaryRoundtrip;

  WriteLn;
  Halt(TestSummary);
end.
