{===============================================================================
  DCPcrypt v2.0.6 - A Base64 encoding/decoding unit

  SPDX-License-Identifier: MIT
  See LICENSE for full license text.

  Copyright (c) 1999-2003 David Barton (crypto@cityinthesky.co.uk)
  Copyright (c) 2006 Barko (Lazarus port)
  Copyright (c) 2009-2010 Graeme Geldenhuys
  Copyright (c) 2022 Werner Pamler
  Copyright (c) 2026 Nicolas Deoux (NDXDev@gmail.com)
===============================================================================}
unit DCPbase64;

{$MODE Delphi}

interface
uses
  Sysutils;

{ --- Public Functions ------------------------------------------------------- }

{ Encode a string to Base64 format. }
function Base64EncodeStr(const Value: string): string;
{ Decode a Base64 string back to its original value. }
function Base64DecodeStr(const Value: string): string;
{ Encode Size bytes from pInput into pOutput (RFC 4648).
  Output buffer must be at least ((Size + 2) div 3) * 4 bytes.
  Returns the number of bytes written to pOutput. }
function Base64Encode(pInput: pointer; pOutput: pointer; Size: longint): longint;
{ Decode Size bytes of Base64 data from pInput into pOutput.
  Output buffer must be at least (Size div 4) * 3 bytes.
  Returns the actual number of decoded bytes (handles '=' padding). }
function Base64Decode(pInput: pointer; pOutput: pointer; Size: longint): longint;


implementation
{$Q-}{$R-}

const
  { Base64 alphabet: A-Z (0-25), a-z (26-51), 0-9 (52-61), + (62), / (63) }
  B64: array[0..63] of byte= (65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,
    81,82,83,84,85,86,87,88,89,90,97,98,99,100,101,102,103,104,105,106,107,108,
    109,110,111,112,113,114,115,116,117,118,119,120,121,122,48,49,50,51,52,53,
    54,55,56,57,43,47);

function Base64Encode(pInput: pointer; pOutput: pointer; Size: longint): longint;
var
  i, iptr, optr: integer;
  Input, Output: PByteArray;
begin
  Input:= PByteArray(pInput); Output:= PByteArray(pOutput);
  iptr:= 0; optr:= 0;
  for i:= 1 to (Size div 3) do
  begin
    Output^[optr+0]:= B64[Input^[iptr] shr 2];
    Output^[optr+1]:= B64[((Input^[iptr] and 3) shl 4) + (Input^[iptr+1] shr 4)];
    Output^[optr+2]:= B64[((Input^[iptr+1] and 15) shl 2) + (Input^[iptr+2] shr 6)];
    Output^[optr+3]:= B64[Input^[iptr+2] and 63];
    Inc(optr,4); Inc(iptr,3);
  end;
  case (Size mod 3) of
    1: begin
         Output^[optr+0]:= B64[Input^[iptr] shr 2];
         Output^[optr+1]:= B64[(Input^[iptr] and 3) shl 4];
         Output^[optr+2]:= byte('=');
         Output^[optr+3]:= byte('=');
       end;
    2: begin
         Output^[optr+0]:= B64[Input^[iptr] shr 2];
         Output^[optr+1]:= B64[((Input^[iptr] and 3) shl 4) + (Input^[iptr+1] shr 4)];
         Output^[optr+2]:= B64[(Input^[iptr+1] and 15) shl 2];
         Output^[optr+3]:= byte('=');
       end;
  end;
  Result:= ((Size+2) div 3) * 4;
end;

function Base64EncodeStr(const Value: string): string;
begin
  SetLength(Result,((Length(Value)+2) div 3) * 4);
  Base64Encode(@Value[1],@Result[1],Length(Value));
end;

function Base64Decode(pInput: pointer; pOutput: pointer; Size: longint): longint;
var
  i, j, iptr, optr: integer;
  Temp: array[0..3] of byte;
  Input, Output: PByteArray;
begin
  Input:= PByteArray(pInput); Output:= PByteArray(pOutput);
  iptr:= 0; optr:= 0;
  Result:= 0;
  for i:= 1 to (Size div 4) do
  begin
    for j:= 0 to 3 do
    begin
      case Input^[iptr] of
        65..90 : Temp[j]:= Input^[iptr] - Ord('A');
        97..122: Temp[j]:= Input^[iptr] - Ord('a') + 26;
        48..57 : Temp[j]:= Input^[iptr] - Ord('0') + 52;
        43     : Temp[j]:= 62;
        47     : Temp[j]:= 63;
        61     : Temp[j]:= $FF;
      end;
      Inc(iptr);
    end;
    Output^[optr]:= (Temp[0] shl 2) or (Temp[1] shr 4);
    Result:= optr+1;
    if (Temp[2]<> $FF) and (Temp[3]= $FF) then
    begin
      Output^[optr+1]:= (Temp[1] shl 4) or (Temp[2] shr 2);
      Result:= optr+2;
      Inc(optr)
    end
    else if (Temp[2]<> $FF) then
    begin
      Output^[optr+1]:= (Temp[1] shl 4) or (Temp[2] shr 2);
      Output^[optr+2]:= (Temp[2] shl 6) or  Temp[3];
      Result:= optr+3;
      Inc(optr,2);
    end;
    Inc(optr);
  end;
end;

function Base64DecodeStr(const Value: string): string;
begin
  SetLength(Result,(Length(Value) div 4) * 3);
  SetLength(Result,Base64Decode(@Value[1],@Result[1],Length(Value)));
end;


end.
