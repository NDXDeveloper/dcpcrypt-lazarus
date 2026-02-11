{===============================================================================
  DCPcrypt v2.0.6 - Main component definitions

  SPDX-License-Identifier: MIT
  See LICENSE for full license text.

  Copyright (c) 1999-2003 David Barton (crypto@cityinthesky.co.uk)
  Copyright (c) 2006 Barko (Lazarus port)
  Copyright (c) 2009-2010 Graeme Geldenhuys
  Copyright (c) 2022 Werner Pamler
  Copyright (c) 2026 Nicolas Deoux (NDXDev@gmail.com)
===============================================================================}
unit DCPcrypt2;

{$MODE Delphi}

interface
uses
  Classes, Sysutils, DCPbase64;

//{$DEFINE DCP1COMPAT}  { DCPcrypt v1.31 compatibility mode - see documentation }

{ --- Predefined Types ------------------------------------------------------- }

type
  {$IFNDEF FPC}
  Pbyte= ^byte;
  Pword= ^word;
  Pdword= ^dword;
  Pint64= ^int64;
  dword= longword;
  Pwordarray= ^Twordarray;
  Twordarray= array[0..19383] of word;
  {$ENDIF}
  Pdwordarray= ^Tdwordarray;
  Tdwordarray= array[0..8191] of dword;

  { Callback for progress reporting during stream encryption/decryption.
    Progress is an integer percentage (0..100). }
  TProgressEvent = procedure(Sender: TObject; Progress: integer) of object;


{ --- TDCP_hash - Base Hash Class -------------------------------------------- }
{ All hash algorithm implementations derive from this class.
  Usage: call Init, then Update/UpdateStr/UpdateStream, then Final.
  The Burn method clears internal state without producing a digest. }

type
  EDCP_hash= class(Exception);  { Exception class for hash errors }
  TDCP_hash= class(TComponent)
  protected
    fInitialized: boolean;  { Whether or not the algorithm has been initialized }

    procedure DeadInt(Value: integer);   { Knudge to display vars in the object inspector   }
    procedure DeadStr(Value: string);    { Knudge to display vars in the object inspector   }
  
  private
    function _GetId: integer;
    function _GetAlgorithm: string;
    function _GetHashSize: integer; 

  public
    property Initialized: boolean
      read fInitialized;

    class function GetId: integer; virtual;
      { Get the algorithm id }
    class function GetAlgorithm: string; virtual;
      { Get the algorithm name }
    class function GetHashSize: integer; virtual;
      { Get the size of the digest produced - in bits }
    class function SelfTest: boolean; virtual;
      { Tests the implementation with several test vectors }

    procedure Init; virtual;
      { Initialize the hash algorithm }
    procedure Final(var Digest); virtual;
      { Create the final digest and clear the stored information.
        The size of the Digest var must be at least equal to the hash size }
    procedure Burn; virtual;
      { Clear any stored information with out creating the final digest }

    procedure Update(const Buffer; Size: longword); virtual;
      { Update the hash buffer with Size bytes of data from Buffer }
    procedure UpdateStream(Stream: TStream; Size: QWord);
      { Update the hash buffer with Size bytes of data from the stream }
    procedure UpdateStr(const Str: string);
      { Update the hash buffer with the string }

    destructor Destroy; override;

  published
    property Id: integer
      read _GetId write DeadInt;
    property Algorithm: string
      read _GetAlgorithm write DeadStr;
    property HashSize: integer
      read _GetHashSize write DeadInt;
  end;
  TDCP_hashclass= class of TDCP_hash;


{ --- TDCP_cipher - Base Cipher Class ---------------------------------------- }
{ Base class for all encryption components.
  Stream ciphers derive directly from this class.
  Block ciphers derive from TDCP_blockcipher (see below).
  Supports key setup via raw bytes (Init) or passphrase (InitStr).
  Provides stream and string encryption with progress reporting. }

type
  EDCP_cipher= class(Exception);  { Exception class for cipher errors }
  TDCP_cipher= class(TComponent)
  protected
    fInitialized: boolean;  { Whether or not the key setup has been done yet }

    procedure DeadInt(Value: integer);   { Knudge to display vars in the object inspector   }
    procedure DeadStr(Value: string);    { Knudge to display vars in the object inspector   }

  private
    FCancelByCallingThread: boolean;
    FOnProgressEvent: TProgressEvent;
    function _GetId: integer;
    function _GetAlgorithm: string;
    function _GetMaxKeySize: integer;

  public
    property Initialized: boolean
      read fInitialized;
    property OnProgressEvent: TProgressEvent read FOnProgressEvent write FOnProgressEvent;
    property CancelByCallingThread: boolean read FCancelByCallingThread write FCancelByCallingThread;

    class function GetId: integer; virtual;
      { Get the algorithm id }
    class function GetAlgorithm: string; virtual;
      { Get the algorithm name }
    class function GetMaxKeySize: integer; virtual;
      { Get the maximum key size (in bits) }
    class function SelfTest: boolean; virtual;
      { Tests the implementation with several test vectors }

    procedure Init(const Key; Size: longword; InitVector: pointer); virtual;
      { Do key setup based on the data in Key, size is in bits }
    procedure InitStr(const Key: string; HashType: TDCP_hashclass);
      { Do key setup based on a hash of the key string }
    procedure Burn; virtual;
      { Clear all stored key information }
    procedure Reset; virtual;
      { Reset any stored chaining information }
    procedure Encrypt(const Indata; var Outdata; Size: longword); virtual;
      { Encrypt size bytes of data and place in Outdata }
    procedure Decrypt(const Indata; var Outdata; Size: longword); virtual;
      { Decrypt size bytes of data and place in Outdata }
    function EncryptStream(InStream, OutStream: TStream; Size: Int64): longword;
      { Encrypt size bytes of data from InStream and place in OutStream }
    function DecryptStream(InStream, OutStream: TStream; Size: Int64): longword;
      { Decrypt size bytes of data from InStream and place in OutStream }
    function PartialEncryptStream(AStream: TMemoryStream; Size: longword): longword;
      { Encrypt up to EncryptLimit bytes in place on a TMemoryStream }
    function PartialDecryptStream(AStream: TMemoryStream; Size: longword): longword;
      { Decrypt up to EncryptLimit bytes in place on a TMemoryStream }
    function EncryptString(const Str: string): string; virtual;
      { Encrypt a string and return Base64 encoded }
    function DecryptString(const Str: string): string; virtual;
      { Decrypt a Base64 encoded string }

    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

  published
    property Id: integer
      read _GetId write DeadInt;
    property Algorithm: string
      read _GetAlgorithm write DeadStr;
    property MaxKeySize: integer
      read _GetMaxKeySize write DeadInt;
  end;
  TDCP_cipherclass= class of TDCP_cipher;


{ --- TDCP_blockcipher - Base Block Cipher Class ----------------------------- }
{ Extends TDCP_cipher with block cipher modes (ECB, CBC, CFB, OFB, CTR).
  The Encrypt/Decrypt methods dispatch to the mode selected by CipherMode.
  Direct mode-specific methods (EncryptCBC, EncryptCTR, etc.) are also available.
  EncryptString/DecryptString always use CFB 8-bit mode for variable-length data. }

type
  { Block cipher chaining modes:
    cmCBC      - Cipher Block Chaining (default, requires padding to block size)
    cmCFB8bit  - Cipher Feedback 8-bit (byte-level, compatible with DCPcrypt v1.x)
    cmCFBblock - Cipher Feedback block-level (faster than CFB 8-bit)
    cmOFB      - Output Feedback (turns block cipher into stream cipher)
    cmCTR      - Counter mode (parallelizable, turns block cipher into stream cipher) }
  TDCP_ciphermode= (cmCBC, cmCFB8bit, cmCFBblock, cmOFB, cmCTR);
  EDCP_blockcipher= class(EDCP_cipher);  { Exception class for block cipher errors }
  TDCP_blockcipher= class(TDCP_cipher)
  protected
    fCipherMode: TDCP_ciphermode;  { The cipher mode the encrypt method uses  }

    procedure InitKey(const Key; Size: longword); virtual;

  private
    function _GetBlockSize: integer;

  public
    class function GetBlockSize: integer; virtual;
      { Get the block size of the cipher (in bits) }

    procedure SetIV(const Value); virtual;
      { Sets the IV to Value and performs a reset }
    procedure GetIV(var Value); virtual;
      { Returns the current chaining information, not the actual IV }

    procedure Encrypt(const Indata; var Outdata; Size: longword); override;
      { Encrypt size bytes of data and place in Outdata using CipherMode }
    procedure Decrypt(const Indata; var Outdata; Size: longword); override;
      { Decrypt size bytes of data and place in Outdata using CipherMode }
    function EncryptString(const Str: string): string; override;
      { Encrypt a string and return Base64 encoded }
    function DecryptString(const Str: string): string; override;
      { Decrypt a Base64 encoded string }
    procedure EncryptECB(const Indata; var Outdata); virtual; 
      { Encrypt a block of data using the ECB method of encryption }
    procedure DecryptECB(const Indata; var Outdata); virtual; 
      { Decrypt a block of data using the ECB method of decryption }
    procedure EncryptCBC(const Indata; var Outdata; Size: longword); virtual; 
      { Encrypt size bytes of data using the CBC method of encryption }
    procedure DecryptCBC(const Indata; var Outdata; Size: longword); virtual; 
      { Decrypt size bytes of data using the CBC method of decryption }
    procedure EncryptCFB8bit(const Indata; var Outdata; Size: longword); virtual; 
      { Encrypt size bytes of data using the CFB (8 bit) method of encryption }
    procedure DecryptCFB8bit(const Indata; var Outdata; Size: longword); virtual; 
      { Decrypt size bytes of data using the CFB (8 bit) method of decryption }
    procedure EncryptCFBblock(const Indata; var Outdata; Size: longword); virtual; 
      { Encrypt size bytes of data using the CFB (block) method of encryption }
    procedure DecryptCFBblock(const Indata; var Outdata; Size: longword); virtual; 
      { Decrypt size bytes of data using the CFB (block) method of decryption }
    procedure EncryptOFB(const Indata; var Outdata; Size: longword); virtual; 
      { Encrypt size bytes of data using the OFB method of encryption }
    procedure DecryptOFB(const Indata; var Outdata; Size: longword); virtual; 
      { Decrypt size bytes of data using the OFB method of decryption }
    procedure EncryptCTR(const Indata; var Outdata; Size: longword); virtual; 
      { Encrypt size bytes of data using the CTR method of encryption }
    procedure DecryptCTR(const Indata; var Outdata; Size: longword); virtual;
      { Decrypt size bytes of data using the CTR method of decryption }

    constructor Create(AOwner: TComponent); override;

  published
    property BlockSize: integer
      read _GetBlockSize write DeadInt;
    property CipherMode: TDCP_ciphermode
      read fCipherMode write fCipherMode default cmCBC;
  end;
  TDCP_blockcipherclass= class of TDCP_blockcipher;


{ --- Helper Functions ------------------------------------------------------- }

{ XOR Size bytes of InData2 into InData1 (byte-by-byte). }
procedure XorBlock(var InData1, InData2; Size: longword);
{ XOR Size bytes of InData2 into InData1 (optimized: 32-bit words, then remaining bytes). }
procedure XorBlockEx(var InData1, InData2; Size: longword);
{ Wrapper around FillChar that suppresses compiler hints for var/out mismatch. }
procedure dcpFillChar(out x; count: SizeInt; Value: Byte); overload;
procedure dcpFillChar(out x; count: SizeInt; Value: Char); overload;
{ Fill a memory block with zeros. }
procedure ZeroMemory(Destination: Pointer; Length: PtrUInt);



implementation

{$Q-}{$R-}

const
  EncryptBufSize = 1024 * 1024 * 8;  { 8 MB - chunk size for stream encryption/decryption }
  EncryptLimit = 16 * 1024;           { 16 KB - max bytes for PartialEncrypt/DecryptStream }


{ --- TDCP_hash Implementation ----------------------------------------------- }

procedure TDCP_hash.DeadInt(Value: integer);
begin
end;

procedure TDCP_hash.DeadStr(Value: string);
begin
end;

function TDCP_hash._GetId: integer;
begin
  Result:= GetId;
end;

function TDCP_hash._GetAlgorithm: string;
begin
  Result:= GetAlgorithm;
end;

function TDCP_hash._GetHashSize: integer;
begin
  Result:= GetHashSize;
end; 

class function TDCP_hash.GetId: integer;
begin
  Result:= -1;
end;

class function TDCP_hash.GetAlgorithm: string;
begin
  Result:= '';
end;

class function TDCP_hash.GetHashSize: integer;
begin
  Result:= -1;
end;

class function TDCP_hash.SelfTest: boolean;
begin
  Result:= false;
end;

procedure TDCP_hash.Init;
begin
end;

procedure TDCP_hash.Final(var Digest);
begin
end;

procedure TDCP_hash.Burn;
begin
end;

procedure TDCP_hash.Update(const Buffer; Size: longword);
begin
end;

procedure TDCP_hash.UpdateStream(Stream: TStream; Size: QWord);
var
  Buffer: array[0..8191] of byte;
  i, read: integer;
begin
  dcpFillChar(Buffer, SizeOf(Buffer), 0);
  for i:= 1 to (Size div Sizeof(Buffer)) do
  begin
    read:= Stream.Read(Buffer,Sizeof(Buffer));
    Update(Buffer,read);
  end;
  if (Size mod Sizeof(Buffer))<> 0 then
  begin
    read:= Stream.Read(Buffer,Size mod Sizeof(Buffer));
    Update(Buffer,read);
  end;
end;

procedure TDCP_hash.UpdateStr(const Str: string);
begin
  Update(Str[1],Length(Str));
end;

destructor TDCP_hash.Destroy;
begin
  if fInitialized then
    Burn;
  inherited Destroy;
end;


{ --- TDCP_cipher Implementation --------------------------------------------- }

procedure TDCP_cipher.DeadInt(Value: integer);
begin
end;

procedure TDCP_cipher.DeadStr(Value: string);
begin
end;

function TDCP_cipher._GetId: integer;
begin
  Result:= GetId;
end;

function TDCP_cipher._GetAlgorithm: string;
begin
  Result:= GetAlgorithm;
end;

function TDCP_cipher._GetMaxKeySize: integer;
begin
  Result:= GetMaxKeySize;
end; 

class function TDCP_cipher.GetId: integer;
begin
  Result:= -1;
end;

class function TDCP_cipher.GetAlgorithm: string;
begin
  Result:= '';
end;

class function TDCP_cipher.GetMaxKeySize: integer;
begin
  Result:= -1;
end;

class function TDCP_cipher.SelfTest: boolean;
begin
  Result:= false;
end;

procedure TDCP_cipher.Init(const Key; Size: longword; InitVector: pointer);
begin
  if fInitialized then
    Burn;
  if (Size <= 0) or ((Size and 3)<> 0) or (Size> longword(GetMaxKeySize)) then
    raise EDCP_cipher.Create('Invalid key size')
  else
    fInitialized:= true;
end;

{ Derives an encryption key from a passphrase by hashing it with HashType.
  If the hash digest is larger than MaxKeySize, only MaxKeySize bits are used.
  The digest buffer is overwritten before being freed (key material cleanup). }
procedure TDCP_cipher.InitStr(const Key: string; HashType: TDCP_hashclass);
var
  Hash: TDCP_hash;
  Digest: pointer;
begin
  if fInitialized then
    Burn;
  try
    GetMem(Digest,HashType.GetHashSize div 8);
    Hash:= HashType.Create(Self);
    Hash.Init;
    Hash.UpdateStr(Key);
    Hash.Final(Digest^);
    Hash.Free;
    if MaxKeySize< HashType.GetHashSize then
    begin
      Init(Digest^,MaxKeySize,nil);
    end
    else
    begin
      Init(Digest^,HashType.GetHashSize,nil);
    end;
    FillChar(Digest^,HashType.GetHashSize div 8,$FF);
    FreeMem(Digest);
  except
    raise EDCP_cipher.Create('Unable to allocate sufficient memory for hash digest');
  end;
end;

procedure TDCP_cipher.Burn;
begin
  fInitialized:= false;
end;

procedure TDCP_cipher.Reset;
begin
end;

procedure TDCP_cipher.Encrypt(const Indata; var Outdata; Size: longword);
begin
end;

procedure TDCP_cipher.Decrypt(const Indata; var Outdata; Size: longword);
begin
end;

{ Encrypts Size bytes from InStream to OutStream in chunks of EncryptBufSize.
  Returns the total number of bytes processed. Fires OnProgressEvent if assigned.
  Set CancelByCallingThread to True from another thread to abort early. }
function TDCP_cipher.EncryptStream(InStream, OutStream: TStream; Size: Int64): longword;
var
  Buffer: array of byte;
  BufSize: longword;
  Read: longword;
  Remaining: Int64;
  Progress: integer;
begin
  if Size <= EncryptBufSize then
    BufSize:= Size
  else
    BufSize:= EncryptBufSize;
  SetLength(Buffer, BufSize);
  dcpFillChar(Buffer[0], BufSize, 0);
  Result:= 0;
  FCancelByCallingThread:= false;
  Remaining:= Size;
  while (Remaining > 0) and (not FCancelByCallingThread) do
  begin
    if Remaining > BufSize then
      Read:= InStream.Read(Buffer[0], BufSize)
    else
      Read:= InStream.Read(Buffer[0], Remaining);
    if Read = 0 then
      Break;
    Inc(Result, Read);
    Encrypt(Buffer[0], Buffer[0], Read);
    OutStream.Write(Buffer[0], Read);
    Dec(Remaining, Read);
    if Assigned(FOnProgressEvent) and (Size > 0) then
    begin
      Progress:= Round((Size - Remaining) * 100.0 / Size);
      FOnProgressEvent(Self, Progress);
    end;
  end;
  SetLength(Buffer, 0);
end;

{ Decrypts Size bytes from InStream to OutStream in chunks of EncryptBufSize.
  Returns the total number of bytes processed. Fires OnProgressEvent if assigned.
  Set CancelByCallingThread to True from another thread to abort early. }
function TDCP_cipher.DecryptStream(InStream, OutStream: TStream; Size: Int64): longword;
var
  Buffer: array of byte;
  BufSize: longword;
  Read: longword;
  Remaining: Int64;
  Progress: integer;
begin
  if Size <= EncryptBufSize then
    BufSize:= Size
  else
    BufSize:= EncryptBufSize;
  SetLength(Buffer, BufSize);
  dcpFillChar(Buffer[0], BufSize, 0);
  Result:= 0;
  FCancelByCallingThread:= false;
  Remaining:= Size;
  while (Remaining > 0) and (not FCancelByCallingThread) do
  begin
    if Remaining > BufSize then
      Read:= InStream.Read(Buffer[0], BufSize)
    else
      Read:= InStream.Read(Buffer[0], Remaining);
    if Read = 0 then
      Break;
    Inc(Result, Read);
    Decrypt(Buffer[0], Buffer[0], Read);
    OutStream.Write(Buffer[0], Read);
    Dec(Remaining, Read);
    if Assigned(FOnProgressEvent) and (Size > 0) then
    begin
      Progress:= Round((Size - Remaining) * 100.0 / Size);
      FOnProgressEvent(Self, Progress);
    end;
  end;
  SetLength(Buffer, 0);
end;

{ Encrypts data in-place on a TMemoryStream starting at the current position.
  At most EncryptLimit (16 KB) bytes are processed regardless of Size.
  Returns the actual number of bytes encrypted. }
function TDCP_cipher.PartialEncryptStream(AStream: TMemoryStream; Size: longword): longword;
var
  p: PByte;
  ActualSize: longword;
begin
  if Size > EncryptLimit then
    ActualSize:= EncryptLimit
  else
    ActualSize:= Size;
  if ActualSize > longword(AStream.Size - AStream.Position) then
    ActualSize:= longword(AStream.Size - AStream.Position);
  p:= PByte(AStream.Memory) + AStream.Position;
  Encrypt(p^, p^, ActualSize);
  Result:= ActualSize;
end;

{ Decrypts data in-place on a TMemoryStream starting at the current position.
  At most EncryptLimit (16 KB) bytes are processed regardless of Size.
  Returns the actual number of bytes decrypted. }
function TDCP_cipher.PartialDecryptStream(AStream: TMemoryStream; Size: longword): longword;
var
  p: PByte;
  ActualSize: longword;
begin
  if Size > EncryptLimit then
    ActualSize:= EncryptLimit
  else
    ActualSize:= Size;
  if ActualSize > longword(AStream.Size - AStream.Position) then
    ActualSize:= longword(AStream.Size - AStream.Position);
  p:= PByte(AStream.Memory) + AStream.Position;
  Decrypt(p^, p^, ActualSize);
  Result:= ActualSize;
end;

function TDCP_cipher.EncryptString(const Str: string): string;
begin
  SetLength(Result,Length(Str));
  Encrypt(Str[1],Result[1],Length(Str));
  Result:= Base64EncodeStr(Result);
end;

function TDCP_cipher.DecryptString(const Str: string): string;
begin
  Result:= Base64DecodeStr(Str);
  Decrypt(Result[1],Result[1],Length(Result));
end;

constructor TDCP_cipher.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  Burn;
end;

destructor TDCP_cipher.Destroy;
begin
  if fInitialized then
    Burn;
  inherited Destroy;
end;


{ --- TDCP_blockcipher Implementation ---------------------------------------- }

procedure TDCP_blockcipher.InitKey(const Key; Size: longword);
begin
end;

function TDCP_blockcipher._GetBlockSize: integer;
begin
  Result:= GetBlockSize;
end;

class function TDCP_blockcipher.GetBlockSize: integer;
begin
  Result:= -1;
end;

procedure TDCP_blockcipher.SetIV(const Value);
begin
end;

procedure TDCP_blockcipher.GetIV(var Value);
begin
end;

{ Dispatches to the mode-specific encryption method based on CipherMode. }
procedure TDCP_blockcipher.Encrypt(const Indata; var Outdata; Size: longword);
begin
  case fCipherMode of
    cmCBC: EncryptCBC(Indata,Outdata,Size);
    cmCFB8bit: EncryptCFB8bit(Indata,Outdata,Size);
    cmCFBblock: EncryptCFBblock(Indata,Outdata,Size);
    cmOFB: EncryptOFB(Indata,Outdata,Size);
    cmCTR: EncryptCTR(Indata,Outdata,Size);
  end;
end;

{ Block cipher string encryption always uses CFB 8-bit mode (not CipherMode)
  to handle arbitrary-length strings without padding. Result is Base64 encoded. }
function TDCP_blockcipher.EncryptString(const Str: string): string;
begin
  SetLength(Result,Length(Str));
  EncryptCFB8bit(Str[1],Result[1],Length(Str));
  Result:= Base64EncodeStr(Result);
end;

{ Decodes the Base64 string, then decrypts using CFB 8-bit mode. }
function TDCP_blockcipher.DecryptString(const Str: string): string;
begin
  Result:= Base64DecodeStr(Str);
  DecryptCFB8bit(Result[1],Result[1],Length(Result));
end;

{ Dispatches to the mode-specific decryption method based on CipherMode. }
procedure TDCP_blockcipher.Decrypt(const Indata; var Outdata; Size: longword);
begin
  case fCipherMode of
    cmCBC: DecryptCBC(Indata,Outdata,Size);
    cmCFB8bit: DecryptCFB8bit(Indata,Outdata,Size);
    cmCFBblock: DecryptCFBblock(Indata,Outdata,Size);
    cmOFB: DecryptOFB(Indata,Outdata,Size);
    cmCTR: DecryptCTR(Indata,Outdata,Size);
  end;
end;

procedure TDCP_blockcipher.EncryptECB(const Indata; var Outdata);
begin
end;

procedure TDCP_blockcipher.DecryptECB(const Indata; var Outdata);
begin
end;

procedure TDCP_blockcipher.EncryptCBC(const Indata; var Outdata; Size: longword);
begin
end;

procedure TDCP_blockcipher.DecryptCBC(const Indata; var Outdata; Size: longword);
begin
end;

procedure TDCP_blockcipher.EncryptCFB8bit(const Indata; var Outdata; Size: longword);
begin
end;

procedure TDCP_blockcipher.DecryptCFB8bit(const Indata; var Outdata; Size: longword);
begin
end;

procedure TDCP_blockcipher.EncryptCFBblock(const Indata; var Outdata; Size: longword);
begin
end;

procedure TDCP_blockcipher.DecryptCFBblock(const Indata; var Outdata; Size: longword);
begin
end;

procedure TDCP_blockcipher.EncryptOFB(const Indata; var Outdata; Size: longword);
begin
end;

procedure TDCP_blockcipher.DecryptOFB(const Indata; var Outdata; Size: longword);
begin
end;

procedure TDCP_blockcipher.EncryptCTR(const Indata; var Outdata; Size: longword);
begin
end;

procedure TDCP_blockcipher.DecryptCTR(const Indata; var Outdata; Size: longword);
begin
end;

constructor TDCP_blockcipher.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  fCipherMode:= cmCBC;
end;


{ --- Helper Functions ------------------------------------------------------- }
procedure XorBlock(var InData1, InData2; Size: longword);
var
  b1: PByteArray;
  b2: PByteArray;
  i: longword;
begin
  b1 := @InData1;
  b2 := @InData2;
  for i := 0 to size-1 do
    b1[i] := b1[i] xor b2[i];
end;

procedure dcpFillChar(out x; count: SizeInt; Value: Byte);
begin
  {$HINTS OFF}
  FillChar(x, count, value);
  {$HINTS ON}
end;

procedure ZeroMemory(Destination: Pointer; Length: PtrUInt);
begin
  FillChar(Destination^, Length, 0);
end;

procedure dcpFillChar(out x; count: SizeInt; Value: Char);
begin
  {$HINTS OFF}
  FillChar(x, count, Value);
  {$HINTS ON}
end;

{ XOR using 32-bit words for bulk, then byte-by-byte for remainder. }
procedure XorBlockEx(var InData1, InData2; Size: longword);
var
  l1: PIntegerArray;
  l2: PIntegerArray;
  b1: PByteArray;
  b2: PByteArray;
  i: integer;
  c: integer;
begin
  l1 := @inData1;
  l2 := @inData2;
  for i := 0 to size div sizeof(LongWord)-1 do
    l1[i] := l1[i] xor l2[i];

  // the rest of the buffer (3 bytes)
  c := size mod sizeof(longWord);
  if c > 0 then begin
    b1 := @InData1;
    b2 := @InData2;
    for i := (size-c) to size-1 do
      b1[i] := b1[i] xor b2[i];
  end;
end;

end.

