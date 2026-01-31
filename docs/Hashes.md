# Hash Algorithms - TDCP_hash

**DCPcrypt Cryptographic Component Library v2.0.5**
Lazarus / Free Pascal edition

All hashes are derived from the TDCP_hash component. It provides a range of functions to allow the hashing of virtually every type of data.

Functions available are:

```
property Initialized: boolean;
property Id: integer;
property Algorithm: string;
property HashSize: integer;

class function SelfTest: boolean;

procedure Init;
procedure Final(var Digest);
procedure Burn;

procedure Update(const Buffer; Size: longword);
procedure UpdateStream(Stream: TStream; Size: QWord);
procedure UpdateStr(const Str: string);
```

Example usage:

- [Example 1](#example-1---file-hashing) - File hashing.

---

## Function descriptions

### <a id="initialized"></a>`property Initialized: boolean`

This is set to true after [Init](#init) has been called.

### <a id="id"></a>`property Id: integer`

Every algorithm I implement gets given a unique ID number so that if I use several different algorithms within a program I can determine which one was used. This is a purely arbitrary numbering system.

### <a id="algorithm"></a>`property Algorithm: string`

This is the name of the algorithm implemented in the component.

### <a id="hashsize"></a>`property HashSize: integer`

This is the size of the output of the hash algorithm in BITS.

### <a id="selftest"></a>`class function SelfTest: boolean`

In order to test whether the implementations have all been compiled correctly you can call the SelfTest function. This compares the results of several hash operations with known results for the algorithms (so called test vectors). If all the tests are passed then true is returned. If ANY of the tests are failed then false is returned. You may want to run this function for all the components when you first install the DCPcrypt package and again if you modify any of the source files, you don't need to run this everytime your program is run. Note: this only performs a selection of tests, it is not exhaustive.

### <a id="init"></a>`procedure Init`

Call this procedure to initialize the hash algorithm, this must be called before using the [Update](#update) procedure.

### <a id="final"></a>`procedure Final(var Digest)`

This procedure returns the final message digest (hash) in Digest. This variable must be the same size as the hash size. This procedure also calls [Burn](#burn) to clear any stored information.

### <a id="burn"></a>`procedure Burn`

Call this procedure if you want to abort the hashing operation (normally [Final](#final) is used). This clears all information stored within the hash. Before the hash can be used again [Init](#init) must be called.

### <a id="update"></a>`procedure Update(const Buffer; Size: longword)`

This procedure hashes Size bytes of Buffer. To get the hash result call [Final](#final).

Update example:

```pascal
procedure HashBuffer(const Buffer; Size: longint; var Output);
var
  Hash: TDCP_ripemd160;
begin
  Hash:= TDCP_ripemd160.Create(nil);
  Hash.Init;
  Hash.Update(Buffer,Size);
  Hash.Final(Output);
  Hash.Free;
end;
```

### <a id="updatestream"></a>`procedure UpdateStream(Stream: TStream; Size: QWord)`

This procedure hashes Size bytes from Stream. The Size parameter is QWord (unsigned 64-bit) to support files larger than 4 GB. To get the hash result call [Final](#final).

### <a id="updatestr"></a>`procedure UpdateStr(const Str: string)`

This procedure hashes the string Str. To get the hash result call [Final](#final).

---

## Example 1 - File hashing

This example shows how you can hash the contents of a file.

```pascal
procedure TForm1.Button1Click(Sender: TObject);
var
  Hash: TDCP_ripemd160;
  Digest: array[0..19] of byte;  // RipeMD-160 produces a 160bit digest (20bytes)
  Source: TFileStream;
  i: integer;
  s: string;
begin
  Source:= nil;
  try
    Source:= TFileStream.Create(Edit1.Text,fmOpenRead);  // open the file specified by Edit1
  except
    MessageDlg('Unable to open file',mtError,[mbOK],0);
  end;
  if Source <> nil then
  begin
    Hash:= TDCP_ripemd160.Create(Self);          // create the hash
    Hash.Init;                                   // initialize it
    Hash.UpdateStream(Source,Source.Size);       // hash the stream contents
    Hash.Final(Digest);                          // produce the digest
    Source.Free;
    s:= '';
    for i:= 0 to 19 do
      s:= s + IntToHex(Digest[i],2);
    Edit2.Text:= s;                              // display the digest
  end;
end;
```

---

[Index](README.md) | [Ciphers](Ciphers.md) | [Block Ciphers](BlockCiphers.md)

---

*DCPcrypt is copyrighted by its respective authors.*
*Released under the MIT license. All trademarks are property of their respective owners.*
