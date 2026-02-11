{===============================================================================
  DCPcrypt v2.0.6 - Component registration for DCPcrypt

  SPDX-License-Identifier: MIT
  See LICENSE for full license text.

  Copyright (c) 1999-2003 David Barton (crypto@cityinthesky.co.uk)
  Copyright (c) 2006 Barko (Lazarus port)
  Copyright (c) 2009-2010 Graeme Geldenhuys
  Copyright (c) 2022 Werner Pamler
  Copyright (c) 2026 Nicolas Deoux (NDXDev@gmail.com)
===============================================================================}
unit DCPreg;

{$MODE Delphi}

interface
uses
  LResources,Classes;

{ Registers all DCPcrypt cipher and hash components on the Lazarus IDE palette. }
procedure Register;

implementation

uses
  DCPcrypt2, DCPblockciphers, DCPconst, DCPblowfish, DCPcast128, DCPcast256,
  DCPdes, DCPgost, DCPice, DCPidea, DCPmars, DCPmisty1, DCPrc2, DCPrc4, DCPrc5,
  DCPrc6, DCPrijndael, DCPserpent, DCPtea, DCPtwofish,
  DCPhaval, DCPmd4, DCPmd5, DCPripemd128, DCPripemd160, DCPsha1, DCPsha256,
  DCPsha512, DCPtiger;

procedure Register;
begin
  { Register 19 ciphers on the 'DCPciphers' palette page.
    Note: TDCP_gost is commented out due to uncertain standard compliance. }
  RegisterComponents(DCPcipherpage,[TDCP_blowfish,TDCP_cast128,TDCP_cast256,
    TDCP_des,TDCP_3des,{TDCP_gost,}TDCP_ice,TDCP_thinice,TDCP_ice2,TDCP_idea,
    TDCP_mars,TDCP_misty1,TDCP_rc2,TDCP_rc4,TDCP_rc5,TDCP_rc6,TDCP_rijndael,
    TDCP_serpent,TDCP_tea,TDCP_twofish]);
  { Register 10 hashes on the 'DCPhashes' palette page. }
  RegisterComponents(DCPhashpage,[TDCP_haval,TDCP_md4,TDCP_md5,TDCP_ripemd128,
    TDCP_ripemd160,TDCP_sha1,TDCP_sha256,TDCP_sha384,TDCP_sha512,TDCP_tiger]);
end;

initialization
  { Load component icons for the IDE palette }
{$I DCPciphers.lrs}
{$I DCPhashes.lrs}
end.
