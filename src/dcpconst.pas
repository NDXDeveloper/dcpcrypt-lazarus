{===============================================================================
  DCPcrypt v2.0.6 - Constants for use with DCPcrypt

  SPDX-License-Identifier: MIT
  See LICENSE for full license text.

  Copyright (c) 1999-2003 David Barton (crypto@cityinthesky.co.uk)
  Copyright (c) 2006 Barko (Lazarus port)
  Copyright (c) 2009-2010 Graeme Geldenhuys
  Copyright (c) 2022 Werner Pamler
  Copyright (c) 2026 Nicolas Deoux (NDXDev@gmail.com)
===============================================================================}
unit DCPconst;

{$MODE Delphi}

interface

{ --- Constants -------------------------------------------------------------- }

const
  { Lazarus component palette page names }
  DCPcipherpage     = 'DCPciphers';
  DCPhashpage       = 'DCPhashes';

  { Unique algorithm identifiers returned by GetId.
    Each cipher and hash has a fixed ID used for component registration
    and algorithm lookup. These values must remain stable across versions. }
  DCP_rc2           =  1;   { RC2 block cipher }
  DCP_sha1          =  2;   { SHA-1 hash }
  DCP_rc5           =  3;   { RC5 block cipher }
  DCP_rc6           =  4;   { RC6 block cipher }
  DCP_blowfish      =  5;   { Blowfish block cipher }
  DCP_twofish       =  6;   { Twofish block cipher }
  DCP_cast128       =  7;   { Cast128 block cipher }
  DCP_gost          =  8;   { Gost block cipher }
  DCP_rijndael      =  9;   { Rijndael (AES) block cipher }
  DCP_ripemd160     = 10;   { RipeMD-160 hash }
  DCP_misty1        = 11;   { Misty1 block cipher }
  DCP_idea          = 12;   { IDEA block cipher }
  DCP_mars          = 13;   { Mars block cipher }
  DCP_haval         = 14;   { Haval hash }
  DCP_cast256       = 15;   { Cast256 block cipher }
  DCP_md5           = 16;   { MD5 hash }
  DCP_md4           = 17;   { MD4 hash }
  DCP_tiger         = 18;   { Tiger hash }
  DCP_rc4           = 19;   { RC4 stream cipher }
  DCP_ice           = 20;   { Ice block cipher }
  DCP_thinice       = 21;   { Thin Ice block cipher }
  DCP_ice2          = 22;   { Ice2 block cipher }
  DCP_des           = 23;   { DES block cipher }
  DCP_3des          = 24;   { Triple DES block cipher }
  DCP_tea           = 25;   { TEA block cipher }
  DCP_serpent       = 26;   { Serpent block cipher }
  DCP_ripemd128     = 27;   { RipeMD-128 hash }
  DCP_sha256        = 28;   { SHA-256 hash }
  DCP_sha384        = 29;   { SHA-384 hash }
  DCP_sha512        = 30;   { SHA-512 hash }


implementation

end.
