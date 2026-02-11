unit UnitUtilitaires;

{$MODE ObjFPC}{$H+}

interface

uses
  SysUtils, Classes;

function IsValidFilename(const FileName: string): boolean;

implementation

function IsValidFilename(const FileName: string): boolean;
var
  Dir, Name: string;
  i: integer;
  InvalidChars: set of char;
begin
  Dir := ExtractFilePath(FileName);
  Name := ExtractFileName(FileName);
  if Name = '' then
    Exit(False);
  if (Dir <> '') and not DirectoryExists(Dir) then
    Exit(False);
  InvalidChars := [#0..#31, '<', '>', ':', '"', '/', '\', '|', '?', '*'];
  for i := 1 to Length(Name) do
    if Name[i] in InvalidChars then
      Exit(False);
  Result := True;
end;

end.
