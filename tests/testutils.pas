{******************************************************************************}
{* testutils.pas - Shared test utilities for DCPcrypt functional tests       *}
{******************************************************************************}
unit testutils;

{$MODE Delphi}

interface

var
  TestCount: integer;
  PassCount: integer;
  FailCount: integer;

procedure Check(const Name: string; Condition: boolean);
procedure CheckEquals(const Name: string; const Expected, Actual: string);
function TestSummary: integer;

implementation

uses
  SysUtils;

procedure Check(const Name: string; Condition: boolean);
begin
  Inc(TestCount);
  if Condition then
  begin
    Inc(PassCount);
    WriteLn('  [OK]   ', Name);
  end
  else
  begin
    Inc(FailCount);
    WriteLn('  [FAIL] ', Name);
  end;
end;

procedure CheckEquals(const Name: string; const Expected, Actual: string);
begin
  Inc(TestCount);
  if Expected = Actual then
  begin
    Inc(PassCount);
    WriteLn('  [OK]   ', Name);
  end
  else
  begin
    Inc(FailCount);
    WriteLn('  [FAIL] ', Name);
    WriteLn('         Expected: "', Expected, '"');
    WriteLn('         Actual:   "', Actual, '"');
  end;
end;

function TestSummary: integer;
begin
  WriteLn;
  WriteLn('=== Test Summary ===');
  WriteLn('  Total:  ', TestCount);
  WriteLn('  Passed: ', PassCount);
  WriteLn('  Failed: ', FailCount);
  if FailCount = 0 then
  begin
    WriteLn('  Result: ALL PASSED');
    Result := 0;
  end
  else
  begin
    WriteLn('  Result: SOME FAILED');
    Result := 1;
  end;
end;

end.
