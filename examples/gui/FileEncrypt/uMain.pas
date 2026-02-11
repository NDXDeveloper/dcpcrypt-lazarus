{******************************************************************************}
{* DCPcrypt v2.0 - Lazarus LCL GUI demo                                      *}
{******************************************************************************}
{* File encryption/decryption demo with Thread                                *}
{* Ported from Delphi VCL to Lazarus LCL                                     *}
{* Uses the DCPcrypt library by David Barton                                  *}
{******************************************************************************}
{* Copyright (c) 2026 Nicolas Deoux (NDXDev@gmail.com)                        *}
{* MIT License - see LICENSE file                                             *}
{******************************************************************************}
unit uMain;

{$MODE ObjFPC}{$H+}

interface

uses
  SysUtils, Classes, Graphics, Controls, Forms,
  Dialogs, DCPtiger, DCPsha512, DCPsha256, DCPsha1, DCPripemd160,
  DCPripemd128, DCPmd5, DCPmd4, DCPcrypt2, DCPhaval, DCPtwofish, DCPtea,
  DCPserpent, DCPblockciphers, DCPrijndael, DCPrc4, DCPrc2, DCPice, DCPdes,
  DCPcast128, DCPblowfish, StdCtrls, Buttons, ComCtrls,
  UnitUtilitaires;

type

  { TThreadTaf }

  TThreadTaf = class(TThread)
  private
    _Hash: TDCP_hash;
    _Cipher: TDCP_cipher;
    _passphrase, _inputfile, _outputfile: string;
    _success: boolean;
    _ModeEncrypt: boolean;
    FOnProgress: TProgressEvent;
    _btnEncrypWasEnabled, _btnDecryptWasEnabled: boolean;
  protected
    procedure Execute; override;
    procedure DoEncrypt;
    procedure DoDecrypt;
    procedure ReActiveControles;
    procedure CancelAllOperations;
    procedure EndingMessageEncryption;
    procedure EndingMessageDecryption;
  public
    constructor Create(CreateSuspended: Boolean);
    destructor Destroy; override;
    property OnProgress: TProgressEvent read FOnProgress write FOnProgress;
    property btnEncrypWasEnabled: boolean read _btnEncrypWasEnabled write _btnEncrypWasEnabled;
    property btnDecryptWasEnabled: boolean read _btnDecryptWasEnabled write _btnDecryptWasEnabled;
    property ModeEncrypt: boolean read _ModeEncrypt write _ModeEncrypt;
    property Hash: TDCP_hash read _Hash write _Hash;
    property Cipher: TDCP_cipher read _Cipher write _Cipher;
    property passphrase: string read _passphrase write _passphrase;
    property inputfile: string read _inputfile write _inputfile;
    property outputfile: string read _outputfile write _outputfile;
    procedure Pourcentage(Sender: TObject; Value: integer);
  end;

  { TfrmMain }

  TfrmMain = class(TForm)
    grpInput: TGroupBox;
    boxInputFile: TEdit;
    btnInputBrowse: TButton;
    lblInputFileSize: TLabel;
    dblInputFileSize: TLabel;
    grpOutput: TGroupBox;
    boxOutputFile: TEdit;
    btnOutputBrowse: TButton;
    grpOptions: TGroupBox;
    cbxCipher: TComboBox;
    lblCipher: TLabel;
    lblHash: TLabel;
    cbxHash: TComboBox;
    lblKeySize: TLabel;
    dblKeySize: TLabel;
    boxPassphrase: TEdit;
    lblPassphrase: TLabel;
    boxConfirmPassphrase: TEdit;
    lblConfirmPassphrase: TLabel;
    dlgInput: TOpenDialog;
    dlgOutput: TSaveDialog;
    Progress: TProgressBar;
    btnEncrypt: TButton;
    btnDecrypt: TButton;
    btnClose: TButton;
    procedure FormCreate(Sender: TObject);
    procedure boxInputFileExit(Sender: TObject);
    procedure btnInputBrowseClick(Sender: TObject);
    procedure btnOutputBrowseClick(Sender: TObject);
    procedure cbxCipherChange(Sender: TObject);
    procedure boxPassphraseChange(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure Pourcentage(Sender: TObject; Value: integer);
    procedure btnEncryptClick(Sender: TObject);
    procedure btnDecryptClick(Sender: TObject);
    procedure btnCloseClick(Sender: TObject);
    procedure FormDropFiles(Sender: TObject; const FileNames: array of string);
  private
    bDec, bEnc: boolean;
    CurrentDir: string;
    procedure DisableForm;
    procedure DisableControls;
    function DoEncryptFile(infile, outfile, apassphrase: string;
                        aHash: TDCP_hash; aCipher: TDCP_cipher): Boolean;
    function DoDecryptFile(infile, outfile, apassphrase: string;
                        aHash: TDCP_hash; aCipher: TDCP_cipher): Boolean;
  public
  end;

var
  frmMain: TfrmMain;
  ThreadRunning: boolean;
  ThreadTaf: TThreadTaf;

implementation

{$R *.lfm}

function Min(a, b: integer): integer;
begin
  if (a < b) then
    Result := a
  else
    Result := b;
end;

procedure TfrmMain.DisableForm;
begin
  grpInput.Enabled := False;
  grpOutput.Enabled := False;
  grpOptions.Enabled := False;
  btnEncrypt.Enabled := False;
  btnDecrypt.Enabled := False;
end;

procedure TfrmMain.DisableControls;
begin
  boxInputFile.Enabled := False;
  boxOutputFile.Enabled := False;
  cbxCipher.Enabled := False;
  cbxHash.Enabled := False;
  boxPassphrase.Enabled := False;
  boxConfirmPassphrase.Enabled := False;
  btnInputBrowse.Enabled := False;
  btnOutputBrowse.Enabled := False;
  btnEncrypt.Enabled := False;
  btnDecrypt.Enabled := False;
end;

procedure TfrmMain.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  if ThreadRunning then
    if MessageDlg('Application is working! Are you sure you want to quit?',
                  mtConfirmation, [mbYes, mbNo], 0) = mrYes then
    begin
      ThreadTaf.CancelAllOperations;
      Repeat
        Application.ProcessMessages;
      Until (not ThreadRunning);
    end
    else
    begin
      CanClose := not ThreadRunning;
    end;
end;

procedure TfrmMain.Pourcentage(Sender: TObject; Value: integer);
begin
  if Value <= 100 then
    if Value >= 0 then
      Progress.Position := Value;
end;

procedure TfrmMain.FormDropFiles(Sender: TObject; const FileNames: array of string);
var
  Ext, dest: string;
begin
  if Length(FileNames) < 1 then Exit;

  CurrentDir := ExtractFilePath(FileNames[0]);
  boxInputFile.Text := FileNames[0];
  boxInputFileExit(boxInputFile);

  dest := boxInputFile.Text;
  Ext := AnsiLowerCase(ExtractFileExt(dest));
  dest := ChangeFileExt(dest, '');
  dest := dest + '_NEW';
  dest := dest + Ext;
  boxOutputFile.Text := dest;

  bEnc := False;
  bDec := False;
  boxPassphrase.Text := '';
  boxConfirmPassphrase.Text := '';
end;

procedure TfrmMain.FormCreate(Sender: TObject);
var
  i: integer;
  Ext, dest: string;
begin
  // Enable drag-and-drop (LCL way)
  AllowDropFiles := True;
  OnDropFiles := @FormDropFiles;

  // Command-line parameter support
  if ParamStr(1) <> '' then
  begin
    if FileExists(ParamStr(1)) then
    begin
      boxInputFile.Text := ParamStr(1);
      dest := ParamStr(1);
      Ext := AnsiLowerCase(ExtractFileExt(dest));
      dest := ChangeFileExt(dest, '');

      if ParamStr(2) = '/decrypt' then
      begin
        btnEncrypt.Enabled := False;
        bDec := True;
        dest := dest + '_Decrypted';
      end
      else
      begin
        btnDecrypt.Enabled := False;
        bEnc := True;
        dest := dest + '_Encrypted';
      end;
      dest := dest + Ext;
      boxOutputFile.Text := dest;
    end;
  end;

  Randomize;

  // Crypto components are created in code (no design-time package needed)
  // -- Ciphers --
  TDCP_blowfish.Create(Self);
  TDCP_cast128.Create(Self);
  TDCP_des.Create(Self);
  TDCP_3des.Create(Self);
  TDCP_ice.Create(Self);
  TDCP_thinice.Create(Self);
  TDCP_ice2.Create(Self);
  TDCP_rc2.Create(Self);
  TDCP_rc4.Create(Self);
  TDCP_rijndael.Create(Self);
  TDCP_serpent.Create(Self);
  TDCP_tea.Create(Self);
  TDCP_twofish.Create(Self);

  // -- Hashes --
  TDCP_haval.Create(Self);
  TDCP_md4.Create(Self);
  TDCP_md5.Create(Self);
  TDCP_ripemd128.Create(Self);
  TDCP_ripemd160.Create(Self);
  TDCP_sha1.Create(Self);
  TDCP_sha256.Create(Self);
  TDCP_sha384.Create(Self);
  TDCP_sha512.Create(Self);
  TDCP_tiger.Create(Self);

  // Iterate through all owned components and find the ciphers/hashes
  for i := 0 to (ComponentCount - 1) do
  begin
    if (Components[i] is TDCP_cipher) then
      cbxCipher.Items.AddObject(TDCP_cipher(Components[i]).Algorithm, Components[i])
    else if (Components[i] is TDCP_hash) then
      cbxHash.Items.AddObject(TDCP_hash(Components[i]).Algorithm, Components[i]);
  end;

  if (cbxCipher.Items.Count = 0) then
  begin
    MessageDlg('No ciphers were found', mtError, [mbOK], 0);
    DisableForm;
  end
  else
  begin
    cbxCipher.ItemIndex := 0;
    if (cbxHash.Items.Count = 0) then
    begin
      MessageDlg('No hashes were found', mtError, [mbOK], 0);
      DisableForm;
    end
    else
    begin
      cbxHash.ItemIndex := 0;
      cbxCipher.OnChange(cbxCipher);
    end;
  end;
end;

// Add commas into a numerical string (e.g. 12345678 becomes 12,345,678)
function AddCommas(const S: string): string;
var
  i, j: integer;
begin
  Result := '';
  i := Length(S) mod 3;
  if ((i <> 0) and (Length(S) > 3)) then
    Result := Copy(S, 1, i) + ',';
  for j := 0 to ((Length(S) div 3) - 2) do
    Result := Result + Copy(S, 1 + i + j * 3, 3) + ',';
  if (Length(S) > 3) then
    Result := Result + Copy(S, Length(S) - 2, 3)
  else
    Result := S;
end;

procedure TfrmMain.boxInputFileExit(Sender: TObject);
var
  strmInput: TFileStream;
begin
  if (boxInputFile.Text = '') then
    dblInputFileSize.Caption := 'no file specified'
  else if FileExists(boxInputFile.Text) then
  begin
    strmInput := nil;
    try
      strmInput := TFileStream.Create(boxInputFile.Text, fmOpenRead);
      dblInputFileSize.Caption := AddCommas(IntToStr(strmInput.Size)) + ' bytes';
      strmInput.Free;
    except
      strmInput.Free;
      dblInputFileSize.Caption := 'unable to open file';
    end;
  end
  else
    dblInputFileSize.Caption := 'file does not exist';
end;

procedure TfrmMain.btnInputBrowseClick(Sender: TObject);
var
  openDialog: TOpenDialog;
begin
  openDialog := TOpenDialog.Create(Self);
  openDialog.InitialDir := CurrentDir;
  openDialog.Filter := 'All Files (*.*)|*.*';
  if openDialog.Execute then
  begin
    CurrentDir := ExtractFilePath(openDialog.Files[0]);
    boxInputFile.Text := openDialog.FileName;
    boxInputFileExit(boxInputFile);
    bEnc := False;
    bDec := False;
    boxOutputFile.Text := '';
    boxPassphrase.Text := '';
    boxConfirmPassphrase.Text := '';
    btnEncrypt.Enabled := False;
    btnDecrypt.Enabled := False;
  end;
  openDialog.Free;
end;

procedure TfrmMain.btnOutputBrowseClick(Sender: TObject);
var
  saveDialog: TSaveDialog;
begin
  saveDialog := TSaveDialog.Create(Self);
  saveDialog.InitialDir := CurrentDir;
  saveDialog.Filter := 'All Files (*.*)|*.*';
  if saveDialog.Execute then
    boxOutputFile.Text := saveDialog.FileName;
  saveDialog.Free;
end;

procedure TfrmMain.cbxCipherChange(Sender: TObject);
var
  aCipher: TDCP_cipher;
  aHash: TDCP_hash;
begin
  aCipher := TDCP_cipher(cbxCipher.Items.Objects[cbxCipher.ItemIndex]);
  aHash := TDCP_hash(cbxHash.Items.Objects[cbxHash.ItemIndex]);
  if (aCipher.MaxKeySize < aHash.HashSize) then
    dblKeySize.Caption := IntToStr(aCipher.MaxKeySize) + ' bits'
  else
    dblKeySize.Caption := IntToStr(aHash.HashSize) + ' bits';
end;

procedure TfrmMain.boxPassphraseChange(Sender: TObject);
begin
  if (Length(boxPassphrase.Text) > 0) then
  begin
    if not bEnc then
      btnDecrypt.Enabled := True;
    if (boxPassphrase.Text = boxConfirmPassphrase.Text) then
    begin
      if not bDec then
        btnEncrypt.Enabled := True;
    end
    else
      btnEncrypt.Enabled := False;
  end
  else
    btnDecrypt.Enabled := False;
end;

function TfrmMain.DoEncryptFile(infile, outfile, apassphrase: string;
                        aHash: TDCP_hash; aCipher: TDCP_cipher): Boolean;
begin
  Result := True;
  if ThreadRunning then Exit;
  ThreadRunning := True;
  ThreadTaf := TThreadTaf.Create(True);
  ThreadTaf.ModeEncrypt := True;
  ThreadTaf.passphrase := apassphrase;
  ThreadTaf.inputfile := infile;
  ThreadTaf.outputfile := outfile;
  ThreadTaf.Hash := aHash;
  ThreadTaf.Cipher := aCipher;
  ThreadTaf.OnProgress := @Pourcentage;
  ThreadTaf.btnEncrypWasEnabled := btnEncrypt.Enabled;
  ThreadTaf.btnDecryptWasEnabled := btnDecrypt.Enabled;
  DisableControls;
  ThreadTaf.Start;
end;

function TfrmMain.DoDecryptFile(infile, outfile, apassphrase: string;
                        aHash: TDCP_hash; aCipher: TDCP_cipher): Boolean;
begin
  Result := True;
  if ThreadRunning then Exit;
  ThreadRunning := True;
  ThreadTaf := TThreadTaf.Create(True);
  ThreadTaf.ModeEncrypt := False;
  ThreadTaf.passphrase := apassphrase;
  ThreadTaf.inputfile := infile;
  ThreadTaf.outputfile := outfile;
  ThreadTaf.Hash := aHash;
  ThreadTaf.Cipher := aCipher;
  ThreadTaf.OnProgress := @Pourcentage;
  ThreadTaf.btnEncrypWasEnabled := btnEncrypt.Enabled;
  ThreadTaf.btnDecryptWasEnabled := btnDecrypt.Enabled;
  DisableControls;
  ThreadTaf.Start;
end;

procedure TfrmMain.btnEncryptClick(Sender: TObject);
var
  aHash: TDCP_hash;
  aCipher: TDCP_cipher;
begin
  if ThreadRunning then Exit;
  if not FileExists(boxInputFile.Text) then
  begin
    MessageDlg('Input filename doesn''t exist!', mtConfirmation, [mbOK], 0);
    Exit;
  end;
  if not IsValidFilename(boxOutputFile.Text) then
  begin
    MessageDlg('Output filename is not valid!', mtConfirmation, [mbOK], 0);
    Exit;
  end;
  if (Trim(boxInputFile.Text) = Trim(boxOutputFile.Text)) then
  begin
    MessageDlg('Output filename: Please choose a different name', mtConfirmation, [mbOK], 0);
    Exit;
  end;
  if FileExists(boxOutputFile.Text) then
    if (MessageDlg('Output file already exists. Overwrite?', mtConfirmation, mbYesNoCancel, 0) <> mrYes) then
      Exit;

  aHash := TDCP_hash(cbxHash.Items.Objects[cbxHash.ItemIndex]);
  aCipher := TDCP_cipher(cbxCipher.Items.Objects[cbxCipher.ItemIndex]);
  DoEncryptFile(boxInputFile.Text, boxOutputFile.Text, boxPassphrase.Text,
                aHash, aCipher);
end;

procedure TfrmMain.btnDecryptClick(Sender: TObject);
var
  aCipher: TDCP_cipher;
  aHash: TDCP_hash;
begin
  if ThreadRunning then Exit;
  if not FileExists(boxInputFile.Text) then
  begin
    MessageDlg('Input filename doesn''t exist!', mtConfirmation, [mbOK], 0);
    Exit;
  end;
  if not IsValidFilename(boxOutputFile.Text) then
  begin
    MessageDlg('Output filename is not valid!', mtConfirmation, [mbOK], 0);
    Exit;
  end;
  if (Trim(boxInputFile.Text) = Trim(boxOutputFile.Text)) then
  begin
    MessageDlg('Output filename: Please choose a different name', mtConfirmation, [mbOK], 0);
    Exit;
  end;
  if FileExists(boxOutputFile.Text) then
    if (MessageDlg('Output file already exists. Overwrite?', mtConfirmation, mbYesNoCancel, 0) <> mrYes) then
      Exit;

  aHash := TDCP_hash(cbxHash.Items.Objects[cbxHash.ItemIndex]);
  aCipher := TDCP_cipher(cbxCipher.Items.Objects[cbxCipher.ItemIndex]);
  DoDecryptFile(boxInputFile.Text, boxOutputFile.Text, boxPassphrase.Text,
                aHash, aCipher);
end;

procedure TfrmMain.btnCloseClick(Sender: TObject);
begin
  Close;
end;

{----------------------------}
{ TThreadTaf methods         }
{----------------------------}
constructor TThreadTaf.Create(CreateSuspended: Boolean);
begin
  inherited Create(True);
  FreeOnTerminate := True;
  Priority := tpNormal;
  _success := False;
end;

destructor TThreadTaf.Destroy;
begin
  inherited;
end;

procedure TThreadTaf.CancelAllOperations;
begin
  _Cipher.CancelByCallingThread := True;
end;

procedure TThreadTaf.Execute;
begin
  _Cipher.OnProgressEvent := @Pourcentage;
  if _ModeEncrypt then
    DoEncrypt
  else
    DoDecrypt;
end;

procedure TThreadTaf.DoDecrypt;
var
  CipherIV: array of byte;
  HashDigest: array of byte;
  Salt: array[0..7] of byte;
  strmInput, strmOutput: TFileStream;
begin
  strmInput := nil;
  strmOutput := nil;
  try
    strmInput := TFileStream.Create(_inputfile, fmOpenRead);
    strmOutput := TFileStream.Create(_outputfile, fmCreate);

    SetLength(HashDigest, _Hash.HashSize div 8);
    strmInput.ReadBuffer(Salt[0], SizeOf(Salt));
    _Hash.Init;
    _Hash.Update(Salt[0], SizeOf(Salt));
    _Hash.UpdateStr(_passphrase);
    _Hash.Final(HashDigest[0]);

    if (_Cipher is TDCP_blockcipher) then
    begin
      SetLength(CipherIV, TDCP_blockcipher(_Cipher).BlockSize div 8);
      strmInput.ReadBuffer(CipherIV[0], Length(CipherIV));
      _Cipher.Init(HashDigest[0], Min(_Cipher.MaxKeySize, _Hash.HashSize), @CipherIV[0]);
      TDCP_blockcipher(_Cipher).CipherMode := cmCBC;
    end
    else
      _Cipher.Init(HashDigest[0], Min(_Cipher.MaxKeySize, _Hash.HashSize), nil);

    _Cipher.DecryptStream(strmInput, strmOutput, strmInput.Size - strmInput.Position);
    _Cipher.Burn;
    strmInput.Free;
    strmOutput.Free;
    ThreadRunning := False;
    _success := True;
    Synchronize(@EndingMessageDecryption);
  except
    strmInput.Free;
    strmOutput.Free;
    _success := False;
    Synchronize(@EndingMessageDecryption);
    ThreadRunning := False;
  end;
end;

procedure TThreadTaf.DoEncrypt;
var
  CipherIV: array of byte;
  HashDigest: array of byte;
  Salt: array[0..7] of byte;
  strmInput, strmOutput: TFileStream;
  i: integer;
begin
  strmInput := nil;
  strmOutput := nil;
  try
    strmInput := TFileStream.Create(_inputfile, fmOpenRead);
    strmOutput := TFileStream.Create(_outputfile, fmCreate);

    SetLength(HashDigest, _Hash.HashSize div 8);
    for i := 0 to 7 do
      Salt[i] := Random(256);
    strmOutput.WriteBuffer(Salt, SizeOf(Salt));
    _Hash.Init;
    _Hash.Update(Salt[0], SizeOf(Salt));
    _Hash.UpdateStr(_passphrase);
    _Hash.Final(HashDigest[0]);

    if (_Cipher is TDCP_blockcipher) then
    begin
      SetLength(CipherIV, TDCP_blockcipher(_Cipher).BlockSize div 8);
      for i := 0 to (Length(CipherIV) - 1) do
        CipherIV[i] := Random(256);
      strmOutput.WriteBuffer(CipherIV[0], Length(CipherIV));
      _Cipher.Init(HashDigest[0], Min(_Cipher.MaxKeySize, _Hash.HashSize), @CipherIV[0]);
      TDCP_blockcipher(_Cipher).CipherMode := cmCBC;
    end
    else
      _Cipher.Init(HashDigest[0], Min(_Cipher.MaxKeySize, _Hash.HashSize), nil);

    _Cipher.EncryptStream(strmInput, strmOutput, strmInput.Size);
    _Cipher.Burn;
    strmInput.Free;
    strmOutput.Free;
    ThreadRunning := False;
    _success := True;
    Synchronize(@EndingMessageEncryption);
  except
    strmInput.Free;
    strmOutput.Free;
    _success := False;
    Synchronize(@EndingMessageEncryption);
    ThreadRunning := False;
  end;
end;

procedure TThreadTaf.Pourcentage(Sender: TObject; Value: integer);
begin
  if Assigned(FOnProgress) then
    FOnProgress(Self, Value);
end;

procedure TThreadTaf.EndingMessageEncryption;
begin
  if _success then
    MessageDlg('File encrypted', mtInformation, [mbOK], 0)
  else
    MessageDlg('An error occurred while processing the file', mtError, [mbOK], 0);
  ReActiveControles;
end;

procedure TThreadTaf.EndingMessageDecryption;
begin
  if _success then
    MessageDlg('File decrypted', mtInformation, [mbOK], 0)
  else
    MessageDlg('An error occurred while processing the file', mtError, [mbOK], 0);
  ReActiveControles;
end;

procedure TThreadTaf.ReActiveControles;
begin
  frmMain.boxInputFile.Enabled := True;
  frmMain.boxOutputFile.Enabled := True;
  frmMain.cbxCipher.Enabled := True;
  frmMain.cbxHash.Enabled := True;
  frmMain.boxPassphrase.Enabled := True;
  frmMain.boxConfirmPassphrase.Enabled := True;
  frmMain.btnInputBrowse.Enabled := True;
  frmMain.btnOutputBrowse.Enabled := True;
  if btnEncrypWasEnabled then
    frmMain.btnEncrypt.Enabled := True
  else
    frmMain.btnEncrypt.Enabled := False;
  if btnDecryptWasEnabled then
    frmMain.btnDecrypt.Enabled := True
  else
    frmMain.btnDecrypt.Enabled := False;
end;

end.
