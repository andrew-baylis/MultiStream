unit DataStream;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  Vcl.Controls,
  System.Zlib;

type
  TSignatureBytes = array [0 .. 7] of byte;

  ECorruptFile = class(Exception);
  TOnAskForKey = function(Sender: TObject): string of object;
  TOnStreamEvent = procedure(Sender: TObject; Source, Dest: TStream) of object;
  TOnCryptStreamEvent = procedure(Sender: TObject; Source, Dest: TStream; const sKey: string) of object;

  [ComponentPlatformsAttribute(pidWin32 or pidWin64 or pidOSX32 or pidiOSSimulator or pidiOSDevice or pidAndroid)]
  TDataStream = class(TComponent)
  private
    FCompressed, FEncrypted: Boolean;
    FSKey: string;
    FOnAskForKey: TOnAskForKey;
    FOnCompressStream: TOnStreamEvent;
    FOnCorrupt: TNotifyEvent;
    FOnDecompressStream: TOnStreamEvent;
    FOnDecryptStream: TOnCryptStreamEvent;
    FOnEncryptStream: TOnCryptStreamEvent;
    FStreamList: TStringList;
    procedure WriteStr(S: string; Stream: TStream);
    function ReadStr(Stream: TStream): string;
    procedure InternalLoadFromStream(ms: TStream);
    procedure InternalSaveToStream(ms: TStream);
    function CheckSignature(ms: TStream; ATest: TSignatureBytes): Boolean;
    procedure FoundCorrupt;
    procedure InternalDecrypt(Sender: TObject; Source, Dest: TStream; const sKey: string);
    procedure InternalEncrypt(Sender: TObject; Source, Dest: TStream; const sKey: string);
    procedure ReadStream(Source, Dest: TStream);
    procedure SaveSignatureBytes(ms: TStream; ATest: TSignatureBytes);
    procedure WriteStream(Source, Dest: TStream);
    // procedure SetfSkey(const Value: string);
  protected
    procedure DoCompressStream(Source, Dest: TStream);
    function DoDecompressStream(Source, Dest: TStream): Boolean;
    function DoDecryptStream(Source, Dest: TStream): Boolean;
    procedure DoEncryptStream(Source, Dest: TStream);
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure LoadFromFile(const Filename: string);
    procedure SaveToFile(const Filename: string);
    procedure AddStream(const ID: string; Source: TStream);
    procedure RemoveStream(const ID: string);
    procedure LoadFromStream(ms: TStream);
    procedure SaveToStream(ms: TStream);
    function GetStream(const ID: string): TStream;
    procedure ClearStreams;
    procedure GetCopyOfStream(const ID: string; Dest: TStream);
    // For Already Compressed/Decompressed streams
    procedure LoadIntoStream(ms: TStream);
    property StreamList: TStringList read FStreamList;
  published
    property Compressed: Boolean read FCompressed write FCompressed;
    property Encrypted: Boolean read FEncrypted write FEncrypted;
    property Key: string read FSKey write FSKey;
    property OnAskForKey: TOnAskForKey read FOnAskForKey write FOnAskForKey;
    property OnCompressStream: TOnStreamEvent read FOnCompressStream write FOnCompressStream;
    property OnCorrupt: TNotifyEvent read FOnCorrupt write FOnCorrupt;
    property OnDecompressStream: TOnStreamEvent read FOnDecompressStream write FOnDecompressStream;
    property OnDecryptStream: TOnCryptStreamEvent read FOnDecryptStream write FOnDecryptStream;
    property OnEncryptStream: TOnCryptStreamEvent read FOnEncryptStream write FOnEncryptStream;
  end;

const
  Signature: TSignatureBytes                    = ($01, $88, $45, $32, $AE, $F0, $77, $60);
  VersionID: TSignatureBytes                    = ($10, $FF, $00, $20, $1D, $0F, $44, $E0);
  EncryptedByte: array [False .. True] of byte  = (Ord(' '), Ord('*'));
  CompressedByte: array [False .. True] of byte = (Ord(' '), Ord('&'));

implementation

{ TDataStream }

procedure TDataStream.AddStream(const ID: string; Source: TStream);
var
  ms: TMemoryStream;
  i: Integer;
begin
  if (length(ID) > 0) and (Assigned(Source)) then
  begin
    i := FStreamList.IndexOf(ID); // check if already present
    if (i >= 0) then
      ms := TMemoryStream(FStreamList.Objects[i])
    else
    begin
      ms := TMemoryStream.Create;
      FStreamList.AddObject(ID, ms);
    end;
    ms.CopyFrom(Source, 0);
  end;
end;

procedure TDataStream.ClearStreams;
begin
  FStreamList.Clear; // as owns objects, also frees streams
end;

constructor TDataStream.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FCompressed := True;
  FEncrypted := False;
  FStreamList := TStringList.Create;
  FStreamList.Duplicates := dupIgnore;
  FStreamList.OwnsObjects := True;
end;

destructor TDataStream.Destroy;
begin
  FStreamList.Free;
  inherited Destroy;
end;

function TDataStream.GetStream(const ID: string): TStream;
var
  i: Integer;
begin
  if (length(ID) > 0) and FStreamList.Find(ID, i) then
  begin
    Result := TMemoryStream(FStreamList.Objects[i]);
    Result.Position := 0;
  end
  else
    Result := nil;
end;

procedure TDataStream.GetCopyOfStream(const ID: string; Dest: TStream);
var
  i: Integer;
begin
  if (length(ID) > 0) and FStreamList.Find(ID, i) and Assigned(Dest) then
  begin
    Dest.CopyFrom(TMemoryStream(FStreamList.Objects[i]), 0);
    Dest.Position := 0;
  end;
end;

procedure TDataStream.LoadFromFile(const Filename: string);
var
  fs: TFileStream;
begin
  fs := TFileStream.Create(Filename, fmOpenRead or fmShareExclusive);
  try
    LoadFromStream(fs);
  finally
    fs.Free;
  end;
end;

procedure TDataStream.FoundCorrupt;
begin
  if Assigned(FOnCorrupt) then
    FOnCorrupt(Self)
  else
    raise ECorruptFile.Create('File is corrupt.');
end;

function TDataStream.CheckSignature(ms: TStream; ATest: TSignatureBytes): Boolean;
var
  Sig: TSignatureBytes;
  a: Integer;
begin
  ms.read(Sig, sizeof(Sig));
  Result := True;
  for a := 0 to length(Sig) - 1 do
    if ATest[a] <> Sig[a] then
    begin
      FoundCorrupt;
      Result := False;
      exit;
    end;
end;

procedure TDataStream.DoCompressStream(Source, Dest: TStream);
var
  comp: TZCompressionStream;
begin
  if Assigned(FOnCompressStream) and Assigned(FOnDecompressStream) then
    FOnCompressStream(Self, Source, Dest)
  else
  begin
    comp := TZCompressionStream.Create(clMax, Dest);
    try
      comp.CopyFrom(Source, 0);
    finally
      comp.Free;
    end;
  end;
end;

function TDataStream.DoDecompressStream(Source, Dest: TStream): Boolean;
var
  decomp: TZDecompressionStream;
begin
  Result := True;
  if Assigned(FOnCompressStream) and Assigned(FOnDecompressStream) then
    FOnDecompressStream(Self, Source, Dest)
  else
  begin
    decomp := TZDecompressionStream.Create(Source);
    try
      Dest.CopyFrom(decomp, 0);
    finally
      decomp.Free;
    end;
  end;
end;

function TDataStream.DoDecryptStream(Source, Dest: TStream): Boolean;
var
  sKey: string;
begin
  Result := True;
  if Assigned(FOnAskForKey) then
    sKey := FOnAskForKey(Self)
  else
    sKey := FSKey;
  sKey := Trim(sKey);
  if (sKey <> '') then
  begin
    if Assigned(FOnEncryptStream) and Assigned(FOnDecryptStream) then
      FOnDecryptStream(Self, Source, Dest, sKey)
    else
      InternalDecrypt(Self, Source, Dest, sKey);
  end
  else
    Dest.CopyFrom(Source, 0); // no encryption
end;

procedure TDataStream.DoEncryptStream(Source, Dest: TStream);
var
  sKey: string;
begin
  if Assigned(FOnAskForKey) then
    sKey := FOnAskForKey(Self)
  else
    sKey := FSKey;
  sKey := Trim(sKey);
  if (sKey <> '') then
  begin
    if Assigned(FOnEncryptStream) and Assigned(FOnDecryptStream) then
      FOnEncryptStream(Self, Source, Dest, sKey)
    else
      InternalEncrypt(Self, Source, Dest, sKey);
  end
  else
    Dest.CopyFrom(Source, 0); // no encryption
end;

procedure TDataStream.InternalDecrypt(Sender: TObject; Source, Dest: TStream; const sKey: string);
var
  sz, i, n: Integer;
  k, buff: array [0 .. 63] of byte;
begin
  n := length(k);
  // set up k as a block of bytes for XOR
  for i := 0 to n - 1 do
    if (i < length(sKey)) then
      k[i] := Ord(sKey[i + 1])
    else
      k[i] := i;

  // decrypt with simple XOR using block
  repeat
    sz := Source.read(buff, n);
    for i := 0 to sz - 1 do
      buff[i] := buff[i] xor k[i]; // encrypt
    if (sz > 0) then
      Dest.Write(buff, sz);
  until (sz = 0);
end;

procedure TDataStream.InternalEncrypt(Sender: TObject; Source, Dest: TStream; const sKey: string);
var
  sz, i, n: Integer;
  k, buff: array [0 .. 63] of byte;
begin
  n := length(k);
  // set up k as a block of bytes for XOR
  for i := 0 to n - 1 do
    if (i < length(sKey)) then
      k[i] := Ord(sKey[i + 1])
    else
      k[i] := i;

  // encrypt with simple XOR using block
  repeat
    sz := Source.read(buff, n);
    for i := 0 to sz - 1 do
      buff[i] := buff[i] xor k[i]; // encrypt
    if (sz > 0) then
      Dest.Write(buff, sz);
  until (sz = 0);
end;

procedure TDataStream.LoadFromStream(ms: TStream);
// expect stream to start with VersionID, c, e then hold data
var
  temp, outstream: TMemoryStream;
  e, c: byte;
begin
  ClearStreams;
  if (ms.Size = 0) then
    exit;

  if CheckSignature(ms, VersionID) then
  begin
    ms.read(c, sizeof(c));
    ms.read(e, sizeof(e));
    FCompressed := (c = CompressedByte[True]);
    FEncrypted := (e = EncryptedByte[True]);
    temp := TMemoryStream.Create;
    outstream := TMemoryStream.Create;
    try
      outstream.CopyFrom(ms, ms.Size - ms.Position); // copy remainder of stream to outstream
      if not DoDecompressStream(outstream, temp) then
        exit; // now temp holds uncompressed data
      outstream.Clear;
      if not DoDecryptStream(temp, outstream) then
        exit; // now outstream holds the unencrypted data

      InternalLoadFromStream(outstream);
    finally
      temp.Free;
      outstream.Free;
    end;
  end;
end;

procedure TDataStream.InternalLoadFromStream(ms: TStream);
var
  mem: TMemoryStream;
  i, iCount: Integer;
  sID: string;
begin
  ClearStreams;
  if CheckSignature(ms, Signature) then // checks that decryption / decompression has worked
  begin
    // read num of items
    ms.read(iCount, sizeof(iCount));
    // now load in ID and data streams
    for i := 0 to iCount - 1 do
    begin
      mem := TMemoryStream.Create;
      sID := ReadStr(ms);
      ReadStream(ms, mem);
      FStreamList.AddObject(sID, mem);
    end;
  end;
end;

procedure TDataStream.LoadIntoStream(ms: TStream);
begin
  FStreamList.Clear;
  FStreamList.LoadFromStream(ms);
end;

function TDataStream.ReadStr(Stream: TStream): string;
var
  i: Word;
  S: string;
{$IFDEF UNICODE}
  b: TBytes;
{$ENDIF}
begin
{$IFDEF UNICODE}
  Stream.read(i, sizeof(i));
  SetLength(b, i);
  Stream.read(b[0], i);
  S := StringOf(b);
{$ELSE}
  Stream.read(i, sizeof(i));
  SetLength(S, i);
  Stream.read(PChar(S)^, i);
{$ENDIF}
  Result := S;
end;

procedure TDataStream.ReadStream(Source, Dest: TStream);
var
  sz: Integer;
begin
  Dest.Position := 0;
  Source.read(sz, sizeof(sz));
  if (sz > 0) then
    Dest.CopyFrom(Source, sz);
end;

procedure TDataStream.RemoveStream(const ID: string);
var
  i: Integer;
begin
  if (length(ID) > 0) and FStreamList.Find(ID, i) then
  begin
    FStreamList.Delete(i); // also frees object
  end;
end;

procedure TDataStream.SaveToFile(const Filename: string);
var
  fs: TFileStream;
begin
  fs := TFileStream.Create(Filename, fmCreate or fmShareExclusive);
  try
    SaveToStream(fs);
  finally
    fs.Free;
  end;
end;

procedure TDataStream.SaveToStream(ms: TStream);
// stream format is VersionID, c, e then data
var
  temp, outstream: TMemoryStream;
  e, c: byte;
begin
  temp := TMemoryStream.Create;
  outstream := TMemoryStream.Create;
  try
    // save VersionID header
    SaveSignatureBytes(ms, VersionID);
    c := CompressedByte[FCompressed];
    e := EncryptedByte[FEncrypted];

    ms.Write(c, sizeof(c));
    ms.Write(e, sizeof(e));

    InternalSaveToStream(outstream);
    temp.Position := 0;
    DoEncryptStream(outstream, temp); // temp now holds encrypted data
    outstream.Clear;
    DoCompressStream(temp, outstream); // outsream now holds compressed data

    ms.CopyFrom(outstream, 0);
  finally
    temp.Free;
    outstream.Free;
  end;
end;

procedure TDataStream.InternalSaveToStream(ms: TStream);
var
  iCount, i: Integer;
  mem: TMemoryStream;
begin
  iCount := FStreamList.Count;
  SaveSignatureBytes(ms, Signature); // repeated here to check that encryted / compressed has been done correctly
  ms.Write(iCount, sizeof(iCount));
  for i := 0 to iCount - 1 do
  begin
    WriteStr(FStreamList[i], ms);
    mem := TMemoryStream(FStreamList.Objects[i]);
    WriteStream(mem, ms);
  end;
end;

procedure TDataStream.SaveSignatureBytes(ms: TStream; ATest: TSignatureBytes);
begin
  ms.Write(ATest, sizeof(TSignatureBytes));
end;

procedure TDataStream.WriteStr(S: string; Stream: TStream);
var
  i: Word;
{$IFDEF UNICODE}
  b: TBytes;
{$ENDIF}
begin
{$IFDEF UNICODE}
  b := BytesOf(S);
  i := length(b);
  Stream.Write(i, sizeof(i));
  Stream.Write(b[0], i);
{$ELSE}
  i := length(S);
  Stream.Write(i, sizeof(i));
  Stream.Write(PChar(S)^, i);
{$ENDIF}
end;

procedure TDataStream.WriteStream(Source, Dest: TStream);
var
  sz: Integer;
begin
  if (Source = nil) then
    sz := 0
  else
    sz := Source.Size;
  Dest.Write(sz, sizeof(sz));
  if (sz > 0) then
    Dest.CopyFrom(Source, 0);
end;

end.
