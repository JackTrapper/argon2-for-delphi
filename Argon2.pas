unit Argon2;

{
	https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03
}

{$IFDEF CONDITIONALEXPRESSIONS}
	{$IF CompilerVersion >= 15} //15 = Delphi 7
		{$DEFINE COMPILER_7_UP}
	{$IFEND}
	{$IF CompilerVersion = 15} //15 = Delphi 7
		{$DEFINE COMPILER_7}
		{$DEFINE COMPILER_7_DOWN}
	{$IFEND}
{$ELSE}
	{$IFDEF VER130} //Delphi 5
		{$DEFINE COMPILER_7_DOWN}
		{$DEFINE COMPILER_5_DOWN}
		{$DEFINE COMPILER_5}
		{$DEFINE MSWINDOWS} //Delphi 5 didn't define MSWINDOWS back then. And there was no other platform
	{$ENDIF}
{$ENDIF}

interface

uses
	SysUtils
	{$IFDEF COMPILER_7_UP}, Types{$ENDIF};

{$IFNDEF UNICODE}
type
	UnicodeString = WideString;
{$ENDIF}

{$IFDEF COMPILER_7} //Delphi 7
type
	TBytes = Types.TByteDynArray; //TByteDynArray wasn't added until around Delphi 7. Sometime later it moved to SysUtils.
{$ENDIF}
{$IFDEF COMPILER_5} //Delphi 5
type
	TBytes = array of Byte; //for old-fashioned Delphi 5, we have to do it ourselves
	IInterface = IUnknown;
	TStringDynArray = array of String;

	EOSError = EWin32Error;
const
	RaiseLastOSError: procedure = SysUtils.RaiseLastWin32Error; //First appeared in Delphi 7
{$ENDIF}



type
	TArgon2 = class(TObject)
	private
		FPassword: TBytes;
		FMemorySizeKB: Integer;
		FDegreeOfParallelism: Integer;
		FIterations: Integer;
		FSalt: TBytes;
		FKnownSecret: TBytes;
		FAssociatedData: TBytes;
	protected
		FHashType: Cardinal; //0=Argon2d, 1=Argon2i, 2=Argon2id
		function GenerateSeedBlock(const Passphrase; PassphraseLength, DesiredNumberOfBytes: Integer): TBytes;
		function GenerateInitialBlock(const H0: TBytes; ColumnIndex, LaneIndex: Integer): TBytes;
		class procedure BurnBytes(var data: TBytes);
		class function StringToUtf8(const Source: UnicodeString): TBytes;

		class function Base64Encode(const data: array of Byte): string;
		class function Base64Decode(const s: string): TBytes;

		class function Tokenize(const s: string; Delimiter: Char): TStringDynArray;
		class function GenRandomBytes(len: Integer; const data: Pointer): HRESULT;
		function GenerateSalt: TBytes;
		class function Hash(const Buffer; BufferLen: Integer; DigestSize: Cardinal): TBytes;

		class function UnicodeStringToUtf8(const Source: UnicodeString): TBytes;

		class function TimingSafeSameString(const Safe, User: string): Boolean;

		procedure GetDefaultParameters(out Iterations, MemoryFactor, Parallelism: Integer);
		function TryParseHashString(HashString: string; out Algorithm: string; out Version, Iterations, MemoryFactor, Parallelism: Integer; out Salt: TBytes; out Data: TBytes): Boolean;
		function FormatPasswordHash(const Algorithm: string; Version: Integer; const Iterations, MemoryFactor, Parallelism: Integer; const Salt, DerivedBytes: array of Byte): string;

		class function CreateHash(AlgorithmName: string; cbHashLen: Integer; const Key; const cbKeyLen: Integer): IUnknown;
	public
		constructor Create;

		function GetBytes(const Passphrase; PassphraseLength: Integer; DesiredNumberOfBytes: Integer): TBytes;

		property Iterations: Integer read FIterations write FIterations; //must be at least 1 iteration
		property MemorySizeKB: Integer read FMemorySizeKB write FMemorySizeKB; //must be at least 4 KB
		property DegreeOfParallelism: Integer read FDegreeOfParallelism write FDegreeOfParallelism; //must be at least 1 thread
		property Salt: TBytes read FSalt write FSalt;
		property KnownSecret: TBytes read FKnownSecret write FKnownSecret;
		property AssociatedData: TBytes read FAssociatedData write FAssociatedData;

		class function DeriveBytes(const Passphrase; PassphraseLength: Integer; const Salt: TBytes; Iterations, MemorySizeKB, Parallelism: Integer; nDesiredBytes: Integer): TBytes;

		//Hashes a password into the standard Argon2 OpenBSD password-file format
		class function HashPassword(const Password: UnicodeString): string; overload;
		class function HashPassword(const Password: UnicodeString; const Iterations, MemorySizeKB, Parallelism: Integer): string; overload;
		class function CheckPassword(const Password: UnicodeString; const ExpectedHashString: string; out PasswordRehashNeeded: Boolean): Boolean; overload;

		class function CreateObject(ObjectName: string): IUnknown;
	end;

	TArgon2i = class(TArgon2)
	public

	end;

	TArgon2d = class(TArgon2)
	public
	end;

	TArgon2id = class(TArgon2)
	public
	end;

	//As basic of a Hash interface as you can get
	IHashAlgorithm = interface(IInterface)
		['{985B0964-C47A-4212-ADAA-C57B26F02CCD}']
		function GetBlockSize: Integer;
		function GetDigestSize: Integer;

		{ Methods }
		procedure HashData(const Buffer; BufferLen: Integer);
		function Finalize: TBytes;

		{ Properties }
		property BlockSize: Integer read GetBlockSize;
		property DigestSize: Integer read GetDigestSize;
	end;

	IHmacAlgorithm = interface(IInterface)
		['{815787A8-D5E7-41C0-9F23-DF30D1532C49}']
		function GetDigestSize: Integer;
		function HashData(const Key; KeyLen: Integer; const Data; DataLen: Integer): TBytes;
		property DigestSize: Integer read GetDigestSize;
	end;

function ROR64(const Value: Int64; const n: Integer): Int64; //rotate right

implementation

{$IFDEF UnitTests}
	{$DEFINE Argon2UnitTests}
{$ENDIF}

{$IFDEF NoArgon2UnitTests}
	{$UNDEF Argon2UnitTests}
{$ENDIF}

uses
	Classes,
	{$IFDEF Argon2UnitTests}Argon2Tests,{$ENDIF}
	{$IFDEF MSWINDOWS}Windows, ComObj, ActiveX,{$ENDIF}
	Math;

const
	ARGON_VERSION: Cardinal = $13;

{$IFDEF COMPILER_7_DOWN}
function MAKELANGID(p, s: WORD): WORD;
begin
	Result := WORD(s shl 10) or p;
end;

function CharInSet(C: AnsiChar; const CharSet: TSysCharSet): Boolean; overload;
begin
	Result := C in CharSet;
end;
{$ENDIF}

type
	EArgon2Exception = class(Exception);

	HCRYPTPROV = THandle;

	function StartsWith(s: string; StartingText: string): Boolean;
	var
		len: Integer;
	begin
		Result := False;

		len := Length(StartingText);

		if Length(s) < len then
			Exit;

		Result := (CompareString(LOCALE_INVARIANT, LINGUISTIC_IGNORECASE, PChar(s), len, PChar(StartingText), len) = CSTR_EQUAL);
	end;

function CryptAcquireContextW(out phProv: HCRYPTPROV; pszContainer: PWideChar; pszProvider: PWideChar; dwProvType: DWORD; dwFlags: DWORD): BOOL; stdcall; external advapi32;
function CryptReleaseContext(hProv: HCRYPTPROV; dwFlags: DWORD): BOOL; stdcall; external advapi32;
function CryptGenRandom(hProv: HCRYPTPROV; dwLen: DWORD; pbBuffer: Pointer): BOOL; stdcall; external advapi32;

type
	UInt64Rec = packed record
		case Byte of
		0: (Lo, Hi: Cardinal;);
		1: (Value: UInt64;);
	end;
	PUInt64Rec = ^UInt64Rec;

type
	TBlake2bBlockArray = array[0..15] of UInt64; //operates a lot on things that are 16 "words" long (where a word in Blake2b is 64-bit)
	PBlake2bBlockArray = ^TBlake2bBlockArray;

{ TBlake2b }
type
	TBlake2b = class(TInterfacedObject, IHashAlgorithm)
	private
	protected
		FDigestSize: Integer;
		FKey: TBytes;
		FInitialized: Boolean;
		h: array[0..7] of Int64; //State vector
		FBuffer: array[0..127] of Byte;
		FBufferLength: Integer;
		FProcessed: Int64;

		procedure Burn;
		procedure BlakeCompress(const m: PBlake2bBlockArray; cbBytesProcessed: Int64; IsFinalBlock: Boolean); virtual;
		procedure BlakeMix(var Va, Vb, Vc, Vd: UInt64; const x, y: Int64); inline;
		procedure Initialize;
	public
		constructor Create(const Key; cbKeyLen: Integer; cbHashLen: Integer);
		destructor Destroy; override;

		function GetBlockSize: Integer;
		function GetDigestSize: Integer;

		{ IHashAlgorithm }
		procedure HashData(const Buffer; BufferLen: Integer); overload;
		function Finalize: TBytes;

		{ Properties }
		property BlockSize: Integer read GetBlockSize;
		property DigestSize: Integer read GetDigestSize;
	end;

	//92 MB/s (verses 22 MB/s of safe version)
	TBlake2bOptimized = class(TBlake2b)
	protected
		procedure BlakeCompress(const m: PBlake2bBlockArray; cbBytesProcessed: Int64; IsFinalBlock: Boolean); override;
	end;

	TArgon2Hash = class(TInterfacedObject, IHashAlgorithm)
	private
		FDigestSize: Integer;
		FBlake2: IHashAlgorithm;
	protected
		function GetBlockSize: Integer;
		function GetDigestSize: Integer;
	public
		constructor Create(DigestSize: Integer);

		{ Methods }
		procedure HashData(const Buffer; BufferLen: Integer);
		function Finalize: TBytes;

		{ Properties }
		property BlockSize: Integer read GetBlockSize;
		property DigestSize: Integer read GetDigestSize;

	end;

{ TArgon2 }

class function TArgon2.Base64Decode(const s: string): TBytes;

const
	Base64DecodeTable: array[#0..#127] of Integer = (
			{  0:} -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  // ________________
			{ 16:} -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  // ________________
			{ 32:} -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,  // _______________/
			{ 48:} 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,  // 0123456789______
			{ 64:} -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,  // _ABCDEFGHIJKLMNO
			{ 80:} 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,  // PQRSTUVWXYZ_____
			{ 96:} -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,  // _abcdefghijklmno
			{113:} 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1); // pqrstuvwxyz_____


	function Char64(character: Char): Integer;
	begin
		if (Ord(character) > Length(Base64DecodeTable)) then
		begin
			Result := -1;
			Exit;
		end;

		Result := Base64DecodeTable[character];
	end;

	procedure Append(value: Byte);
	var
		i: Integer;
	begin
		i := Length(Result);
		SetLength(Result, i+1);
		Result[i] := value;
	end;

var
	i: Integer;
	len: Integer;
	c1, c2, c3, c4: Integer;
begin
	SetLength(Result, 0);

	len := Length(s);
	i := 1;
	while i <= len do
	begin
		// We'll need to have at least 2 character to form one byte.
		// Anything less is invalid
		if (i+1) > len then
			raise EArgon2Exception.Create('Invalid base64 hash string');

		c1 := Char64(s[i  ]);
		c2 := Char64(s[i+1]);
		c3 := -1;
		c4 := -1;
		if (i+2) <= len then
		begin
			c3 := Char64(s[i+2]);
			if (i+3) <= len then
				c4 := Char64(s[i+3]);
		end;
		Inc(i, 4);

		if (c1 = -1) or (c2 = -1) then
			raise EArgon2Exception.Create('Invalid base64 hash string');

		//Now we have at least one byte in c1|c2
		// c1 = ..111111
		// c2 = ..112222
		Append( ((c1 and $3f) shl 2) or (c2 shr 4) );

		if (c3 = -1) then
			Exit;

		//Now we have the next byte in c2|c3
		// c2 = ..112222
		// c3 = ..222233
		Append( ((c2 and $0f) shl 4) or (c3 shr 2) );

		//If there's a 4th caracter, then we can use c3|c4 to form the third byte
		if (c4 = -1) then
			Exit;

		//Now we have the next byte in c3|c4
		// c3 = ..222233
		// c4 = ..333333
		Append( ((c3 and $03) shl 6) or c4 );
	end;
end;

class function TArgon2.Base64Encode(const data: array of Byte): string;

const
	Base64EncodeTable: array[0..63] of Char =
			{ 0:} 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'+
			{26:} 'abcdefghijklmnopqrstuvwxyz'+
			{52:} '0123456789+/';

	function EncodePacket(b1, b2, b3: Byte; Len: Integer): string;
	begin
		{
			11111111 22222222 33333333
			\____/\_____/\_____/\____/
			  |      |      |     |
			 c1     c2     c3    c4
		}
		Result := '====';

		Result[1] := Base64EncodeTable[b1 shr 2];
		Result[2] := Base64EncodeTable[((b1 and $03) shl 4) or (b2 shr 4)];
		if Len < 2 then Exit;

		Result[3] := Base64EncodeTable[((b2 and $0f) shl 2) or (b3 shr 6)];
		if Len < 3 then Exit;

		Result[4] := Base64EncodeTable[b3 and $3f];
	end;

var
	i: Integer;
	len: Integer;
	b1, b2: Integer;
begin
	Result := '';

	len := Length(data);
	if len = 0 then
		Exit;

	//encode whole 3-byte chunks  TV4S 6ytw fsfv kgY8 jIuc Drjc 8deX 1s.
	i := Low(data);
	while len >= 3 do
	begin
		Result := Result+EncodePacket(data[i], data[i+1], data[i+2], 3);
		Inc(i, 3);
		Dec(len, 3);
	end;

	if len = 0 then
		Exit;

	//encode partial final chunk
	Assert(len < 3);
	if len >= 1 then
		b1 := data[i]
	else
		b1 := 0;
	if len >= 2 then
		b2 := data[i+1]
	else
		b2 := 0;
	Result := Result+EncodePacket(b1, b2, 0, len);
end;

class procedure TArgon2.BurnBytes(var data: TBytes);
begin
	if Length(data) <= 0 then
		Exit;

	FillChar(data[Low(data)], Length(data), 0);
	SetLength(data, 0);
end;

const
	//The Blake2 IV comes from the SHA2-512 IV.
	//The values are the the fractional part of the square root of the first 8 primes (2, 3, 5, 7, 11, 13, 17, 19)
	IV: array[0..7] of Int64 = (
			Int64($6A09E667F3BCC908), //frac(sqrt(2))
			Int64($BB67AE8584CAA73B), //frac(sqrt(3))
			Int64($3C6EF372FE94F82B), //frac(sqrt(5))
			Int64($A54FF53A5F1D36F1), //frac(sqrt(7))
			Int64($510E527FADE682D1), //frac(sqrt(11))
			Int64($9B05688C2B3E6C1F), //frac(sqrt(13))
			Int64($1F83D9ABFB41BD6B), //frac(sqrt(17))
			Int64($5BE0CD19137E2179)  //frac(sqrt(19))
	);

	SIGMA: array[0..9] of array[0..15] of Integer = (
			( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15),
			(14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3),
			(11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4),
			( 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8),
			( 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13),
			( 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9),
			(12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11),
			(13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10),
			( 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5),
			(10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0)
	);

class function TArgon2.CheckPassword(const Password: UnicodeString; const ExpectedHashString: string; out PasswordRehashNeeded: Boolean): Boolean;
var
	ar: TArgon2;
	algorithm: string;
	version, iterations, memorySizeKB, parallelism: Integer;
	salt, expected, actual: TBytes;
	t1, t2, freq: Int64;
	duration: Real;
begin
	Result := False;
	PasswordRehashNeeded := False;

	ar := TArgon2.Create;
	try
		if not ar.TryParseHashString(ExpectedHashString, {out}algorithm, {out}version, {out}iterations, {out}memorySizeKB, {out}parallelism, {out}salt, {out}expected) then
			raise EArgon2Exception.Create('Could not parse password hash string');
		try
			QueryPerformanceCounter(t1);
			actual := TArgon2.DeriveBytes(Password, Length(Password)*SizeOf(WideChar), salt, iterations, memorySizeKB, parallelism, 32);
			QueryPerformanceCounter(t2);

			if Length(actual) <> Length(expected) then
				Exit;

			Result := CompareMem(@expected[0], @actual[0], Length(expected));

			if Result then
			begin
				//Only advertise a rehash being needed if they got the correct password.
				//Don't want someone blindly re-hashing with a bad password because they forgot to check the result,
				//or because they decided to handle "PasswordRehashNeeded" first.
				if QueryPerformanceFrequency(freq) then
				begin
					duration := (t2-t1)/freq * 1000; //ms
					if duration < 250 then
						PasswordRehashNeeded := True;
				end;
			end;
		finally
			ar.BurnBytes(actual);
			ar.BurnBytes(expected);
		end;
	finally
		ar.Free;
	end;
end;

constructor TArgon2.Create;
begin
	inherited Create;

	SetLength(FPassword, 0);
	FMemorySizeKB := 128*1024; //128 MB
	FHashType := 1; //0=Argon2d, 1=Argon2i, 2=Argon2id
	FDegreeOfParallelism := 1; //1 thread
	FIterations := 1000; //1000 iterations
	SetLength(FSalt, 0); //we can't generate salt for them; they need to know what it was
	SetLength(FAssociatedData, 0);
	SetLength(FKnownSecret, 0);
end;

class function TArgon2.CreateHash(AlgorithmName: string; cbHashLen: Integer; const Key; const cbKeyLen: Integer): IUnknown;
begin
	if AlgorithmName = 'Blake2b.Optimized' then
		Result := TBlake2bOptimized.Create(Key, cbKeyLen, cbHashLen)
	else if AlgorithmName = 'Blake2b.Safe' then
		Result := TBlake2b.Create(Key, cbKeyLen, cbHashLen)
	else if AlgorithmName = 'Blake2b' then
		Result := TArgon2.CreateHash('Blake2b.Optimized', cbHashLen, Key, cbKeyLen)
	else
		raise EArgon2Exception.CreateFmt('Unknown hash algorithmname "%s"', [AlgorithmName]);
end;

class function TArgon2.CreateObject(ObjectName: string): IUnknown;
begin
	if ObjectName = 'Blake2b' then
		Result := TArgon2.CreateObject('Blake2b.Optimized')
	else if ObjectName = 'Blake2b.Safe' then
		Result := TBlake2b.Create(Pointer(nil)^, 0, 64)
	else if ObjectName = 'Blake2b.Optimized' then
		Result := TBlake2bOptimized.Create(Pointer(nil)^, 0, 64)
	else
		raise EArgon2Exception.CreateFmt('Unknown object name "%s"', [ObjectName]);
end;

class function TArgon2.DeriveBytes(const Passphrase; PassphraseLength: Integer; const Salt: TBytes; Iterations, MemorySizeKB, Parallelism: Integer; nDesiredBytes: Integer): TBytes;
var
	ar: TArgon2;
begin
	{
		Iterations (t): Number of iterations
				Used to determine the running time independantly of the memory size
				1 - 0x7FFFFFFF
		Parallelism (p): Degree of Parallelism
				Determines how many independant (but synchronizing) computational chains can be run.
				1 - 0x00FFFFFF
		MemorySizeKB (m): number of kilobyes
				8p - 0x7FFFFFFF

		Secret value (K): Serves as a key if necessary
				0 - 32 bytes
	}

	//Unhelpfully, Argon2 doesn't
	ar := TArgon2.Create();
	try
		ar.Iterations := Iterations;
		ar.MemorySizeKB := MemorySizeKB;
		ar.DegreeOfParallelism := Parallelism;
		ar.Salt := Salt;

		Result := ar.GetBytes(Passphrase, PassphraseLength, nDesiredBytes);
	finally
		ar.Free;
	end;
end;

function TArgon2.FormatPasswordHash(const Algorithm: string; Version: Integer;
		const Iterations, MemoryFactor, Parallelism: Integer; const Salt, DerivedBytes: array of Byte): string;
var
	saltString: string;
	hashString: string;
	KBRequired: Integer; //2^MemoryFactor = KB = KiB
begin
	{
		Type:           Argon2i
		Version:        19
		Iterations:     2
		Memory:         16 ==> 2^16 = 65536 = 65536 KB
		Parallelism:    4
		Salt:           736F6D6573616c74
		Hash:           45d7ac72e76f242b20b77b9bf9bf9d5915894e669a24e6c6

		Result:         $argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
	}
	saltString := Base64Encode(Salt);
	hashString := Base64Encode(DerivedBytes);
	KBRequired := 1 shl MemoryFactor;

	Result := Format('$%s$v=%d$m=%d,t=%d,p=%d$%s$%s', [
			Algorithm,     //"argon2i", "argon2d"
			Version,       //19
			KBRequired,    //65535 KB
			Parallelism,   //4
			saltString,    //"c29tZXNhbHQ"
			hashString		//"RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
	]);
end;

function TArgon2.GenerateSalt: TBytes;
var
	type4Uuid: TGUID;
	salt: TBytes;
const
	ARGON2_SALT_LEN = 16; //Salt is a 128-bit (16 byte) random value
begin
	SetLength(salt, ARGON2_SALT_LEN);

	//Use real random data. Fallback to random guid if it fails
	if Failed(Self.GenRandomBytes(ARGON2_SALT_LEN, {out}@salt[0])) then
	begin
		//Type 4 UUID (RFC 4122) is a handy source of (almost) 128-bits of random data (actually 120 bits)
		//But the security doesn't come from the salt being secret, it comes from the salt being different each time
		OleCheck(CoCreateGUID(Type4Uuid));
		Move(type4Uuid.D1, salt[0], ARGON2_SALT_LEN); //16 bytes
	end;

	Result := salt;
end;

class function TArgon2.GenRandomBytes(len: Integer; const data: Pointer): HRESULT;
var
	hProv: THandle;
const
	PROV_RSA_FULL = 1;
	CRYPT_VERIFYCONTEXT = DWORD($F0000000);
	CRYPT_SILENT         = $00000040;
begin
	if not CryptAcquireContextW(hPRov, nil, nil, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT or CRYPT_SILENT) then
	begin
		Result := HResultFromWin32(GetLastError);
		Exit;
	end;
	try
		if not CryptGenRandom(hProv, len, data) then
		begin
			Result := HResultFromWin32(GetLastError);
			Exit;
		end;
	finally
		CryptReleaseContext(hProv, 0);
	end;

	Result := S_OK;
end;

type
	TLane = class(TObject)
	public
		BlockCount: Integer;
	end;

function TArgon2.GetBytes(const Passphrase; PassphraseLength: Integer; DesiredNumberOfBytes: Integer): TBytes;
var
	lanes: array of TArray<UInt64>;
	i, j, s, l: Integer;
	iref, jref: Integer;
	segmentLength: Integer;
	start: Integer;
	currOffset, prevOffset: Integer;
	digest: TBytes;
	prevLane: Integer;
	c: Integer;
	h0: TBytes;
	columnCount, blockCount: Integer;
	B: TBytes;
const
	SDesiredBytesMaxError = 'Argon2 only supports generating a maximum of 1,024 bytes (Requested %d bytes)';
	SInvalidIterations = 'Argon2 hash requires at least 1 iteration (Requested %d)';
	SInvalidMemorySize = 'Argon2 requires at least 4 KB to be used (Requested %d KB)';
	SInvalidParallelism = 'Argon2 requires at one 1 thread (Requested %d parallelism)';
	BlockStride = 128;
begin
	if DesiredNumberOfBytes > 1024 then
		raise EArgon2Exception.CreateFmt(SDesiredBytesMaxError, [DesiredNumberOfBytes]);
	if FIterations < 1 then
		raise EArgon2Exception.CreateFmt(SInvalidIterations, [FIterations]);
	if FMemorySizeKB < 4 then
		raise EArgon2Exception.CreateFmt(SInvalidMemorySize, [FMemorySizeKB]);
	if FDegreeOfParallelism < 1 then
		raise EArgon2Exception.CreateFmt(SInvalidParallelism, [FDegreeOfParallelism]);

	//Generate the initial 64-byte block h0
	h0 := Self.GenerateSeedBlock(Passphrase, PassphraseLength, DesiredNumberOfBytes);

	//Calculate number of 1 KiB blocks by rounding down memorySizeKB to the nearest multiple of 4*DegreeOfParallelism kilobytes
	columnCount := memorySizeKB div 4 div FDegreeOfParallelism;
	blockCount := columnCount * FDegreeOfParallelism;

	//Allocate two-dimensional array of 1 KiB blocks (parallelism rows x columnCount columns)
	SetLength(lanes, FDegreeOfParallelism);
	for i := 0 to FDegreeOfParallelism-1 do
		SetLength(lanes[i], columnCount*1024 div SizeOf(UInt64));

	//Compute the first and second blocks of each lane (i.e. column zero and one)
	for i := 0 to FDegreeOfParallelism-1 do
	begin
		//lanes[i][0] := Hash(H0 || 0 || i);
		digest := GenerateInitialBlock(h0, 0, i);
		Move(digest[0], lanes[i][0], 1024);

		//lanes[i][1] := Hash(H0 || 1 || i);
		GenerateInitialBlock(h0, 1, i);
		Move(digest[0], lanes[i][BlockStride], 1024);
	end;

	//Compute remaining columns of each lane
	for i := 0 to FDegreeOfParallelism-1 do //for each row
	begin
		for j := 2 to columnCount-1 do //for each subsequent column
		begin
			//iref and jref indexes depend if it's Argon2i, Argon2d, or Argon2id (See section 3.4)
			//GetBlockIndexes(i, j, {out}iref, {out}jref);
			//Bi[j] = G(Bi[j-1], Biref[jref])
		end;
	end;

end;

function TArgon2.GenerateInitialBlock(const H0: TBytes; ColumnIndex, LaneIndex: Integer): TBytes;
var
	hash: IHashAlgorithm;
begin
	hash := TArgon2Hash.Create(1024);

	//block = Hash( h0 || columnIndex || LaneIndex, 1024);
	hash.HashData(h0[0], Length(h0));
	hash.HashData(ColumnIndex, 4);
	hash.HashData(LaneIndex, 4);

	Result := hash.Finalize;
end;

function TArgon2.GenerateSeedBlock(const Passphrase; PassphraseLength: Integer; DesiredNumberOfBytes: Integer): TBytes;
var
	blake2b: IHashAlgorithm;
	n: Integer;
begin
	{
		Generate the 64-byte H0 seed block
	}
	blake2b := Self.CreateObject('Blake2b') as IHashAlgorithm;

	blake2b.HashData(FDegreeOfParallelism, 4);
	blake2b.HashData(DesiredNumberOfBytes, 4);
	blake2b.HashData(FMemorySizeKB, 4);
	blake2b.HashData(FIterations, 4);
	blake2b.HashData(Cardinal(ARGON_VERSION), 4);
	blake2b.HashData(FHashType, 4);

	//Variable length items are prepended with their length
	blake2b.HashData(PassphraseLength, 4);
	blake2b.HashData(Passphrase, PassphraseLength);

	n := Length(FSalt);
	blake2b.HashData(n, 4);
	blake2b.HashData(PByte(FSalt)^, Length(FSalt));

	n := Length(FKnownSecret);
	blake2b.HashData(n, 4);
	blake2b.HashData(PByte(FKnownSecret)^, Length(FKnownSecret));

	n := Length(FAssociatedData);
	blake2b.HashData(n, 4);
	blake2b.HashData(PByte(FAssociatedData)^, Length(FAssociatedData));

	Result := blake2b.Finalize;
end;


procedure TArgon2.GetDefaultParameters(out Iterations, MemoryFactor, Parallelism: Integer);
begin

end;

class function TArgon2.HashPassword(const Password: UnicodeString): string;
var
	iterations, memorySizeKB, degreeOfParallelism: Integer;
begin
	iterations := 10000;      // 10,000 iterations
	memorySizeKB := 128*1024; // 128 MB
	degreeOfParallelism := 1; // 1 thread

	Result := TArgon2.HashPassword(Password, iterations, memorySizeKB, degreeOfParallelism);
end;

class function TArgon2.Hash(const Buffer; BufferLen: Integer; DigestSize: Cardinal): TBytes;
var
	blake2b: IHashAlgorithm;
	digest: TBytes;
begin
	{
		This is a variable length hash function, that can generate digests up to 2^32 bytes
	}
	if DigestSize <= 64 then
	begin
		blake2b := Self.CreateObject('Blake2b') as IHashAlgorithm;
		blake2b.HashData(Buffer, BufferLen);
		Result := blake2b.Finalize;
		if DigestSize < 64 then
		begin
			//Grab first DigestSize bytes
			SetLength(digest, DigestSize);
			Move(Result[0], digest[0], DigestSize);
			Result := digest;
		end;
		Exit;
	end;

	raise ENotImplemented.Create('todo: digests over 64-bytes');

	//For desired digest sizes over 64 bytes, we generate a series of 64-byte blocks, and use the first 32-bytes from each

	//Number of whole blocks (knowing we're going to only use 32-bytes from each)


end;

class function TArgon2.HashPassword(const Password: UnicodeString; const Iterations, MemorySizeKB, Parallelism: Integer): string;
var
	salt, derivedBytes: TBytes;
	utf8Password: TBytes;
	ar: TArgon2;
begin
	{
		Iterations (t): Number of iterations
				Used to determine the running time independantly of the memory size
				1 - 0x7FFFFFFF
		Parallelism (p): Degree of Parallelism
				Determines how many independant (but synchronizing) computational chains can be run.
				1 - 0x00FFFFFF
		MemorySizeKB (m): power of two number of kilobyes (minimum of 8*Parallelism KB)
				8p - 0x7FFFFFFF
	}

	if MemorySizeKB < (8*Parallelism) then
		raise EArgon2Exception.CreateFmt('Requested MemorySizeKB (%d) is to small to handle desired Parallelism (%d)', [MemorySizeKB, Parallelism]);

	ar := TArgon2.Create;
	try
		salt := ar.GenerateSalt;

		utf8Password := TArgon2.StringToUtf8(Password);
		try
			derivedBytes := TArgon2.DeriveBytes(utf8Password, Length(Password)*SizeOf(WideChar), salt, Iterations, MemorySizeKB, Parallelism, 32);
		finally
			TArgon2.BurnBytes({var}utf8Password);
		end;

		Result := ar.FormatPasswordHash('Argon2id', $13, Iterations, MemorySizeKB, Parallelism, salt, derivedBytes);
	finally
		ar.Free;
	end;
end;

class function TArgon2.StringToUtf8(const Source: UnicodeString): TBytes;
var
	strLen: Integer;
	dw: DWORD;
const
	CodePage = CP_UTF8;
begin
{
	For Argon2 passwords we will use UTF-8 encoding.
}
//	Result := TEncoding.UTF8.GetBytes(s);

	if Length(Source) = 0 then
	begin
		SetLength(Result, 0);
		Exit;
	end;

	// Determine real size of destination string, in bytes
	strLen := WideCharToMultiByte(CodePage, 0,
			PWideChar(Source), Length(Source), //Source
			nil, 0, //Destination
			nil, nil);
	if strLen = 0 then
	begin
		dw := GetLastError;
		raise EConvertError.Create('[StringToUtf8] Could not get length of destination string. Error '+IntToStr(dw)+' ('+SysErrorMessage(dw)+')');
	end;

	// Allocate memory for destination string
	SetLength(Result, strLen);

	// Convert source UTF-16 string (UnicodeString) to the destination using the code-page
	strLen := WideCharToMultiByte(CodePage, 0,
			PWideChar(Source), Length(Source), //Source
			PAnsiChar(@Result[0]), strLen, //Destination
			nil, nil);
	if strLen = 0 then
	begin
		dw := GetLastError;
		raise EConvertError.Create('[StringToUtf8] Could not convert utf16 to utf8 string. Error '+IntToStr(dw)+' ('+SysErrorMessage(dw)+')');
	end;
end;

class function TArgon2.TimingSafeSameString(const Safe, User: string): Boolean;
var
	i: Integer;
	safeLen, userLen: Integer;
	nDiff: Integer;
begin
	{
		A timing safe equals comparison

		To prevent leaking length information, it is important that user input is always used as the second parameter.

			safe The internal (safe) value to be checked
			user The user submitted (unsafe) value

		Returns True if the two strings are identical.
	}

	safeLen := Length(Safe);
	userLen := Length(User);

	// Set the result to the difference between the lengths
	nDiff := safeLen - userLen;

	// Note that we ALWAYS iterate over the user-supplied length
	// This is to prevent leaking length information
	for i := 0 to userLen-1 do
	begin
		// Using mod here is a trick to prevent notices.
		// It's safe, since if the lengths are different nDiff is already non-zero
		nDiff := nDiff or (
				Ord(Safe[(i mod safeLen) + 1])
				xor
				Ord(User[i+1])
		);
	end;

	 // They are only identical strings if nDiff is exactly zero
	Result := (nDiff = 0);
end;

class function TArgon2.Tokenize(const s: string; Delimiter: Char): TStringDynArray;
var
	iLength: integer;
	i: integer;
	szOutput: string;
	n: Integer;
begin
	iLength := Length(s);

	SetLength(Result, 0);

	for i := 1 to iLength do
	begin
		if s[i] = Delimiter then
		begin
			n := Length(Result);
			SetLength(Result, n+1);
			Result[n] := szOutput;
			szOutput := '';
		end
		else
			szOutput := szOutput + s[i];
	end;

	if szOutput <> '' then
	begin
		n := Length(Result);
		SetLength(Result, n+1);
		Result[n] := szOutput;
	end;
end;

function TArgon2.TryParseHashString(HashString: string;
		out Algorithm: string; out Version, Iterations, MemoryFactor, Parallelism: Integer;
		out Salt, Data: TBytes): Boolean;
var
	tokens: TStringDynArray;
	options: TStringDynArray;
	currIndex: Integer;
	a: string;
	b: Integer;
	i: Integer;

	function TryParseAB(const AeqB: string; out sName: string; nValue: Integer): Boolean;
	var
		lr: TStringDynArray;
	begin
		{
			Extract
				sName=nValue
			into
				sName <- String
				nValue <- Integer
		}
		Result := False;

		lr := Self.Tokenize(AeqB, '=');
		if Length(lr) <> 2 then Exit;

		A := lr[0];

		Result := TryStrToInt(lr[1], {out}B);
	end;
begin
(*
	$argon2<T>[$v=<num>]$m=<num>,t=<num>,p=<num>$<bin>$<bin>

	where
		<T> is either 'd', 'id', or 'i'
		<num> is a decimal integer (positive, fits in an 'unsigned long')
		<bin> is Base64-encoded data (no '=' padding characters, no newline or whitespace).

	The last two binary chunks (encoded in Base64) are, in that order, the salt and the output.
	Both are required. The binary salt length and the output length must be in the allowed ranges defined in argon2.h.
*)
	Result := False;
	Algorithm := '';
	Version := 0;
	Iterations := 0;
	MemoryFactor := 0;
	Parallelism := 0;
	SetLength(Salt, 0);
	SetLength(Data, 0);

{
	HashString:		$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG

		Algorithm:    "argon2i"
		Version:      19
		MemoryFactor: 16 (log2(65536) = 16)
		Iterations:   2
		Parallelism:  4
		Salt:         736F6D6573616c74
		Data:         45d7ac72e76f242b20b77b9bf9bf9d5915894e669a24e6c6
}

	if HashString = '' then
		Exit; //raise EArgon2Exception.Create('HashString cannot be empty');

	//All versions start with a "$"
	if HashString[1] <> '$' then
		Exit;

	SetLength(tokens, 0); //Variable 'tokens' might not have been initialized
	tokens := Self.Tokenize(HashString, '$');
		//tokens[0] ==> "" (the space before the first $)
		//tokens[1] ==> "argon2i"
		//tokens[2] ==> "v=19"
		//tokens[3] ==> "m=65536,t=2,p=4"
		//tokens[4] ==> "c29tZXNhbHQ"
		//tokens[5] ==> "RdescudvJCsgt3ub+b+dWRWJTmaaJObG"

	if (Length(tokens) <> 6) and (Length(tokens) <> 5) then Exit;

	currIndex := 1;
	if (not AnsiSameText(tokens[currIndex], 'argon2i')) and
			(not AnsiSameText(tokens[currIndex], 'argon2d')) and
			(not AnsiSameText(tokens[currIndex], 'argon2id')) then Exit;
	Algorithm := tokens[currIndex];
	Inc(currIndex);

	//"v=19" (optinal)
	if StartsWith(tokens[currIndex], 'v=') then
	begin
		if not TryParseAB(tokens[currIndex], {out}a, {out}b) then Exit;
		if not AnsiSameText(a, 'v') then Exit;
		Version := b;
		Inc(currIndex);
	end;

	//"m=65536,t=2,p=4"
	//	m: MemoryFactor
	//	t: Iterations
	//	p: Parallelism
	options := Self.Tokenize(tokens[currIndex], ',');
	if Length(options) <> 3 then Exit;
	for i := 0 to 2 do
	begin
		//"m=65536"
		if not TryParseAB(options[i], {out}a, {out}b) then Exit;

		if SameText(a, 'm') then
			MemoryFactor := b
		else if SameText(a, 't') then
			Iterations := b
		else if SameText(a, 'p') then
			Parallelism := b
		else
			Exit;
	end;
	Inc(currIndex);

	Salt := TArgon2.Base64Decode(tokens[currIndex]);
	Inc(currIndex);

	Data := TArgon2.Base64Decode(tokens[currIndex]);

	Result := True;
end;

class function TArgon2.UnicodeStringToUtf8(const Source: UnicodeString): TBytes;
var
	strLen: Integer;
	dw: DWORD;
const
	CodePage = CP_UTF8;
begin
{
	For Argon2 passwords we will use UTF-8 encoding.
}
//	Result := TEncoding.UTF8.GetBytes(s);

	if Length(Source) = 0 then
	begin
		SetLength(Result, 0);
		Exit;
	end;

	// Determine real size of destination string, in bytes
	strLen := WideCharToMultiByte(CodePage, 0,
			PWideChar(Source), Length(Source), //Source
			nil, 0, //Destination
			nil, nil);
	if strLen = 0 then
	begin
		dw := GetLastError;
		raise EConvertError.Create('[UnicodeStringToUtf8] Could not get length of destination string. Error '+IntToStr(dw)+' ('+SysErrorMessage(dw)+')');
	end;

	// Allocate memory for destination string
	SetLength(Result, strLen);

	// Convert source UTF-16 string (UnicodeString) to the destination using the code-page
	strLen := WideCharToMultiByte(CodePage, 0,
			PWideChar(Source), Length(Source), //Source
			PAnsiChar(@Result[0]), strLen, //Destination
			nil, nil);
	if strLen = 0 then
	begin
		dw := GetLastError;
		raise EConvertError.Create('[UnicodeStringToUtf8] Could not convert utf16 to utf8 string. Error '+IntToStr(dw)+' ('+SysErrorMessage(dw)+')');
	end;
end;

{ TBlake2b }

{$OVERFLOWCHECKS OFF}
{$RANGECHECKS OFF}
procedure TBlake2b.BlakeCompress(const m: PBlake2bBlockArray; cbBytesProcessed: Int64; IsFinalBlock: Boolean);
var
	V: TBlake2bBlockArray;  //local work vector
	S: array[0..15] of Integer; //current round message mixing schedule
	i: Integer;
const
	r = 12; //The number of rounds (Blake2b: 12, Blake2s: 10)
begin
	{
		Initialize local work vector
	}
	//V[0..7]  <- State[0..7]
	//V[8..15] <- IV[0..7]
	Move(h[0],  V[0], 8*SizeOf(Int64));
	Move(IV[0], V[8], 8*SizeOf(Int64));

	V[12] := UInt64(V[12] xor cbBytesProcessed);

	//Invert the bits in V[14] if this is the final block
	if IsFinalBlock then
		v[14] := UInt64(v[14] xor UInt64($FFFFFFFFFFFFFFFF));

	//Cryptographic mixing
	for i := 0 to r-1 do //0..11 (r=12 for for Blake2b)
	begin
		//Message word selection permutation for this round
		Move(SIGMA[i mod 10][0], S[0], 16*SizeOf(Integer));

		Self.BlakeMix(V[0], V[4], V[ 8], V[12], m[S[ 0]], m[S[ 1]]);
		Self.BlakeMix(V[1], V[5], V[ 9], V[13], m[S[ 2]], m[S[ 3]]);
		Self.BlakeMix(V[2], V[6], V[10], V[14], m[S[ 4]], m[S[ 5]]);
		Self.BlakeMix(V[3], V[7], V[11], V[15], m[S[ 6]], m[S[ 7]]);

		Self.BlakeMix(V[0], V[5], V[10], V[15], m[S[ 8]], m[S[ 9]]);
		Self.BlakeMix(V[1], V[6], V[11], V[12], m[S[10]], m[S[11]]);
		Self.BlakeMix(V[2], V[7], V[ 8], V[13], m[S[12]], m[S[13]]);
		Self.BlakeMix(V[3], V[4], V[ 9], V[14], m[S[14]], m[S[15]]);
	end;

	//Mix the upper and lower halves of V into ongoing state vector h
	for i := 0 to 7 do    //XOR the two halves into state
		h[i] := UInt64(h[i] xor V[i] xor V[i+8]);
end;

procedure TBlake2b.BlakeMix(var Va, Vb, Vc, Vd: UInt64; const x, y: Int64);
begin
	{
		The Mixing primitive function mixes two input words, "x" and "y",
		into four words indexed by "a", "b", "c", and "d"
		in the working vector v[0..15].
		The full modified vector is returned.
		The rotation constants (R1, R2, R3, R4) are given in Section 2.1.
	}
	Va := UInt64(va+vb+x);       //with input
	vd := UInt64(ROR64(UInt64(vd xor va), 32));

	vc := UInt64(vc + vd);       //no input
	vb := UInt64(ROR64(UInt64(vb xor vc), 24));

	va := UInt64(va + vb + y);   //with input
	vd := UInt64(ROR64(UInt64(vd xor va), 16));

	vc := UInt64(vc + vd);       //no input
	vb := UInt64(ROR64(UInt64(vb xor vc), 63));
end;
{$OVERFLOWCHECKS ON}
{$RANGECHECKS ON}

procedure TBlake2b.Burn;
begin
	FProcessed := 0;
	FBufferLength := 0;

	if Length(FKey) > 0 then
	begin
		FillChar(FKey[0], Length(FKey), 0);
		SetLength(FKey, 0);
	end;
	FInitialized := False;
	FillChar(h[0], Length(h)*SizeOf(Int64), 0); //State vector
	FillChar(FBuffer[0], Length(FBuffer), 0);
end;

constructor TBlake2b.Create(const Key; cbKeyLen: Integer; cbHashLen: Integer);
begin
	inherited Create;

	if (cbHashLen < 0) or (cbHashLen > 64) then
		raise EArgon2Exception.CreateFmt('Invalid Blake2b desired hash length: %d', [cbHashLen]);
	if (cbKeyLen < 0) or (cbKeyLen > 64) then
		raise EArgon2Exception.CreateFmt('Invalid Blake2b key length: %d', [cbKeyLen]);

	Self.Burn;

	FDigestSize := cbHashLen;
	SetLength(FKey, cbKeyLen);
	if cbKeyLen > 0 then
		Move(Key, FKey[0], cbKeyLen);
end;

destructor TBlake2b.Destroy;
begin
	Self.Burn;

	inherited;
end;

function TBlake2b.Finalize: TBytes;
begin
	if not FInitialized then
		Self.Initialize;

	//We now have our last block
	//Fill our zero-padded chunk array with any remaining bytes
	//pChunk will point to this temporary buffer
	if (FBufferLength > 0) or (FProcessed = 0) then
	begin
		if FBufferLength < 128 then
			ZeroMemory(@FBuffer[FBufferLength], 128-FBufferLength);
		Inc(FProcessed, FBufferLength);
		BlakeCompress(@FBuffer[0], FProcessed, True);
	end;

	//RETURN first "DesiredHashBytes" bytes from little-endian word array h[].
	SetLength(Result, FDigestSize);
	Move(h[0], Result[0], FDigestSize);

	FInitialized := False;
end;

function TBlake2b.GetBlockSize: Integer;
begin
	Result := 128; //128-bytes
end;

function TBlake2b.GetDigestSize: Integer;
begin
	Result := FDigestSize;
end;

procedure TBlake2b.HashData(const Buffer; BufferLen: Integer);
var
	cbRemaining: Int64;
	bufferRoom: Integer;
	bytesToCopy: Integer;
	source: PByte;
begin
	{
		Input:
			M:             The message to be hashed
			cbMessageLen:  Number of bytes in original message (0..2^128)
			Key:           Optional key material (0..64 bytes)
			cbKeyLen:      Number of bytes of key material (0..64)
			cbHashLen:     Desired size in bytes of returned hash (1..64)
		Output:
			Result:        Hash of cbHashLen bytes long
	}
	if not FInitialized then
		Self.Initialize;

	if BufferLen <= 0 then
		Exit;

	cbRemaining := BufferLen;

	source := @Buffer;

	if (FBufferLength > 0) and (FBufferLength < 128) then
	begin
		//Fill our partial buffer
		bufferRoom := 128 - FBufferLength;
		bytesToCopy := cbRemaining;
		if bytesToCopy > bufferRoom then
			bytesToCopy := bufferRoom;

		Move(source^, FBuffer[FBufferLength], bytesToCopy);
		Inc(FBufferLength, bytesToCopy);
		Inc(source, bytesToCopy);
		Dec(cbRemaining, bytesToCopy);
	end;

	if cbRemaining <= 0 then
		Exit;

	//there are more bytes to deal with; that means we know that our pending block is not the final
	if FBufferLength >= 128 then
	begin
		Inc(FProcessed, 128);
		BlakeCompress(@FBuffer[0], FProcessed, False);
		FBufferLength := 0;
	end;

	while cbRemaining > 128 do
	begin
		Inc(FProcessed, 128);
		BlakeCompress(Pointer(source), FProcessed, False);
		Inc(source, 128);
		Dec(cbRemaining, 128);
	end;

	//Store any partial block data in our buffer
	if cbRemaining > 0 then
	begin
		FBufferLength := cbRemaining;
		Move(source^, FBuffer[0], cbRemaining);
	end;
end;

procedure TBlake2b.Initialize;
begin
	FProcessed := 0;
	FBufferLength := 0;

	//Initialize state vector h with IV
	Move(IV[0], h[0], 8*SizeOf(Int64));


	// Mix key size (cbKeyLen) and desired hash length (cbHashLen) into h0
	// 0x0101kknn
	//       kk   is key length in bytes
	//         nn is the desired hash length in bytes
	h[0] := Int64(h[0] xor $01010000 xor (Length(FKey) shl 8) xor FDigestSize);

	//If we were passed a key, then pad it to 128 bytes, and pass it as our first chunk
	if Length(FKey) > 0 then
	begin
		ZeroMemory(@FBuffer[0], Length(FBuffer));
		Move(FKey[0], FBuffer[0], Length(FKey));
		FBufferLength := 128;
		//We'll process it the next block we try to hash (even if that means during Finalize)
	end;

	FInitialized := True;
end;

function ROR64(const Value: Int64; const n: Integer): Int64;
var
	i: Int64Rec absolute Value;
	r: Int64Rec absolute Result;
begin
	{
		Rotate-right
	}
	case n of
	32:
		begin
			//It is a swap of Lo and Hi
			r.Lo := i.hi;
			r.Hi := i.Lo;
		end;
	24:
		begin
			r.lo := (i.hi shl  8) or (i.lo shr 24);
			r.hi := (i.hi shr 24) or (i.lo shl  8);
		end;
	16:
		begin
			r.lo := (i.hi shl 16) or (i.lo shr 16);
			r.hi := (i.hi shr 16) or (i.lo shl 16);
		end;
	63:
		begin
			r.lo := (i.lo shl 1) or (i.hi shr 31);
			r.hi := (i.hi shl 1) or (i.lo shr 31);
		end;
	else
		raise EArgon2Exception.Create('');
	end;
end;

type
	TVector16i = array[0..15] of Integer;
	PVector16i = ^TVector16i;

	function GetMemAligned(AlignmentBytes: Cardinal; Size: Integer; out RawPointer: Pointer): Pointer;
	var
		n: NativeUInt;
	begin
		RawPointer := GetMemory(Size+AlignmentBytes);

		n := NativeUInt(RawPointer);
		if (n mod AlignmentBytes) <> 0 then
		begin
			n := n - (n mod AlignmentBytes) + AlignmentBytes;
		end;

		Result := Pointer(n);
		Assert(n mod AlignmentBytes = 0);
	end;

function __AddInt64(a: Int64; b: Int64): Int64;
asm
	movq  xmm0, a;
	movq  xmm1, b;
	paddq xmm0, xmm1;
//	paddq xmm0, b;

//	movq  a,  xmm0;
	movq Result, xmm0;
//	movq Result, a;
end;

{ TBlake2bOptimized }

{$OVERFLOWCHECKS OFF}
{$RANGECHECKS OFF}
procedure TBlake2bOptimized.BlakeCompress(const m: PBlake2bBlockArray; cbBytesProcessed: Int64; IsFinalBlock: Boolean);
var
	v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15: UInt64;
	Scurrent: PVector16i;
	s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15: Integer;
	i: Integer; //indexes
	t1, t2, t3, t4: UInt64Rec;
	x: Integer;
	raw: Pointer;
const
	r = 12; //The number of rounds (Blake2b: 12, Blake2s: 10)
	SIGMA: array[0..11] of array[0..15] of Integer = (
			//0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
			( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15),
			(14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3),
			(11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4),
			( 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8),
			( 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13),
			( 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9),
			(12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11),
			(13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10),
			( 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5),
			(10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0),
			( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15),
			(14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3)
	);

begin
	{
		Initialize local work vector
	}
	//V[0..7]  <- State[0..7]
	//V[8..15] <- IV[0..7]

//	v := GetMemAligned(16, 16*SizeOf(UInt64), {out}raw);

	//Check that it's aligned on a 16-byte boundary
//	if (IntPtr(@v[0]) mod 16) <> 0 then
//		raise Exception.CreateFmt('V alignment not 16 (%d, %d)', [IntPtr(@v[0]), IntPtr(@v[0]) mod 16]);


	v0  := h[0];
	v1  := h[1];
	v2  := h[2];
	v3  := h[3];
	v4  := h[4];
	v5  := h[5];
	v6  := h[6];
	v7  := h[7];
	v8  := IV[0];
	v9  := IV[1];
	v10 := IV[2];
	v11 := IV[3];
	v12 := IV[4] xor cbBytesProcessed;
	v13 := IV[5];
	v14 := IV[6];
	v15 := IV[7];

	//Invert the bits in V[14] if this is the final block
	if IsFinalBlock then
		v14 := v14 xor UInt64($FFFFFFFFFFFFFFFF);

	//Cryptographic mixing
	for i := 0 to r-1 do //0..11 (r=12 for for Blake2b)
	begin
		//Message word selection permutation for this round
{
		Because we unwrap the loops, we access the SIGMA array in the index order:

			0	2	4	6
			1	3	5	7
			8	10	12	14
			9	11	13	15

		So i'm going to cache the current SIGMA into local S, but rearranged in this order.
}
		Scurrent := @SIGMA[i];
{		S[ 0] := Scurrent[ 0];	S[ 1] := Scurrent[ 2];	S[ 2] := Scurrent[ 4];	S[ 3] := Scurrent[ 6];
		S[ 4] := Scurrent[ 1];	S[ 5] := Scurrent[ 3];	S[ 6] := Scurrent[ 5];	S[ 7] := Scurrent[ 7];
		S[ 8] := Scurrent[ 8];	S[ 9] := Scurrent[10];	S[10] := Scurrent[12];	S[11] := Scurrent[14];
		S[12] := Scurrent[ 9];	S[13] := Scurrent[11];	S[14] := Scurrent[13];	S[15] := Scurrent[15];}
		S0  := Scurrent[ 0];	S1  := Scurrent[ 2];	S2  := Scurrent[ 4];	S3  := Scurrent[ 6];
		S4  := Scurrent[ 1];	S5  := Scurrent[ 3];	S6  := Scurrent[ 5];	S7  := Scurrent[ 7];
		S8  := Scurrent[ 8];	S9  := Scurrent[10];	S10 := Scurrent[12];	S11 := Scurrent[14];
		S12 := Scurrent[ 9];	S13 := Scurrent[11];	S14 := Scurrent[13];	S15 := Scurrent[15];

		//Mix input
		//v[0,1,2,3] += v[4,5,6,7] + m[S[0,2,4,6]]
		v0 := v0+v4;
		v1 := v1+v5;
		v2 := v2+v6;
		v3 := v3+v7;
		v0 := v0+m[s0];
		v1 := v1+m[s1];
		v2 := v2+m[s2];
		v3 := v3+m[s3];

		//v[12..15] = (v[12..15] xor v[0..3]) ror 32
		v12 := (v12 xor v0);
		v13 := (v13 xor v1);
		v14 := (v14 xor v2);
		v15 := (v15 xor v3);
		v12 := (v12 shr 32) or (v12 shl 32);
		v13 := (v13 shr 32) or (v13 shl 32);
		v14 := (v14 shr 32) or (v14 shl 32);
		v15 := (v15 shr 32) or (v15 shl 32);

		//No input
		//v[8..11] += v[12..15]
		//Inc(v[ 8], v[12]);  Inc(v[ 9], v[13]);  Inc(v[10], v[14]);  Inc(v[11], v[15]);
		v8  := v8 + v12;
		v9  := v9 + v13;
		v10 := v10 + v14;
		v11 := v11 + v15;
		//V[4..7] = (V[4..7] xor V[8..11]) ror 24
		t1.Value := v4 xor v8;
		t2.Value := v5 xor v9;
		t3.Value := v6 xor v10;
		t4.Value := v7 xor v11;
		PUInt64Rec(@v4).lo := (t1.Hi shl  8) or (t1.lo shr 24); PUInt64Rec(@v4).hi := (t1.Hi shr 24) or (t1.lo shl  8);
		PUInt64Rec(@v5).lo := (t2.Hi shl  8) or (t2.lo shr 24); PUInt64Rec(@v5).hi := (t2.Hi shr 24) or (t2.lo shl  8);
		PUInt64Rec(@v6).lo := (t3.Hi shl  8) or (t3.lo shr 24); PUInt64Rec(@v6).hi := (t3.Hi shr 24) or (t3.lo shl  8);
		PUInt64Rec(@v7).lo := (t4.Hi shl  8) or (t4.lo shr 24); PUInt64Rec(@v7).hi := (t4.Hi shr 24) or (t4.lo shl  8);

		//Mix input
		//v[0..3] += v[4..7] + m[S[1,3,5,7]]
		v0 := v0 + v4;
		v1 := v1 + v5;
		v2 := v2 + v6;
		v3 := v3 + v7;
		v0 := v0 + m[S4];
		v1 := v1 + m[S5];
		v2 := v2 + m[S6];
		v3 := v3 + m[S7];
		//V[12..15] = (V[12..15] xor V[0..3]) ror 16
		t1.Value := v12 xor v0;
		t2.Value := v13 xor v1;
		t3.Value := v14 xor v2;
		t4.Value := v15 xor v3;
		PUInt64Rec(@v12).lo := (t1.Hi shl 16) or (t1.lo shr 16); PUInt64Rec(@v12).hi := (t1.Hi shr 16) or (t1.lo shl 16);
		PUInt64Rec(@v13).lo := (t2.Hi shl 16) or (t2.lo shr 16); PUInt64Rec(@v13).hi := (t2.Hi shr 16) or (t2.lo shl 16);
		PUInt64Rec(@v14).lo := (t3.Hi shl 16) or (t3.lo shr 16); PUInt64Rec(@v14).hi := (t3.Hi shr 16) or (t3.lo shl 16);
		PUInt64Rec(@v15).lo := (t4.Hi shl 16) or (t4.lo shr 16); PUInt64Rec(@v15).hi := (t4.Hi shr 16) or (t4.lo shl 16);

		//No Input
		//V[8..11] = V[8..1] + V[12..15]
		v8 := v8 + v12;
		v9 := v9 + v13;
		v10 := v10 + v14;
		v11 := v11 + v15;
		//V[4..7] = (V[4..11] xor V[8..11]) ror 63
		t1.Value := v4 xor v8;
		t2.Value := v5 xor v9;
		t3.Value := v6 xor v10;
		t4.Value := v7 xor v11;
		PUInt64Rec(@v4).lo := (t1.Hi shr 31) or (t1.lo shl  1); PUInt64Rec(@v4).hi := (t1.Hi shl  1) or (t1.lo shr 31);
		PUInt64Rec(@v5).lo := (t2.Hi shr 31) or (t2.lo shl  1); PUInt64Rec(@v5).hi := (t2.Hi shl  1) or (t2.lo shr 31);
		PUInt64Rec(@v6).lo := (t3.Hi shr 31) or (t3.lo shl  1); PUInt64Rec(@v6).hi := (t3.Hi shl  1) or (t3.lo shr 31);
		PUInt64Rec(@v7).lo := (t4.Hi shr 31) or (t4.lo shl  1); PUInt64Rec(@v7).hi := (t4.Hi shl  1) or (t4.lo shr 31);

		{
			Second half
		}
		//Mix input
		//V[0..3] += V[5,6,7,4] + m[S[8,10,12,14]]
		v0 := v0 + v5;
		v1 := v1 + v6;
		v2 := v2 + v7;
		v3 := v3 + v4;
		v0 := v0 + m[S8];
		v1 := v1 + m[S9];
		v2 := v2 + m[S10];
		v3 := v3 + m[S11];
		//V[12..15] = (V[12..15] xor V[1230]) ror 32
		t1.Value := (v12 xor v1);
		t2.Value := (v13 xor v2);
		t3.Value := (v14 xor v3);
		t4.Value := (v15 xor v0);
		PUInt64Rec(@v12).Lo := t1.Hi; PUInt64Rec(@v12).Hi := t1.Lo;
		PUInt64Rec(@v13).Lo := t2.Hi; PUInt64Rec(@v13).Hi := t2.Lo;
		PUInt64Rec(@v14).Lo := t3.Hi; PUInt64Rec(@v14).Hi := t3.Lo;
		PUInt64Rec(@v15).Lo := t4.Hi; PUInt64Rec(@v15).Hi := t4.Lo;

		//V[8..11] += V[13,14,15,12]
		//Inc(v[ 8], v[13]); Inc(v[ 9], v[14]); Inc(v[10], v[15]); Inc(v[11], v[12]);
		v8 := v8 + v13;
		v9 := v9 + v14;
		v10 := v10 + v15;
		v11 := v11 + v12;
		//V[4..7] = (V[5,6,7,4] xor V[10,11,8,9]) ror 24
		t1.Value := v5 xor v10;
		t2.Value := v6 xor v11;
		t3.Value := v7 xor v8;
		t4.Value := v4 xor v9;
		PUInt64Rec(@v5).lo := (t1.Hi shl  8) or (t1.lo shr 24); PUInt64Rec(@v5).hi := (t1.Hi shr 24) or (t1.lo shl  8);
		PUInt64Rec(@v6).lo := (t2.Hi shl  8) or (t2.lo shr 24); PUInt64Rec(@v6).hi := (t2.Hi shr 24) or (t2.lo shl  8);
		PUInt64Rec(@v7).lo := (t3.Hi shl  8) or (t3.lo shr 24); PUInt64Rec(@v7).hi := (t3.Hi shr 24) or (t3.lo shl  8);
		PUInt64Rec(@v4).lo := (t4.Hi shl  8) or (t4.lo shr 24); PUInt64Rec(@v4).hi := (t4.Hi shr 24) or (t4.lo shl  8);

		//Mix input
		//V[0..3] += V[5,6,7,4] + m[S[9,11,13,15]]
		v0 := v0 + v5;
		v1 := v1 + v6;
		v2 := v2 + v7;
		v3 := v3 + v4;
		v0 := v0 + m[S12];
		v1 := v1 + m[S13];
		v2 := v2 + m[S14];
		v3 := v3 + m[S15];
		//V[15,12,13,14] = (v[15,12,13,14] xor v[0,1,2,3]) ror 16
		t1.Value := v15 xor v0;
		t2.Value := v12 xor v1;
		t3.Value := v13 xor v2;
		t4.Value := v14 xor v3;
		PUInt64Rec(@v15).lo := (t1.Hi shl 16) or (t1.lo shr 16); PUInt64Rec(@v15).hi := (t1.Hi shr 16) or (t1.lo shl 16);
		PUInt64Rec(@v12).lo := (t2.Hi shl 16) or (t2.lo shr 16); PUInt64Rec(@v12).hi := (t2.Hi shr 16) or (t2.lo shl 16);
		PUInt64Rec(@v13).lo := (t3.Hi shl 16) or (t3.lo shr 16); PUInt64Rec(@v13).hi := (t3.Hi shr 16) or (t3.lo shl 16);
		PUInt64Rec(@v14).lo := (t4.Hi shl 16) or (t4.lo shr 16); PUInt64Rec(@v14).hi := (t4.Hi shr 16) or (t4.lo shl 16);

		//No input
		//V[10,11,8,9] += v[15,12,13,14]
		//Inc(v[10], v[15]); Inc(v[11], v[12]); Inc(v[ 8], v[13]); Inc(v[ 9], v[14]);
		v10 := v10 + v15;
		v11 := v11 + v12;
		v8  := v8  + v13;
		v9  := v9  + v14;

		//v[5,6,7,4] = (v[5,6,7,4] xor v[10,11,8,9]) ror 63
		t1.Value := v5 xor v10;
		t2.Value := v6 xor v11;
		t3.Value := v7 xor v8;
		t4.Value := v4 xor v9;
		PUInt64Rec(@v5).lo := (t1.Hi shr 31) or (t1.lo shl  1); PUInt64Rec(@v5).hi := (t1.Hi shl  1) or (t1.lo shr 31);
		PUInt64Rec(@v6).lo := (t2.Hi shr 31) or (t2.lo shl  1); PUInt64Rec(@v6).hi := (t2.Hi shl  1) or (t2.lo shr 31);
		PUInt64Rec(@v7).lo := (t3.Hi shr 31) or (t3.lo shl  1); PUInt64Rec(@v7).hi := (t3.Hi shl  1) or (t3.lo shr 31);
		PUInt64Rec(@v4).lo := (t4.Hi shr 31) or (t4.lo shl  1); PUInt64Rec(@v4).hi := (t4.Hi shl  1) or (t4.lo shr 31);
	end;

	//Mix the upper and lower halves of V into ongoing state vector h
	//Unrolling this loop did nothing
	h[0] := h[0] xor (v0 xor v8 );
	h[1] := h[1] xor (v1 xor v9 );
	h[2] := h[2] xor (v2 xor v10);
	h[3] := h[3] xor (v3 xor v11);
	h[4] := h[4] xor (v4 xor v12);
	h[5] := h[5] xor (v5 xor v13);
	h[6] := h[6] xor (v6 xor v14);
	h[7] := h[7] xor (v7 xor v15);
end;

{$OVERFLOWCHECKS ON}
{$RANGECHECKS ON}

{ TArgon2Hash }

constructor TArgon2Hash.Create(DigestSize: Integer);
begin
	inherited Create;

	FDigestSize := DigestSize;

	FBlake2 := TArgon2.CreateHash('Blake2b', 64, Pointer(nil)^, 0) as IHashAlgorithm;
	FBlake2.HashData(DigestSize, 4);
end;

function TArgon2Hash.Finalize: TBytes;
var
	cbRemaining: Integer;
	nIndex: Integer;
	data: TBytes;
	finalBlake2b: IHashAlgorithm;
begin
	//If the requested digestSize is 64-bytes or lower, then use Blake2b directly
	if FDigestSize <= 64 then
	begin
		//TODO: This should never actually happen; as Argon does everything in chunks of 64.
		//Find out if this code can *ever* be hit, and if not; eliminate it.
		if IsDebuggerPresent then
			DebugBreak;
		Result := FBlake2.Finalize;
		if FDigestSize < 64 then
		begin
			SetLength(data, FDigestSize);
			Move(Result[0], data[0], FDigestSize);
			Result := data;
		end;
		Exit;
	end;

	{
		For desired hashes over 64-bytes (e.g. 1024 bytes for Argon2 blocks),
		we use Blake2b to generate twice the number of needed 64-byte blocks,
		and then only use 32-bytes from each block
	}
	SetLength(Result, FDigestSize);
	cbRemaining := FDigestSize;
	nIndex := 0;

	data := FBlake2.Finalize;
	Move(data[0], Result[nIndex], 32);
	Dec(cbRemaining, 32);
	Inc(nIndex, 32);

	while cbRemaining > 64 do
	begin
		FBlake2.HashData(data[0], 64);
		data := FBlake2.Finalize;
		Move(data[0], Result[nIndex], 32);
		Inc(nIndex, 32);
		Dec(cbRemaining, 32);
	end;

	if cbRemaining < 64 then
	begin
		//todo: this should never actually happen, as we do everything in 1024 chunks.
		//Ensure that this never happens, and eliminate this safety check code path
		if IsDebuggerPresent then
			DebugBreak;
		finalBlake2b := TArgon2.CreateHash('Blake2b', cbRemaining, Pointer(nil)^, 0) as IHashAlgorithm;
		finalBlake2b.HashData(data[0], 64);
		data := finalBlake2b.Finalize;
	end
	else
	begin
		FBlake2.HashData(data[0], 64);
		data := FBlake2.Finalize;
	end;

	Move(data[0], Result[nIndex], cbRemaining);
end;

function TArgon2Hash.GetBlockSize: Integer;
begin
	Result := 64;
end;

function TArgon2Hash.GetDigestSize: Integer;
begin
	Result := FDigestSize;
end;

procedure TArgon2Hash.HashData(const Buffer; BufferLen: Integer);
begin
	FBlake2.HashData(Buffer, BufferLen);
end;

end.

