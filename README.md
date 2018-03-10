**Warning:** This implementation is incomplete. There are items in the Argon2 specification that are undocumented.

# Argon2 for Delphi

[Argon2](https://en.wikipedia.org/wiki/Argon2) is a key derivation function. It is designed to take a password (and some salt), and generate a desired number of pseudo-random bytes. Like *scrypt*, it is also *memory hard*, meaning it is designed thwart implementations on ASICs and GPUs. It was selected as the winner of Google's [Password Hashing Competition](https://password-hashing.net/) in 2015.

The algorithm takes every advantage of x86/x64 architecture in can, in order to have the fastest software implementation possible, while making hurting hardware implementations. Argon2 uses the very fast Blake2 software hashing algorithm. Blake2 is faster in software than SHA-3, SHA-2, SHA-1, and MD5.^[1](https://blake2.net/) The reason SHA-3 (Keccak) was not used is because SHA-3 is faster on hardware; and we don't want algorithms that run faster on custom hardware. In order to give custom hardware every disadvantage possible, the fastest *software-only* hashing algorithm was used


Sample Usage
----------------

To hash a pssword using default cost factors:

        hash := TArgon2.HashPassword('correct battery horse staple'); //using default cost factors
    
To hash a password specifying your own cost factors:

        hash := TArgon2.HashPassword('correct battery horse staple', 1000, 128*1024, 1); //Iterations=1000, Memory=128MB, Parallelism=1
    
To verify a password:

        isPasswordValid := TArgon2.CheckPassword('correct battery horse stapler', expectedHash, {out}passwordRehashNeeded);


By convention Argon2 outputs a password hash as string in the form:

    $Argon2id$v=[version]$m=[memoryKB],t=[type],p=[parallelism]$[salt]$[hash]
    $argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$VGhpcyB3YXMgb25seSBhbiBleGFtcGxlLCBpIGRvbid0IGFjdHVhbGx5IGhhdmUgYSB2YWxpZCBpbXBsZW1udA==

The parts of the string are:

| Value | Meaning | Notes |
|-------|---------|-------|
| argon2id | Hash algorithm | "argon2id", "argon2d", "argon2i" |
| v=19 | Decimal coded version | Default is 0x13, which is 19 decimal |
| m=65536 | Memory size in KiB | Valid range: 8*Parallelism .. 0x7fffffff, and must be a power of two  |
| p=4 | Parallelization Factor | 1-0x00ffffff  |
| salt | base64 encoded salt | 0-16 bytes decoded |
| hash | base64 encoded hash | 32-bytes |

Because the four argon parameters are stored in the returned string, argon2 password hashes are backwards and forwards compatible with changing the factors. It also makes Argon2 extraordinarily convenient, in that a random salt is automatically generated and stored for you (you don't have to worry about storing it in a database or retrieving it).

This code is licensed under public domain **Unlicense**. 

Bonus Reading
------------

- RFC: [The memory-hard Argon2 password hash and proof-of-work function](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03) *(updated August 3, 2017)*
- Whitepaper: [Argon2: the memory-hard function for password hashing and other
applications](https://github.com/P-H-C/phc-winner-argon2/raw/master/argon2-specs.pdf) *(updated March 24, 2017)*

-----------------

One of the virtues of the Unlicense license is that if you don't like the license, you can change the license to whatever you want. This means that if you don't like the license, you are free to pick any other license you prefer (or your company or country understands):

- unlicense license
- DWTFYW license
- BSD
- GPL
- LGPL
- MIT
- Copyleft
