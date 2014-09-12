# Kripto
*Simple and flexible cryptographic library written in ISO C99.*

Due to lack of time, lack of interest and technical difficulties
project is abandoned.

There is no documentation, however API is really simple.

Run build.sh to compile. Makefile doesn't work (outdated).

### Supported features:
#### Block ciphers
* Rijndael128 (AES)
* Rijndael256
* Serpent
* Twofish
* RC6
* Camellia
* ARIA
* Threefish256
* Threefish512
* Threefish1024
* Noekeon
* 3-Way
* Anubis
* KHAZAD
* SEED
* Blowfish
* GOST
* TEA
* XTEA
* Skipjack
* Speck128
* Speck64
* Speck32
* Simon128
* Simon64
* Simon32
* DES (TDES)
* IDEA
* MARS
* RC5
* RC5/64
* RC2
* CAST5
* SAFER

#### Block cipher modes
* CTR
* CBC
* CFB
* OFB
* ECB

#### Authenticated modes
* EAX2
* EAX

#### Stream ciphers
* Salsa20 (XSalsa20)
* ChaCha (XChaCha)
* RC4
* Keccak1600
* Keccak800
* Skein256
* Skein512
* Skein1024

#### Hash functions
* SHA2
* SHA1
* Keccak1600
* Keccak800
* Skein256
* Skein512
* Skein1024
* BLAKE-256
* BLAKE-512
* BLAKE2s
* BLAKE2b
* WHIRPOOL
* Tiger
* MD5

#### Message authentication codes
* HMAC
* OMAC (CMAC1)
* XCBC
* Keccak1600
* Keccak800
* Skein256
* Skein512
* Skein1024

#### Authenticated stream ciphers
* Keccak1600
* Keccak800

#### Other
* PKCS7
* PBKDF2
* scrypt
* random
* memwipe

### Candidate features:
#### Public-key cryptography
* RSA
* DSA
* DH
* ECC
* NTRU
* ElGamal
* McEliece

#### Block cipher modes
* CFB8
* CFB1
* TBC
* XTS
* LRW

#### Authenticated modes
* GCM
* OCB
* CCM
* CWC
* IAPM

#### Stream ciphers
* SOSEMANUK
* Rabbit
* HC-256
* HC-128
* SEAL
* Scream
* MUGI
* Py (RCR)
* Trivium

#### Hash functions
* Grostl
* JH
* Fugue
* Luffa
* RIPEMD
* HAVAL

#### Message authentication codes
* CMAC2
* CBC variants
* PMAC
* UMAC
* VMAC
* Poly1305

#### Authenticated stream ciphers
* CAESAR competition winner/s
* Phelix
* Helix

#### Other
* Password Hashing Competition winner/s
