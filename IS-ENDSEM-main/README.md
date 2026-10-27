# INFORMATION SECURITY MIDSEM

This exam-ready repository is derived only from the two supplied official manuals for Labs 1-6. **Source status:** the manuals contain theory, worked parameters, web-tool instructions, and exercise statements, but no official source-code listings. The unchanged PDFs are in `SOURCE_MATERIAL/`. Every program folder has a runnable `00_original/generated_baseline.py`, clearly marked as an addition, plus focused code under `modifications/`.

## How to use this repository

```text
ORIGINAL
  ↓
UNDERSTAND
  ↓
MODIFY
  ↓
TEST
  ↓
COMBINE
  ↓
SCENARIO
  ↓
MOCK MIDSEM
```

Do **not** memorize every line. For each program, trace:

```text
INPUT
  ↓
CORE ALGORITHM
  ↓
OUTPUT
```

Know which LEGO blocks can connect: input/encoding, encrypt/decrypt, hash, sign/verify, socket send/receive, file read/write, access decision, and timing.

## Environment and testing

Python 3 is used because every implementation exercise in the manuals requests or implies Python. Install `requirements.txt`, then run `python tests/smoke_test.py`. Interactive, timing, and client/server cases also have manual cases beside their programs. These programs are learning demonstrations; small textbook keys are not production security.

## Programs found/derived from Labs 1-6

- `LAB_1_BASIC_CIPHERS/01_Additive_Cipher` - Additive (Caesar/shift) cipher
- `LAB_1_BASIC_CIPHERS/02_Multiplicative_Cipher` - Multiplicative cipher
- `LAB_1_BASIC_CIPHERS/03_Affine_Cipher` - Affine cipher
- `LAB_1_BASIC_CIPHERS/04_Vigenere_Cipher` - Vigenere cipher
- `LAB_1_BASIC_CIPHERS/05_Autokey_Cipher` - Autokey cipher
- `LAB_1_BASIC_CIPHERS/06_Playfair_Cipher` - Playfair cipher
- `LAB_1_BASIC_CIPHERS/07_Hill_Cipher` - Hill cipher
- `LAB_1_BASIC_CIPHERS/08_Cipher_Attacks` - Classical cipher attacks
- `LAB_2_ADVANCED_SYMMETRIC/01_DES` - DES
- `LAB_2_ADVANCED_SYMMETRIC/02_AES` - AES
- `LAB_2_ADVANCED_SYMMETRIC/03_Triple_DES` - Triple DES
- `LAB_2_ADVANCED_SYMMETRIC/04_DES_AES_Performance` - DES/AES performance comparison
- `LAB_3_ASYMMETRIC/01_RSA` - RSA
- `LAB_3_ASYMMETRIC/02_ElGamal` - ElGamal encryption
- `LAB_3_ASYMMETRIC/03_ECC_Key_Exchange` - Elliptic-curve key exchange
- `LAB_3_ASYMMETRIC/04_Diffie_Hellman` - Diffie-Hellman key exchange
- `LAB_3_ASYMMETRIC/05_RSA_ECC_File_Transfer` - RSA/ECC file-transfer study
- `LAB_4_ADVANCED_ASYMMETRIC/01_RSA_ElGamal_Rabin_Comparison` - RSA, ElGamal and Rabin comparison
- `LAB_4_ADVANCED_ASYMMETRIC/02_Key_Management_System` - Key management system
- `LAB_4_ADVANCED_ASYMMETRIC/03_Access_Control` - Cryptographic access control
- `LAB_4_ADVANCED_ASYMMETRIC/04_SecureCorp_Communication` - SecureCorp scenario
- `LAB_4_ADVANCED_ASYMMETRIC/05_Rabin_Healthcare_KMS` - Rabin healthcare key management
- `LAB_5_HASHING/01_User_Defined_Hash` - User-defined 32-bit hash
- `LAB_5_HASHING/02_Socket_Hash_Integrity` - Socket hash integrity
- `LAB_5_HASHING/03_Hash_Performance_Collisions` - MD5/SHA-1/SHA-256 experiment
- `LAB_6_DIGITAL_SIGNATURE/01_RSA_Digital_Signature` - RSA digital signature
- `LAB_6_DIGITAL_SIGNATURE/02_ElGamal_Schnorr_Signature` - ElGamal signature
- `LAB_6_DIGITAL_SIGNATURE/03_Schnorr_Signature` - Schnorr signature
- `LAB_6_DIGITAL_SIGNATURE/04_Client_Server_Signature` - Client/server signatures
- `LAB_6_DIGITAL_SIGNATURE/05_CIA_RSA_SHA_Signature` - CIA triad demonstration

## Modifications created

- **Additive (Caesar/shift) cipher:** preserve case and spaces, brute-force attack
- **Multiplicative cipher:** validated interactive input, multiple messages
- **Affine cipher:** known-plaintext key recovery, brute-force candidates
- **Vigenere cipher:** preserve formatting, menu encrypt/decrypt
- **Autokey cipher:** preserve formatting, validated seed
- **Playfair cipher:** decrypt and remove filler carefully, print key matrix
- **Hill cipher:** encrypt/decrypt 2x2 key, validate invertible key
- **Classical cipher attacks:** additive birthday-nearby search, affine known-pair recovery
- **DES:** CBC with IV, file input/output
- **AES:** select key size, CTR with nonce
- **Triple DES:** CBC mode, multiple messages
- **DES/AES performance comparison:** five-message benchmark, CSV output
- **RSA:** text as per-character integers, timing report
- **ElGamal encryption:** fixed manual parameters, fresh random k per character
- **Elliptic-curve key exchange:** derive AES key with HKDF, timing report
- **Diffie-Hellman key exchange:** interactive toy parameters, timing report
- **RSA/ECC file-transfer study:** RSA hybrid file encryption, ECC ECDH hybrid file encryption
- **RSA, ElGamal and Rabin comparison:** repeatable benchmark, CSV report
- **Key management system:** multi-organization registry, expiry/renewal
- **Cryptographic access control:** RBAC policy, time-limited grants
- **SecureCorp scenario:** add/revoke subsystem, audit communication
- **Rabin healthcare key management:** facility lifecycle, RSA/Rabin trade-off report
- **User-defined 32-bit hash:** interactive and multiple inputs, file hashing
- **Socket hash integrity:** normal and tampered mode, framed multi-part message
- **MD5/SHA-1/SHA-256 experiment:** configurable dataset, CSV report
- **RSA digital signature:** file sign/verify, tamper detection
- **ElGamal signature:** text hashing, invalid signature test
- **Schnorr signature:** text input, tamper detection
- **Client/server signatures:** client/server pair, tamper mode
- **CIA triad demonstration:** message workflow, file workflow

## Combinations

- Level 1: encrypt then hash; hash then RSA-sign.
- Level 2: encrypt, hash, and sign.
- Level 3: secure file package/integrity scenario.
- Mock midsems: secure marks file, authenticated department message, hospital session setup, revocable secure document.

## Concepts to modify under exam conditions

- Text/bytes/integer/hex conversion and preservation of formatting.
- Modular arithmetic, inverses, valid classical keys, padding/fillers.
- AES/DES/3DES key sizes, modes, IVs/nonces, padding, and timing.
- RSA, ElGamal, ECC/ECDH, Diffie-Hellman, Rabin, key lifecycle, and access decisions.
- Custom hash, standard hashes, collision checks, sockets, framing, tamper detection.
- RSA/ElGamal/Schnorr signing, verification, and confidentiality-integrity-authenticity composition.

## Recommended study order

1. Lab 1 substitution/transposition and attacks.
2. Lab 2 library API patterns, modes, padding, and benchmarks.
3. Lab 3 public/private keys, encoding, and shared secrets.
4. Lab 4 key lifecycle and access-control scenarios.
5. Lab 5 custom/standard hashes and socket integrity.
6. Lab 6 sign/verify and tamper cases.
7. Level 1 combinations, then Level 2, Level 3, and mock midsems.
