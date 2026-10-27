# Secure Marks File

## QUESTION
Read a marks file, encrypt it with AES, compute SHA-256 of the ciphertext, and verify integrity before decryption.

## REQUIREMENTS
1. Keep input, cryptographic operation, and output blocks separate.
2. Validate parameters and demonstrate one failure/tamper case.
3. Print only the evidence needed to show correctness.

## CONCEPTS INVOLVED
AES + SHA-256 + file I/O

## EXPECTED INPUT
A short message/file and valid keys or generated keys.

## EXPECTED OUTPUT
Ciphertext/digest/signature or access result, successful recovery/verification, and the required failure case.

## HINTS
Reuse the matching lab modification; do not retype the algorithm from memory.
