# Hospital Session Setup

## QUESTION
Use Diffie-Hellman/ECDH to agree a session key, encrypt a short record, and report key-exchange time.

## REQUIREMENTS
1. Keep input, cryptographic operation, and output blocks separate.
2. Validate parameters and demonstrate one failure/tamper case.
3. Print only the evidence needed to show correctness.

## CONCEPTS INVOLVED
DH/ECDH + symmetric encryption + timing

## EXPECTED INPUT
A short message/file and valid keys or generated keys.

## EXPECTED OUTPUT
Ciphertext/digest/signature or access result, successful recovery/verification, and the required failure case.

## HINTS
Reuse the matching lab modification; do not retype the algorithm from memory.
