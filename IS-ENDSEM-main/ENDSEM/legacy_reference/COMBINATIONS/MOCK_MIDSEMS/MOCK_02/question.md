# Authenticated Department Message

## QUESTION
Sign a message with RSA, send message and signature to a server, and reject a one-byte tampered message.

## REQUIREMENTS
1. Keep input, cryptographic operation, and output blocks separate.
2. Validate parameters and demonstrate one failure/tamper case.
3. Print only the evidence needed to show correctness.

## CONCEPTS INVOLVED
RSA signature + SHA-256 + sockets

## EXPECTED INPUT
A short message/file and valid keys or generated keys.

## EXPECTED OUTPUT
Ciphertext/digest/signature or access result, successful recovery/verification, and the required failure case.

## HINTS
Reuse the matching lab modification; do not retype the algorithm from memory.
