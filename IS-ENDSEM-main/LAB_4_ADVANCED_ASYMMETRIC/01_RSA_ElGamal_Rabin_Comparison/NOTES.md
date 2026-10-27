PROGRAM:
RSA, ElGamal and Rabin comparison

Purpose:
Compare core integer operations and timing.

INPUT:
Message/data plus the documented key or parameters.

OUTPUT:
Ciphertext, digest, signature, decision, timings, or recovered data as applicable.

CORE IDEA:
Keep input handling separate from the core operation and output formatting.

FORMULA / ALGORITHM:
RSA exponentiation; ElGamal discrete-log construction; Rabin squaring

IMPORTANT FUNCTIONS:
Core operation, inverse/verification operation, validation, and encoding helpers.

IMPORTANT VARIABLES:
message/data, key parameters, encoded bytes/integers, result.

WHAT I MUST UNDERSTAND:
Why the inverse or verification works; valid parameter sizes; what must be transmitted or retained.

COMMON MODIFICATIONS:
1. repeatable benchmark
2. CSV report
3. validation and tamper/error cases

CAN COMBINE WITH:
1. hashing
2. socket/file transfer
3. signing or access control (only where the syllabus combination fits)

COMMON EXAM TRAPS:
1. Confusing text, bytes, hexadecimal, and integer representations.
2. Using invalid keys, nonces, IVs, or modular inverses.
3. Comparing formatted output instead of the exact original bytes.
