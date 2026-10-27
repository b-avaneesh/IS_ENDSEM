PROGRAM:
Multiplicative cipher

Purpose:
Encrypt/decrypt letters using a key coprime with 26.

INPUT:
Message/data plus the documented key or parameters.

OUTPUT:
Ciphertext, digest, signature, decision, timings, or recovered data as applicable.

CORE IDEA:
Keep input handling separate from the core operation and output formatting.

FORMULA / ALGORITHM:
C = kP mod 26; P = k^-1 C mod 26

IMPORTANT FUNCTIONS:
Core operation, inverse/verification operation, validation, and encoding helpers.

IMPORTANT VARIABLES:
message/data, key parameters, encoded bytes/integers, result.

WHAT I MUST UNDERSTAND:
Why the inverse or verification works; valid parameter sizes; what must be transmitted or retained.

COMMON MODIFICATIONS:
1. validated interactive input
2. multiple messages
3. validation and tamper/error cases

CAN COMBINE WITH:
1. hashing
2. socket/file transfer
3. signing or access control (only where the syllabus combination fits)

COMMON EXAM TRAPS:
1. Confusing text, bytes, hexadecimal, and integer representations.
2. Using invalid keys, nonces, IVs, or modular inverses.
3. Comparing formatted output instead of the exact original bytes.
