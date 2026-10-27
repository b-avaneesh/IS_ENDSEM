INFORMATION SECURITY LAB EXAM KIT
=================================

START HERE -- LOWEST-EFFORT EXAM METHOD
---------------------------------------
Open the STRAIGHT_COPY_PASTE folder and then open 00_USE_THESE_FILES.txt.
It maps every lab question to one short, complete Python file.

For a LARGE role-based hospital/university/company question, open:

    STANDARD_ROLE_TEMPLATES/00_TEMPLATE_MAP.txt

Then select the already-configured algorithm file from READY_VARIANTS. These
templates cover every encryption, hashing and signature algorithm in Labs 1-6.

Each cipher file already contains both encrypt_data() and decrypt_data().
Copy the complete matching file and edit only the plaintext/key values in its
final main block. The large LAB_1...LAB_6 files are reference copies; you do
not need them for ordinary copy-paste answers.

For a large role-based question use EASY_EXAM_TEMPLATE.py. It is generic and
has only two edit boxes. To change DES to AES, change only CIPHER_NAME and
CIPHER_KEY; never paste another AES function into the template.

FILES
-----
STRAIGHT_COPY_PASTE/
  Short complete files, one per algorithm/question. Use these first.

LAB_1_BASIC_SYMMETRIC.py
  Additive, multiplicative, affine, Vigenere, autokey, Playfair, Hill,
  transposition, additive and the two brute-force/known-plaintext exercises.

LAB_2_ADVANCED_SYMMETRIC.py
  DES, AES-128/192/256, Triple DES, ECB/CBC/CFB/OFB/CTR, timing and graph.

LAB_3_ASYMMETRIC.py
  RSA, weak-RSA attack, ElGamal, ECC/ECIES, Diffie-Hellman, RSA/ECC hybrid
  file encryption and performance comparison.

LAB_4_KEY_MANAGEMENT_ACCESS_CONTROL.py
  SecureCorp RSA+DH communication; Rabin hospital key service; ElGamal DRM
  access control; weak-RSA attack; generation, distribution, renewal,
  revocation and audit logging.

LAB_5_HASHING.py
  32-bit user-defined hash, MD5/SHA-1/SHA-256 timing/collisions and a
  single-part/multipart client-server integrity demonstration.

LAB_6_DIGITAL_SIGNATURE.py
  ElGamal signature, Schnorr signature, DH encryption, RSA signatures,
  client-server signature verification and CIA triad demonstration.

EASY_EXAM_TEMPLATE.py
  A short generic role-based solution with keyboard/file input, encryption,
  decryption, hashing, signatures, timestamps and file storage.

SETUP_CHECK.py
  Run this before the exam to confirm the required package and functions work.

LIKELY_EXAM_QUESTION_PERMUTATIONS.txt
  Twenty predicted practice questions derived from the structure of the sample
  paper and the exercises in Labs 1-6, ranked by likely exam format.

TEMPLATE_CHANGES_FOR_EACH_PREDICTED_QUESTION.txt
  Exact checklist of what to rename, replace, add or keep in the exam template
  for each of the twenty predicted questions.


BEFORE THE OFFLINE EXAM
-----------------------
1. Install the dependency while internet access is available:

       pip install pycryptodome matplotlib

   matplotlib is only needed for the optional Lab 2 graph. All network,
   hashing and Lab 1 programs use the standard Python library.

2. Copy this entire folder to the exam computer/drive.

3. Run:

       python SETUP_CHECK.py

4. For any lab file, run:

       python LAB_1_BASIC_SYMMETRIC.py


FASTEST EXAM METHOD
-------------------
1. Read STRAIGHT_COPY_PASTE/00_USE_THESE_FILES.txt.
2. Open the one matching short file.
3. Copy the complete file.
4. Change only the values in its final main block if fixed values are given.

For a large role-based question, copy EASY_EXAM_TEMPLATE.py and edit only the
two clearly marked boxes at the top.


STANDARD FUNCTION NAMES IN EVERY FILE
-------------------------------------
Use these names in exam answers. The same argument order is used throughout:

    encrypt_data(data, key, algorithm, **options)
    decrypt_data(encrypted_data, key, algorithm, **options)
    generate_keys(algorithm, **options)
    hash_data(data, algorithm)
    sign_data(data, private_key, algorithm, **options)
    verify_signature(data, signature, public_key, algorithm, **options)

Only relevant functions appear in each lab. For example, Lab 5 has hash_data()
but does not contain meaningless encryption functions. Older descriptive names
such as aes_encrypt() remain as internal/reference helpers.

EASY_EXAM_TEMPLATE.py now places WHEN TO EDIT and WHERE ELSE TO EDIT comments
above every setting, crypto function, storage helper and role/menu function.


CLIENT-SERVER QUESTIONS
-----------------------
Open two terminals in this folder.

Lab 5 hashing:
    Terminal 1: python LAB_5_HASHING.py server
    Terminal 2: python LAB_5_HASHING.py client

Lab 6 signature:
    Terminal 1: python LAB_6_DIGITAL_SIGNATURE.py server
    Terminal 2: python LAB_6_DIGITAL_SIGNATURE.py client


MANUAL ISSUES ALREADY HANDLED
-----------------------------
1. The Lab 3 additional ElGamal question gives p=7919, g=2, h=6465 and
   x=2999. These are inconsistent because 2^2999 mod 7919 = 3868, not 6465.
   The demo uses the consistent generated value so encryption/decryption works.

2. The Lab 2 AES-192 question supplies only 32 hex characters (128 bits).
   AES-192 requires 48 hex characters (192 bits). make_key() pads the supplied
   value with zero bytes for a working classroom demonstration.

   The supplied 3DES key repeats the same 8 bytes three times, which reduces to
   ordinary DES and is rejected by PyCryptodome. make_3des_key() derives a
   valid 24-byte classroom key from the supplied text for the demo.

3. The Hill key printed as [03 03 2 07] is treated multiline as:
       [[3, 3],
        [2, 7]]

4. The sample paper signs the hash of encrypted data but also asks Faculty to
   hash the decrypted data. EASY_EXAM_TEMPLATE.py stores both encrypted_hash
   and plaintext_hash, so both requirements can be demonstrated correctly.

5. Two Lab 1 ciphertexts appear to contain typing errors. Using the stated
   keys, XVIEWYWI decrypts to TREASUSE (the intended word is probably TREASURE)
   and the affine text contains AKTERWARDS (probably AFTERWARDS). The code
   prints the exact mathematical decryption instead of silently changing it.


IMPORTANT NOTE
--------------
The small-number RSA, ElGamal, Rabin and Schnorr versions are intentionally
simple educational code. Use 2048-bit RSA/P-256 hybrid functions when the
question explicitly asks for realistic files or keys.
