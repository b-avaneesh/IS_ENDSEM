from pathlib import Path
import ast
import json
import re

ROOT = Path(r'D:\IS-ENDSEM\LAB_ENDSEM_SAMPLE_QUESTIONS')
OUT = ROOT / 'WITHOUT_SOCKET_FILE_BASED_LAB_ENDSEM_SAMPLE_PAPER_SOLUTIONS'
SAMPLE = Path(r'C:\Users\abhij\.codex\attachments\3b8220a5-81e2-4c5e-8aa0-33b43a05cf6a\Pasted text.txt').read_text()
COMBOS = json.loads((ROOT / 'COMBINATIONS_INDEX.json').read_text())

def section(title):
    return '\n\n# =========================================================\n# ' + title + '\n# =========================================================\n\n'

def functions(source):
    return {n.name: ast.get_source_segment(source, n) for n in ast.parse(source).body if isinstance(n, ast.FunctionDef)}

sample_funcs = functions(SAMPLE)
imports = '''from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from pathlib import Path
from math import gcd
import random
import secrets
import hashlib
import hmac
import math
import base64
import json
import re
'''

storage = '''
def initialize():
    global SERVER_RSA, SERVER_ECC, PRIVATE_X, PUBLIC_Y
    for name in ("encrypted", "hashes", "signature", "public_key", "add", "metadata", "keys"):
        (BASE / name).mkdir(parents=True, exist_ok=True)
    key_file = BASE / "keys" / "local.json"
    if key_file.exists():
        state = json.loads(key_file.read_text())
    else:
        state = {"symmetric": get_random_bytes(KEY_BYTES).hex(),
                 "search": get_random_bytes(32).hex()}
        if ASYMMETRIC == "RSA":
            state["private"] = RSA.generate(2048).export_key().decode()
        elif ASYMMETRIC == "ECDH":
            state["private"] = ECC.generate(curve="P-256").export_key(format="PEM")
        else:
            state["private"] = secrets.randbelow(P - 3) + 2
        key_file.write_text(json.dumps(state), encoding="utf-8")
    if ASYMMETRIC == "RSA":
        SERVER_RSA = RSA.import_key(state["private"])
    elif ASYMMETRIC == "ECDH":
        SERVER_ECC = ECC.import_key(state["private"])
    else:
        PRIVATE_X = state["private"]
        PUBLIC_Y = pow(G, PRIVATE_X, P)
    return bytes.fromhex(state["symmetric"]), bytes.fromhex(state["search"])


def record_path(folder, filename):
    if (not filename or filename in (".", "..") or
            any(ch in filename for ch in '<>:"/\\\\|?*') or
            filename.endswith((".", " ")) or
            filename.split('.')[0].upper() in
            {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)],
             *[f"LPT{i}" for i in range(1, 10)]}):
        raise ValueError("Enter a plain filename, for example report1.txt")
    return BASE / folder / filename


def write_file(folder, filename, value):
    record_path(folder, filename).write_text(value, encoding="utf-8")


def read_file(folder, filename):
    return record_path(folder, filename).read_text(encoding="utf-8")


def load_documents():
    documents = {}
    for file in (BASE / "encrypted").iterdir():
        if file.is_file():
            try:
                documents[file.name] = read_document(file.name)
            except (ValueError, OSError, KeyError, TypeError):
                print("Skipping invalid document:", file.name)
    return documents
'''
sse = '''def token(key, word):
    return hmac.new(key, word.lower().encode(), hashlib.sha256).hexdigest()


def create_index(documents, key, iv=None):
    index = {}
    for doc_id, doc in documents.items():
        for word in set(doc.lower().split()):
            record_iv = get_random_bytes(BLOCK_CIPHER.block_size)
            enc_id = symmetric_encrypt(doc_id, key, record_iv)
            index.setdefault(token(SEARCH_KEY, word), []).append((record_iv.hex(), enc_id))
    (BASE / "index.json").write_text(json.dumps(index), encoding="utf-8")
    return index


def search(index, query, key, documents=None):
    results = []
    for iv_hex, enc_id in index.get(token(SEARCH_KEY, query.strip()), []):
        doc_id = symmetric_decrypt(enc_id, key, bytes.fromhex(iv_hex))
        results.append((doc_id, read_document(doc_id)))
    return results
'''
symmetric = '''def symmetric_encrypt(plaintext, key, iv):
    cipher = BLOCK_CIPHER.new(key, BLOCK_CIPHER.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(plaintext.encode(), BLOCK_CIPHER.block_size)).hex()


def symmetric_decrypt(ciphertext_hex, key, iv):
    cipher = BLOCK_CIPHER.new(key, BLOCK_CIPHER.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(bytes.fromhex(ciphertext_hex)), BLOCK_CIPHER.block_size).decode()
'''
roles = '''def student(filename, plaintext, num1, num2, key, iv):
    if record_path("encrypted", filename).exists():
        raise ValueError("Document already exists!")
    homomorphic = calculate_homomorphic(num1, num2)
    # A fresh IV is stored for each record.
    iv = get_random_bytes(BLOCK_CIPHER.block_size)
    ciphertext = symmetric_encrypt(plaintext, key, iv)
    private_key, public_key = generate_keys()
    signature, hash_value = sign_message(ciphertext, private_key)
    metadata = {"iv": iv.hex(), "wrapped_key": wrap_key(key), "num1": num1, "num2": num2}
    write_file("encrypted", filename, ciphertext)
    write_file("hashes", filename, hash_value)
    write_file("signature", filename, json.dumps(signature))
    write_file("public_key", filename, json.dumps(public_key))
    write_file("add", filename, json.dumps(homomorphic))
    write_file("metadata", filename, json.dumps(metadata))
    print("Encrypted", homomorphic["operation"], ":", homomorphic["ciphertext"])
    print("Record uploaded successfully.")


def read_document(filename):
    ciphertext = read_file("encrypted", filename)
    if digest_text(ciphertext) != read_file("hashes", filename):
        raise ValueError("Integrity verification failed.")
    signature = json.loads(read_file("signature", filename))
    public_key = json.loads(read_file("public_key", filename))
    if not verify_signature(ciphertext, signature, public_key):
        raise ValueError("Digital signature verification failed.")
    metadata = json.loads(read_file("metadata", filename))
    key = unwrap_key(metadata["wrapped_key"])
    return symmetric_decrypt(ciphertext, key, bytes.fromhex(metadata["iv"]))


def faculty(filename, num1=None, num2=None, key=None, iv=None):
    ciphertext = read_file("encrypted", filename)
    print("\\nStudent Hash :", read_file("hashes", filename))
    print("Faculty Hash :", digest_text(ciphertext))
    plaintext = read_document(filename)
    print("Hash verified successfully.")
    print("Signature verified:", True)
    metadata = json.loads(read_file("metadata", filename))
    homomorphic = json.loads(read_file("add", filename))
    result = decrypt_homomorphic(homomorphic["ciphertext"])
    expected = expected_homomorphic(metadata["num1"], metadata["num2"])
    print("Homomorphic decrypted result:", result)
    if result != expected:
        raise ValueError("Homomorphic verification failed.")
    print("homomorphic verified")
    print("\\nPlaintext:")
    print(plaintext)
    return plaintext


def hod(filename):
    ciphertext = read_file("encrypted", filename)
    saved_hash = read_file("hashes", filename)
    signature = json.loads(read_file("signature", filename))
    public_key = json.loads(read_file("public_key", filename))
    result = (digest_text(ciphertext) == saved_hash and
              verify_signature(ciphertext, signature, public_key))
    print("\\nHash:", saved_hash)
    print("Signature and hash verified:", result)
    return result
'''

for combo in COMBOS:
    src = (ROOT / combo['folder'] / 'server.py').read_text()
    funcs = functions(src)
    tree = ast.parse(src)
    constants = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = {x.id for target in node.targets for x in ast.walk(target) if isinstance(x, ast.Name)}
            if names & {'BLOCK_CIPHER', 'SIG_P', 'P'}:
                constants.append(ast.get_source_segment(src, node))
    title = combo['folder'][9:].replace('_', ' ')
    code = imports + '\n# Standalone lab example; local teaching keys are stored in keys/.\n'
    code += f'TITLE = {title!r}\nASYMMETRIC = {combo["asymmetric"]!r}\nBASE = Path(__file__).resolve().parent\n'
    code += '\n'.join(constants) + '\n'
    code += section('SSE - CREATE ENCRYPTED INDEX AND SEARCH') + sse
    code += section('HOMOMORPHIC ENCRYPTION AND DECRYPTION')
    hom = combo['homomorphic']
    if hom in ('Paillier', 'RSA'):
        suffix = 'paillier' if hom == 'Paillier' else 'RSA'
        code += sample_funcs['encrypt_homomorphic_' + suffix] + '\n\n'
        code += sample_funcs['decrypt_homomorphic_' + suffix] + '\n\n'
        modulus = 323 if hom == 'Paillier' else 143
        op = '+' if hom == 'Paillier' else '*'
        operation = 'addition' if hom == 'Paillier' else 'multiplication'
        code += f'''def expected_homomorphic(a, b):
    return (a {op} b) % {modulus}


def calculate_homomorphic(a, b):
    if not (0 <= a < {modulus} and 0 <= b < {modulus}):
        raise ValueError("Use integers from 0 to {modulus-1}")
    c1, modulus = encrypt_homomorphic_{suffix}(a)
    c2, modulus = encrypt_homomorphic_{suffix}(b)
    return {{"operation": "{operation} modulo {modulus}", "ciphertext": c1 * c2 % modulus}}


def decrypt_homomorphic(ciphertext):
    return decrypt_homomorphic_{suffix}(ciphertext)
'''
    else:
        code += '''HOM_P, HOM_G, HOM_X = 467, 2, 127
HOM_Y = pow(HOM_G, HOM_X, HOM_P)


def encrypt_homomorphic_elgamal(m):
    k = secrets.randbelow(HOM_P - 2) + 1
    return pow(HOM_G, k, HOM_P), m * pow(HOM_Y, k, HOM_P) % HOM_P


def decrypt_homomorphic(ciphertext):
    a, b = ciphertext
    return b * pow(pow(a, HOM_X, HOM_P), -1, HOM_P) % HOM_P


def expected_homomorphic(a, b):
    return a * b % HOM_P


def calculate_homomorphic(a, b):
    if not (1 <= a < HOM_P and 1 <= b < HOM_P):
        raise ValueError("Use integers from 1 to 466")
    c1, c2 = encrypt_homomorphic_elgamal(a), encrypt_homomorphic_elgamal(b)
    combined = [c1[0] * c2[0] % HOM_P, c1[1] * c2[1] % HOM_P]
    return {"operation": "multiplication modulo 467", "ciphertext": combined}
'''
    code += section('GENERATE KEYS, SIGN MESSAGE AND VERIFY SIGNATURE')
    code += funcs['digest_text'] + '\n\n'
    sig = combo['signature']
    if sig == 'RSA':
        code += '''def generate_keys():
    private_key = RSA.generate(2048)
    return private_key, private_key.publickey().export_key().decode()


def sign_message(message, private_key):
    signature = pkcs1_15.new(private_key).sign(SHA256.new(message.encode()))
    return signature.hex(), digest_text(message)


def verify_signature(message, signature, public_key):
    try:
        pkcs1_15.new(RSA.import_key(public_key)).verify(SHA256.new(message.encode()), bytes.fromhex(signature))
        return True
    except (ValueError, TypeError):
        return False
'''
    else:
        limit = 'SIG_P - 2' if sig == 'ElGamal' else 'SIG_Q - 1'
        code += f'''def generate_keys():
    private_key = secrets.randbelow({limit}) + 1
    return private_key, pow(SIG_G, private_key, SIG_P)


'''
        if 'challenge' in funcs:
            code += funcs['challenge'] + '\n\n'
        sign = funcs['sign_content'].replace('def sign_content(username, content):', 'def sign_message(content, private_key):').replace('USER_SIGNING_KEYS[username]', 'private_key')
        sign = sign.replace('return [r, s]', 'return [r, s], digest_text(content)').replace('return [e, (k + private_key * e) % SIG_Q]', 'return [e, (k + private_key * e) % SIG_Q], digest_text(content)')
        verify = funcs['verify_signature'].replace('def verify_signature(username, content, signature):', 'def verify_signature(content, signature, public_key):').replace('USER_VERIFY_KEYS[username]', 'public_key')
        code += sign + '\n\n' + verify + '\n'
    code += section(combo['symmetric'].upper() + ' ENCRYPTION AND DECRYPTION') + symmetric
    code += section(combo['asymmetric'] + ' KEY PROTECTION')
    code += '\n\n'.join(funcs[n] for n in ('b64', 'unb64', 'wrap_key', 'unwrap_key'))
    code += section(combo['classical'].upper() + ' CLASSICAL CIPHER')
    start = src.index('def digest_text(')
    end = src.index('def b64(')
    nodes = [n for n in ast.parse(src[start:end]).body if isinstance(n, ast.FunctionDef) and n.name != 'digest_text']
    code += '\n\n'.join(ast.get_source_segment(src[start:end], n) for n in nodes)
    code += section('FILE STORAGE') + storage
    # Keep the sample's role functions and main menu ordering.
    role_funcs = functions(roles)
    for name in ('student', 'read_document', 'faculty', 'hod'):
        code += section(name.upper().replace('_', ' ')) + role_funcs[name]
    main = sample_funcs['main']
    main = main.replace('    documents = {}', '    global SEARCH_KEY\n    key, SEARCH_KEY = initialize()\n    documents = load_documents()')
    main = main.replace('    key = b"A1B2C3D4"\n    iv = b"A1B2C3D4"', '    iv = None')
    main = main.replace('print("             EduSecure")', 'print("             " + TITLE)')
    main = main.replace('print("\\nExiting EduSecure...")', 'print("\\nExiting " + TITLE + "...")')
    main = main.replace('Enter academic record:', 'Enter document record:')
    main = main.replace('                    documents[filename] = plaintext\n                    print("Document added successfully!")\n', '')
    main = main.replace('                    student(filename, plaintext, num1, num2,key,iv)', '''                    try:
                        student(filename, plaintext, num1, num2, key, iv)
                        documents[filename] = plaintext
                        create_index(documents, key)
                    except (ValueError, OSError) as exc:
                        print(exc)''')
    main = main.replace('                    num1 = int(input("Enter first integer: "))\n                    num2 = int(input("Enter second integer: "))', '''                    try:
                        num1 = int(input("Enter first integer: "))
                        num2 = int(input("Enter second integer: "))
                    except ValueError:
                        print("Enter valid integers.")
                        continue''')
    main = main.replace('                    faculty(filename, num1, num2,key ,iv)', '''                    try:
                        faculty(filename)
                    except (ValueError, OSError, KeyError, TypeError) as exc:
                        print(exc)''')
    main = main.replace('                        encrypted_index = create_index(documents, key,iv)\n                        results = search(encrypted_index, search_text, key, documents)', '''                        encrypted_index = json.loads((BASE / "index.json").read_text())
                        try:
                            results = search(encrypted_index, search_text, key, documents)
                        except (ValueError, OSError, KeyError, TypeError) as exc:
                            print(exc)
                            continue''')
    main = main.replace('    iv = None', '    iv = None\n    create_index(documents, key)')
    main = main.replace('            hod(filename)', '''            try:
                hod(filename)
            except (ValueError, OSError, KeyError, TypeError) as exc:
                print(exc)''')
    main = main.replace('print("3. Back to main menu")\n\n                student_choice', 'print("3. Back to main menu")\n                print("4. Classical cipher demonstration")\n\n                student_choice')
    main = main.replace('                elif student_choice == "3":', '''                elif student_choice == "4":
                    try:
                        result = classical_demo(input("Enter classical cipher text: "))
                        print("Ciphertext:", result["ciphertext"])
                        print("Decrypted text:", result["decrypted_text"])
                    except ValueError as exc:
                        print(exc)

                elif student_choice == "3":''')
    code += section('MAIN MENU') + main
    code += section('PROGRAM START') + 'if __name__ == "__main__":\n    main()\n'
    ast.parse(code)
    dest = OUT / combo['folder']
    dest.mkdir(exist_ok=True)
    (dest / 'solution.py').write_text(code, encoding='utf-8')
    (dest / 'requirements.txt').write_text('pycryptodome>=3.20\n')
    actual = {k:v for k,v in combo.items() if k != 'port'}
    actual['search'] = 'SSE'
    (dest / 'algos_used.json').write_text(json.dumps(actual, indent=2))
    (dest / 'RUN.txt').write_text(f'''{title.upper()} - FILE-BASED SOLUTION

Run in this folder:
  python -m pip install -r requirements.txt
  python solution.py

The layout follows the supplied sample: helpers, Student, Faculty, HoD,
main menu, program start. Student/Faculty/HoD are the sample's role names.
Student adds/views documents and has option 4 for the classical cipher.
Faculty verifies/decrypts and searches; HoD verifies without decrypting.
Try document report1.txt, text "fever treatment followup", numbers 7 and 3.
Search for fever. Paillier gives 10; RSA/ElGamal give 21.

Algorithms: {actual}

All search uses HMAC-SHA256 SSE tokens and symmetrically encrypted IDs.
Search matches one whitespace-delimited word, ignoring case, as in the sample.
Files are stored beside solution.py; keys and documents survive restart.
Folders: encrypted, hashes, signature, public_key, add, metadata, keys.
index.json stores the encrypted inverted index. No network is used.
The add folder retains the sample name, including for multiplication.

Paillier accepts 0..322 and adds modulo 323. RSA accepts 0..142 and
multiplies modulo 143. ElGamal accepts 1..466 and multiplies modulo 467.
Classical ciphers are separate demonstrations; original documents retain
formatting. Playfair merges I/J and retains fillers; Hill/transposition
may retain padding. Signature hashing and SSE use SHA256; the index's
assigned hash is used for the separate ciphertext integrity file.
Local private keys, tiny textbook groups and legacy algorithms are lab
examples. Menus illustrate roles, without login/access enforcement.
''', encoding='utf-8')
(OUT / 'COMBINATIONS_INDEX_SSE.json').write_text(json.dumps([{k:('SSE' if k=='search' else v) for k,v in c.items() if k!='port'} for c in COMBOS], indent=2))
(OUT / 'RUN_36_COMBINATIONS.txt').write_text('36 standalone file-based solutions\n\nOpen any COMBO folder and run python solution.py.\nInstall pycryptodome using its requirements.txt if needed.\nEach folder follows the supplied Student/Faculty/HoD sample layout.\nAll 36 use SSE. Read each RUN.txt for algorithms and a test walkthrough.\nOriginal root files and the source combinations index were preserved.\n')
print('Generated', len(COMBOS), 'standalone solutions')
