"""File-based solution to the sample e-voting paper. No sockets.
Read START_HERE.txt first. This is a single-computer teaching demonstration.
"""
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from getpass import getpass
from math import gcd, lcm

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA, ElGamal
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad, unpad

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "election_files")
CANDIDATES = [1, 2, 3]
IST = timezone(timedelta(hours=5, minutes=30))
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
# Wide dates make the lab runnable. Change these before setting up an election.
START = "2020-01-01 00:00:00"
DEADLINE = "2099-12-31 23:59:59"


# =========================================================
# FILE STORAGE
# =========================================================
def save_text(folder, filename, text):
    with open(os.path.join(DATA, folder, filename), "w", encoding="utf-8") as f:
        f.write(text)


def read_text(folder, filename):
    with open(os.path.join(DATA, folder, filename), "r", encoding="utf-8") as f:
        return f.read()


def save_json(folder, filename, value):
    save_text(folder, filename, json.dumps(value, sort_keys=True))


def read_json(folder, filename):
    return json.loads(read_text(folder, filename))


def valid_id(ballot_id):
    # Do not allow paths such as ../keys in a ballot filename.
    return 1 <= len(ballot_id) <= 40 and ballot_id.isascii() and ballot_id.isalnum()


def now():
    return datetime.now(IST).strftime(TIME_FORMAT)


# =========================================================
# PASSWORDS AND TWO PASSWORD-PROTECTED SHARE FILES
# =========================================================
def password_key(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)


def new_password(label):
    while True:
        password = getpass("Set " + label + " password: ")
        if password and password == getpass("Confirm password: "):
            return password
        print("Passwords must be nonempty and match.")


def protect_share(number, share, password):
    salt = os.urandom(16)
    cipher = AES.new(password_key(password, salt), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(str(share).encode())
    save_json("authorities", str(number) + ".json", {
        "salt": salt.hex(), "nonce": cipher.nonce.hex(),
        "ciphertext": ciphertext.hex(), "tag": tag.hex()
    })


def unlock_share(number, password):
    record = read_json("authorities", str(number) + ".json")
    key = password_key(password, bytes.fromhex(record["salt"]))
    cipher = AES.new(key, AES.MODE_EAX, nonce=bytes.fromhex(record["nonce"]))
    plaintext = cipher.decrypt_and_verify(
        bytes.fromhex(record["ciphertext"]), bytes.fromhex(record["tag"]))
    return int(plaintext.decode())


def login(role):
    account = read_json("keys", "accounts.json")[role]
    password = getpass(role + " password: ")
    actual = password_key(password, bytes.fromhex(account["salt"])).hex()
    if not hmac.compare_digest(actual, account["hash"]):
        print("Access denied.")
        return False
    return True


# =========================================================
# FIRST RUN: CREATE FOLDERS AND SAVE KEYS ONCE
# =========================================================
def setup():
    folders = ["keys", "authorities", "encrypted", "encrypted_key", "iv",
               "hashes", "signature", "public_key", "voter_private_key",
               "paillier", "metadata", "index", "receipts", "verified", "tally"]
    for folder in folders:
        os.makedirs(os.path.join(DATA, folder), exist_ok=True)
    if os.path.exists(os.path.join(DATA, "keys", "settings.json")):
        return
    if os.listdir(os.path.join(DATA, "keys")):
        raise ValueError("Incomplete first setup. Use a fresh election_files folder.")

    print("First run: set three role passwords and two authority passwords.")
    accounts = {}
    for role in ["voter", "server", "tally"]:
        password = new_password(role)
        salt = os.urandom(16)
        accounts[role] = {"salt": salt.hex(),
                          "hash": password_key(password, salt).hex()}
    password1 = new_password("authority 1")
    password2 = new_password("authority 2")

    print("Generating RSA-4096 keys. Please wait...")
    rsa_key = RSA.generate(4096)
    save_text("keys", "rsa_private.pem", rsa_key.export_key().decode())
    save_text("keys", "rsa_public.pem", rsa_key.publickey().export_key().decode())
    save_json("keys", "accounts.json", accounts)
    save_text("keys", "search_key.txt", os.urandom(32).hex())
    save_text("keys", "receipt_key.txt", os.urandom(32).hex())

    # Paillier: the factors are not saved. Only n and g are public.
    print("Generating Paillier keys and splitting the private exponent...")
    while True:
        p = getPrime(1024)
        q = getPrime(1024)
        n = p * q
        lam = lcm(p - 1, q - 1)
        if p != q and gcd(lam, n) == 1:
            break
    # d is a multiple of lambda and d % n == 1.
    d = lam * pow(lam, -1, n)
    share1 = secrets.randbelow(n * lam - 1) + 1
    share2 = (d - share1) % (n * lam)
    protect_share(1, share1, password1)
    protect_share(2, share2, password2)
    save_json("keys", "paillier_public.json", {"n": n, "g": n + 1})

    # Small ElGamal size keeps this classroom example quick; see notes.
    print("Generating educational ElGamal parameters...")
    eg = ElGamal.generate(256, os.urandom)
    save_json("keys", "elgamal_parameters.json", {"p": int(eg.p), "g": int(eg.g)})
    save_json("keys", "settings.json", {"start": START, "deadline": DEADLINE})
    print("Setup complete. Keys will be reused on later runs.")


# =========================================================
# AES-256-CBC AND RSA-4096 KEY WRAPPING
# =========================================================
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv.hex(), ciphertext.hex()


def aes_decrypt(ciphertext, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=bytes.fromhex(iv))
    plaintext = unpad(cipher.decrypt(bytes.fromhex(ciphertext)), AES.block_size)
    return plaintext.decode()


def rsa_encrypt_key(key):
    public_key = RSA.import_key(read_text("keys", "rsa_public.pem"))
    return PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(key).hex()


def rsa_decrypt_key(ciphertext):
    private_key = RSA.import_key(read_text("keys", "rsa_private.pem"))
    return PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(bytes.fromhex(ciphertext))


# =========================================================
# SHA-512 AND ELGAMAL SIGNATURE
# =========================================================
def hash_message(message):
    return hashlib.sha512(message.encode()).hexdigest()


def sign_hash(digest, x, p, g):
    while True:
        k = secrets.randbelow(p - 2) + 1
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((int(digest, 16) - x * r) * pow(k, -1, p - 1)) % (p - 1)
    return [r, s]


def verify_signature(digest, signature, public_key):
    p = public_key["p"]
    g = public_key["g"]
    y = public_key["y"]
    r, s = signature
    if not (0 < r < p and 0 <= s < p - 1):
        return False
    left = (pow(y, r, p) * pow(r, s, p)) % p
    right = pow(g, int(digest, 16), p)
    return left == right


# =========================================================
# PAILLIER: MULTIPLY CIPHERTEXTS TO ADD VOTES
# =========================================================
def paillier_encrypt(message, n):
    while True:
        r = secrets.randbelow(n - 1) + 1
        if gcd(r, n) == 1:
            break
    ciphertext = (pow(n + 1, message, n * n) * pow(r, n, n * n)) % (n * n)
    return ciphertext, r


# =========================================================
# SEARCH TOKENS AND TRUSTED LOCAL RECEIPTS
# =========================================================
def search_token(value):
    key = bytes.fromhex(read_text("keys", "search_key.txt"))
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()


def seal(value):
    # The local server authenticates its timestamp and submitted files.
    key = bytes.fromhex(read_text("keys", "receipt_key.txt"))
    data = json.dumps(value, sort_keys=True).encode()
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def ballot_files(ballot_id):
    record = {}
    for folder in ["encrypted", "encrypted_key", "iv", "hashes", "signature",
                   "public_key", "paillier", "metadata", "index"]:
        record[folder] = read_text(folder, ballot_id + ".txt")
    return record


def valid_receipt(ballot_id):
    expected = read_text("receipts", ballot_id + ".txt")
    return hmac.compare_digest(seal(ballot_files(ballot_id)), expected)


# =========================================================
# VOTER: ENCRYPT, SIGN, AND STORE IN SEPARATE FILES
# =========================================================
def cast_vote(ballot_id, candidate, constituency):
    if not valid_id(ballot_id) or candidate not in CANDIDATES:
        raise ValueError("Use an alphanumeric ballot ID and candidate 1, 2, or 3.")
    if not constituency.isascii() or not constituency.isdigit():
        raise ValueError("Constituency ID must contain digits only.")
    if os.path.exists(os.path.join(DATA, "metadata", ballot_id + ".txt")):
        raise ValueError("Ballot ID already exists. It cannot be overwritten.")
    if os.path.exists(os.path.join(DATA, "tally", "aggregate.json")):
        raise ValueError("The election is closed for tallying.")
    timestamp = now()
    settings = read_json("keys", "settings.json")
    if not settings["start"] <= timestamp <= settings["deadline"]:
        raise ValueError("Outside the voting period.")

    ballot = "CandidateID=" + str(candidate) + ";ConstituencyID=" + constituency
    digest = hash_message(ballot)
    eg = read_json("keys", "elgamal_parameters.json")
    x = secrets.randbelow(eg["p"] - 2) + 1
    public_key = {"p": eg["p"], "g": eg["g"], "y": pow(eg["g"], x, eg["p"])}
    signature = sign_hash(digest, x, eg["p"], eg["g"])

    n = read_json("keys", "paillier_public.json")["n"]
    vote_ciphertext, vote_randomness = paillier_encrypt(candidate, n)
    counts = {}
    randomness = {}
    for cid in CANDIDATES:
        if cid == candidate:
            value = 1
        else:
            value = 0
        counts[str(cid)], randomness[str(cid)] = paillier_encrypt(value, n)

    # Randomness stays inside AES encryption. The server can check that
    # the Paillier values really match the ballot, without decrypting them.
    payload = {"ballot": ballot, "vote_randomness": vote_randomness,
               "count_randomness": randomness}
    aes_key = os.urandom(32)
    iv, ciphertext = aes_encrypt(json.dumps(payload), aes_key)
    wrapped_key = rsa_encrypt_key(aes_key)
    index = {"constituency": search_token("constituency:" + constituency),
             "minute": search_token("minute:" + timestamp[:16])}
    filename = ballot_id + ".txt"
    save_text("encrypted", filename, ciphertext)
    save_text("encrypted_key", filename, wrapped_key)
    save_text("iv", filename, iv)
    save_text("hashes", filename, digest)
    save_json("signature", filename, signature)
    save_json("public_key", filename, public_key)
    save_text("voter_private_key", filename, str(x))
    save_json("paillier", filename, {"candidate_id": vote_ciphertext, "counts": counts})
    save_json("metadata", filename, {"timestamp": timestamp})
    save_json("index", filename, index)
    save_text("receipts", filename, seal(ballot_files(ballot_id)))

    print("Ballot UTF-8:", ballot)
    print("SHA-512:", digest)
    print("IV:", iv)
    print("AES-256-CBC ciphertext:", ciphertext)
    print("RSA-4096 encrypted AES key:", wrapped_key)
    print("ElGamal signature:", signature)
    print("Paillier candidate ID ciphertext:", hex(vote_ciphertext))
    print("Encrypted 0/1 counts:", counts)
    print("Timestamp:", timestamp, "IST")
    print(ballot_id, "submitted and indexed.")


# =========================================================
# ELECTION SERVER: VERIFY BEFORE ACCEPTING A BALLOT
# =========================================================
def verify_ballot(ballot_id):
    if not valid_id(ballot_id):
        raise ValueError("Invalid ballot ID.")
    filename = ballot_id + ".txt"
    # Reject changed ciphertext, metadata, keys, or homomorphic values first.
    if not valid_receipt(ballot_id):
        raise ValueError("Tampering detected. Decryption stopped.")
    timestamp = read_json("metadata", filename)["timestamp"]
    settings = read_json("keys", "settings.json")
    datetime.strptime(timestamp, TIME_FORMAT)
    if not settings["start"] <= timestamp <= settings["deadline"] or timestamp > now():
        raise ValueError("Timestamp outside voting period or in the future.")
    digest = read_text("hashes", filename)
    signature = read_json("signature", filename)
    public_key = read_json("public_key", filename)
    if not verify_signature(digest, signature, public_key):
        raise ValueError("ElGamal signature failed.")
    key = rsa_decrypt_key(read_text("encrypted_key", filename))
    payload = json.loads(aes_decrypt(read_text("encrypted", filename),
                                   read_text("iv", filename), key))
    if hash_message(payload["ballot"]) != digest:
        raise ValueError("SHA-512 mismatch.")
    parts = payload["ballot"].split(";")
    candidate = int(parts[0].split("=")[1])
    constituency = parts[1].split("=")[1]
    if candidate not in CANDIDATES:
        raise ValueError("Invalid candidate.")
    n = read_json("keys", "paillier_public.json")["n"]
    encrypted = read_json("paillier", filename)
    # Re-encryption checks consistency; no Paillier private key is used.
    values = {"candidate_id": candidate}
    ciphertexts = {"candidate_id": encrypted["candidate_id"]}
    random_values = {"candidate_id": payload["vote_randomness"]}
    for cid in CANDIDATES:
        values[str(cid)] = int(candidate == cid)
        ciphertexts[str(cid)] = encrypted["counts"][str(cid)]
        random_values[str(cid)] = payload["count_randomness"][str(cid)]
    for name in values:
        r = random_values[name]
        if not 0 < r < n or gcd(r, n) != 1:
            raise ValueError("Invalid Paillier randomness.")
        expected = (pow(n + 1, values[name], n*n) * pow(r, n, n*n)) % (n*n)
        if ciphertexts[name] != expected:
            raise ValueError("Paillier value does not match the signed ballot.")
    index = read_json("index", filename)
    if index != {"constituency": search_token("constituency:" + constituency),
                 "minute": search_token("minute:" + timestamp[:16])}:
        raise ValueError("Search index mismatch.")
    save_json("verified", filename, {"receipt": read_text("receipts", filename),
                                     "verified_at": now()})
    print("RSA unwrap successful; signature valid; SHA-512 matches.")
    print("Timestamp valid; Paillier values consistent and still encrypted.")
    print(ballot_id, "accepted.")


# =========================================================
# SEARCH ENCRYPTED INDEX: NO BALLOT DECRYPTION
# =========================================================
def search_ballots():
    print("1. Constituency")
    print("2. Time range (IST, maximum 7 days)")
    choice = input("Enter choice: ").strip()
    tokens = []
    if choice == "1":
        value = input("Constituency ID: ").strip()
        tokens.append(search_token("constituency:" + value))
        field = "constituency"
    elif choice == "2":
        start = input("Start YYYY-MM-DD HH:MM:SS: ").strip()
        end = input("End   YYYY-MM-DD HH:MM:SS: ").strip()
        start_time = datetime.strptime(start, TIME_FORMAT)
        end_time = datetime.strptime(end, TIME_FORMAT)
        start = start_time.strftime(TIME_FORMAT)
        end = end_time.strftime(TIME_FORMAT)
        if end_time < start_time or end_time - start_time > timedelta(days=7):
            raise ValueError("Use an ordered range of at most 7 days.")
        minute = start_time.replace(second=0)
        while minute <= end_time:
            tokens.append(search_token("minute:" + minute.strftime("%Y-%m-%d %H:%M")))
            minute += timedelta(minutes=1)
        field = "minute"
    else:
        print("Invalid choice.")
        return
    matches = []
    for filename in sorted(os.listdir(os.path.join(DATA, "index"))):
        ballot_id = filename[:-4]
        if not valid_receipt(ballot_id):
            print("Skipping changed ballot:", ballot_id)
            continue
        index = read_json("index", filename)
        if index[field] in tokens:
            timestamp = read_json("metadata", filename)["timestamp"]
            if choice == "1" or start <= timestamp <= end:
                matches.append(ballot_id)
    print("Matching ballot IDs:", matches)


# =========================================================
# HOMOMORPHIC AGGREGATION: ACCEPTED BALLOTS ONLY
# =========================================================
def build_aggregate():
    n = read_json("keys", "paillier_public.json")["n"]
    totals = {"candidate_id_sum": 1}
    for cid in CANDIDATES:
        totals[str(cid)] = 1
    receipts = {}
    for filename in sorted(os.listdir(os.path.join(DATA, "verified"))):
        ballot_id = filename[:-4]
        verified = read_json("verified", filename)
        if not valid_receipt(ballot_id):
            raise ValueError("Accepted ballot changed: " + ballot_id)
        if verified["receipt"] != read_text("receipts", filename):
            raise ValueError("Ballot must be verified again: " + ballot_id)
        receipts[ballot_id] = verified["receipt"]
        encrypted = read_json("paillier", filename)
        totals["candidate_id_sum"] = (totals["candidate_id_sum"] * encrypted["candidate_id"]) % (n*n)
        for cid in CANDIDATES:
            totals[str(cid)] = (totals[str(cid)] * encrypted["counts"][str(cid)]) % (n*n)
    if len(receipts) < 2:
        raise ValueError("Verify at least two ballots before publishing an aggregate.")
    if len(receipts) * max(CANDIDATES) >= n:
        raise ValueError("Too many votes for this Paillier modulus.")
    if len(receipts) != len(os.listdir(os.path.join(DATA, "receipts"))):
        raise ValueError("Verify every submitted ballot before closing the election.")
    return {"ciphertexts": totals, "ballots": receipts}


def aggregate_votes():
    aggregate = build_aggregate()
    save_json("tally", "aggregate.json", aggregate)
    save_text("tally", "aggregate_seal.txt", seal(aggregate))
    print("Election closed. Included ballot IDs:", list(aggregate["ballots"]))
    print("Aggregate ciphertexts:", aggregate["ciphertexts"])
    print("Encrypted values multiplied modulo n squared; nothing decrypted.")


# =========================================================
# TWO-OF-TWO DECRYPTION: COMBINE PARTIAL RESULTS, NOT KEYS
# =========================================================
def threshold_decrypt():
    aggregate = read_json("tally", "aggregate.json")
    if not hmac.compare_digest(seal(aggregate), read_text("tally", "aggregate_seal.txt")):
        raise ValueError("Aggregate file was changed.")
    if aggregate != build_aggregate():
        raise ValueError("Stored aggregate is stale. Aggregate again.")
    n = read_json("keys", "paillier_public.json")["n"]
    partials = []
    for number in [1, 2]:
        password = getpass("Authority " + str(number) + " password: ")
        share = unlock_share(number, password)
        partial = {}
        for name in aggregate["ciphertexts"]:
            ciphertext = aggregate["ciphertexts"][name]
            partial[name] = pow(ciphertext, share, n*n)
        # Each authority's partial result is bound to this exact aggregate.
        save_json("tally", "partial_" + str(number) + ".json", {
            "aggregate_seal": seal(aggregate), "partial": partial})
        partials.append(partial)
        del share
        print("Authority", number, "partial decryption computed.")
    results = {}
    for name in aggregate["ciphertexts"]:
        combined = (partials[0][name] * partials[1][name]) % (n*n)
        if (combined - 1) % n != 0:
            raise ValueError("Invalid combined decryption.")
        results[name] = ((combined - 1) // n) % n
    total = 0
    for cid in CANDIDATES:
        print("Candidate", cid, "count:", results[str(cid)])
        total += results[str(cid)]
    if total != len(aggregate["ballots"]):
        raise ValueError("Counts do not match the number of ballots.")
    save_json("tally", "final_totals.json", results)
    print("Overall votes:", total)
    print("Candidate ID sum (not a per-candidate count):", results["candidate_id_sum"])
    print("Only aggregate Paillier ciphertexts were decrypted.")


# =========================================================
# ROLE MENUS - SAME FUNCTION-BASED STYLE AS EduSecure
# =========================================================
def voter():
    while True:
        print("\n===== VOTER =====\n1. Cast vote\n2. Back")
        choice = input("Enter choice: ").strip()
        if choice == "1":
            ballot_id = input("Ballot ID (example B001): ").strip()
            candidate = int(input("Candidate ID (1, 2, 3): "))
            constituency = input("Constituency ID: ").strip()
            cast_vote(ballot_id, candidate, constituency)
        elif choice == "2":
            break
        else:
            print("Invalid choice.")


def election_server():
    while True:
        print("\n===== ELECTION SERVER =====\n1. Verify ballot\n2. Search index\n3. Back")
        choice = input("Enter choice: ").strip()
        if choice == "1":
            verify_ballot(input("Ballot ID: ").strip())
        elif choice == "2":
            search_ballots()
        elif choice == "3":
            break
        else:
            print("Invalid choice.")


def tally_authority():
    while True:
        print("\n===== TALLY AUTHORITY =====\n1. Aggregate and close election\n2. Threshold decrypt\n3. Back")
        choice = input("Enter choice: ").strip()
        if choice == "1":
            aggregate_votes()
        elif choice == "2":
            threshold_decrypt()
        elif choice == "3":
            break
        else:
            print("Invalid choice.")


def main():
    print("File-based e-voting lab. Data folder:", DATA)
    setup()
    while True:
        print("\n" + "=" * 40)
        print("          SECURE E-VOTING SYSTEM")
        print("=" * 40)
        print("1. Voter\n2. Election Server\n3. Tally Authority\n4. Exit")
        choice = input("Enter choice: ").strip()
        try:
            if choice == "1":
                if login("voter"):
                    voter()
            elif choice == "2":
                if login("server"):
                    election_server()
            elif choice == "3":
                if login("tally"):
                    tally_authority()
            elif choice == "4":
                print("Exiting system.")
                break
            else:
                print("Invalid choice.")
        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
            print("Operation stopped:", error)
            print("Returning to the main menu.")


if __name__ == "__main__":
    main()
