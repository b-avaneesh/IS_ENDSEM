# Install dependency:
# python -m pip install pycryptodome
#
# File-based, menu-driven lab solution. No sockets.
# Timestamp trust and two-authority separation are simulated locally.
# A real deployment needs separate authority machines and a trusted time service.

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ElGamal
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

from pathlib import Path
from datetime import datetime, timedelta, timezone
from time import perf_counter
from getpass import getpass
from math import gcd, lcm

import hashlib
import hmac
import json
import secrets
import os
import re


BASE = Path(__file__).resolve().parent / "election_files"
IST = timezone(timedelta(hours=5, minutes=30))
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

CANDIDATES = [1, 2, 3]

ROLE = None
EVENTS = []

FOLDERS = [
    "keys",
    "authorities",
    "encrypted",
    "encrypted_key",
    "iv",
    "hashes",
    "signature",
    "public_key",
    "paillier",
    "metadata",
    "index",
    "receipts",
    "verified",
    "tally",
]


# =========================================================
# FILE STORAGE, TIMESTAMPS AND TIMINGS
# =========================================================

def now():
    return datetime.now(IST).strftime(TIME_FORMAT)


def save(folder, filename, value):
    path = BASE / folder / filename
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def read(folder, filename):
    path = BASE / folder / filename
    return json.loads(path.read_text(encoding="utf-8"))


def ballot_filename(ballot_id):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", ballot_id):
        raise ValueError("Use a ballot ID containing letters, digits, _ or -.")

    return ballot_id + ".json"


def require(role):
    if ROLE != role:
        raise PermissionError("Access denied for this role.")


def timed(operation, function, *args):
    started_at = datetime.now(IST).isoformat(timespec="milliseconds")
    start = perf_counter()
    status = "success"

    try:
        result = function(*args)

        if result is False:
            status = "failed"

        return result

    except Exception:
        status = "error"
        raise

    finally:
        EVENTS.append({
            "operation": operation,
            "started_at": started_at,
            "finished_at": datetime.now(IST).isoformat(
                timespec="milliseconds"
            ),
            "duration_ms": (perf_counter() - start) * 1000,
            "status": status,
        })


def show_summary(action, details):
    timestamp = datetime.now(IST).isoformat(timespec="milliseconds")

    print(f"\n[{timestamp}] {ROLE.upper()} - {action}")

    for name, value in details.items():
        print(name + ":", value)

    totals = {}

    for event in EVENTS:
        name = event["operation"]
        totals[name] = totals.get(name, 0) + event["duration_ms"]

    if totals:
        print(
            "Times (ms):",
            " | ".join(
                f"{name}={duration:.6f}"
                for name, duration in totals.items()
            ),
        )

    entry = {
        "timestamp": timestamp,
        "role": ROLE,
        "action": action,
        "details": details,
        "events": list(EVENTS),
    }

    with (BASE / "events.jsonl").open("a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")


# =========================================================
# PASSWORDS AND ROLE-BASED ACCESS
# =========================================================

def password_key(password, salt):
    return hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=32,
    )


def new_password(label):
    while True:
        password = getpass(f"Set {label} password: ")
        confirmation = getpass("Confirm password: ")

        if password and password == confirmation:
            return password

        print("Passwords must be nonempty and match.")


def login(role):
    account = read("keys", "accounts.json")[role]
    password = getpass(f"{role.capitalize()} password: ")

    actual = password_key(
        password,
        bytes.fromhex(account["salt"]),
    ).hex()

    if not hmac.compare_digest(actual, account["hash"]):
        print("Access denied.")
        return False

    return True


# =========================================================
# PASSWORD-PROTECTED THRESHOLD SHARES
# =========================================================

def protect_share(number, share, password):
    salt = os.urandom(16)
    key = password_key(password, salt)

    cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(
        str(share).encode()
    )

    save("authorities", f"{number}.json", {
        "salt": salt.hex(),
        "nonce": cipher.nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    })


def unlock_share(number, password):
    record = read("authorities", f"{number}.json")

    key = password_key(
        password,
        bytes.fromhex(record["salt"]),
    )

    cipher = AES.new(
        key,
        AES.MODE_EAX,
        nonce=bytes.fromhex(record["nonce"]),
    )

    plaintext = cipher.decrypt_and_verify(
        bytes.fromhex(record["ciphertext"]),
        bytes.fromhex(record["tag"]),
    )

    return int(plaintext.decode())


# =========================================================
# FIRST-RUN SETUP
# =========================================================

def setup():
    for folder in FOLDERS:
        (BASE / folder).mkdir(parents=True, exist_ok=True)

    if (BASE / "keys" / "settings.json").exists():
        return

    if any((BASE / folder).iterdir() for folder in []):
        pass

    if any((BASE / "keys").iterdir()):
        raise ValueError(
            "Incomplete setup. Use a fresh election_files folder."
        )

    print("\nFIRST-RUN ELECTION SETUP")
    print("Enter dates in IST using YYYY-MM-DD HH:MM:SS.")

    start = datetime.strptime(
        input("Voting starts: ").strip(),
        TIME_FORMAT,
    )

    deadline = datetime.strptime(
        input("Voting deadline: ").strip(),
        TIME_FORMAT,
    )

    if deadline <= start:
        raise ValueError("Deadline must be after the starting time.")

    accounts = {}

    for role in ("voter", "server", "tally"):
        password = new_password(role)
        salt = os.urandom(16)

        accounts[role] = {
            "salt": salt.hex(),
            "hash": password_key(password, salt).hex(),
        }

    authority_passwords = [
        new_password("authority 1"),
        new_password("authority 2"),
    ]

    print("Generating RSA-4096 keys...")

    rsa_key = RSA.generate(4096)

    save(
        "keys",
        "rsa_private.json",
        rsa_key.export_key().decode(),
    )

    save(
        "keys",
        "rsa_public.json",
        rsa_key.publickey().export_key().decode(),
    )

    print("Generating Paillier parameters...")

    while True:
        p = getPrime(1024)
        q = getPrime(1024)

        n = p * q
        lam = lcm(p - 1, q - 1)

        if p != q and gcd(lam, n) == 1:
            break

    # d is divisible by lambda, and d mod n = 1.
    # Therefore L(c^d mod n²) recovers the plaintext modulo n.
    d = lam * pow(lam, -1, n)
    period = n * lam

    share1 = secrets.randbelow(period - 1) + 1
    share2 = (d - share1) % period

    protect_share(1, share1, authority_passwords[0])
    protect_share(2, share2, authority_passwords[1])

    save("keys", "paillier_public.json", {
        "n": n,
        "g": n + 1,
    })

    # Do not persist p, q, lambda or the complete exponent d.
    del p, q, lam, d, period, share1, share2

    print("Generating educational ElGamal parameters...")

    elgamal = ElGamal.generate(512, os.urandom)

    save("keys", "elgamal.json", {
        "p": int(elgamal.p),
        "g": int(elgamal.g),
    })

    save("keys", "accounts.json", accounts)
    save("keys", "search_key.json", os.urandom(32).hex())
    save("keys", "receipt_key.json", os.urandom(32).hex())

    save("keys", "settings.json", {
        "start": start.strftime(TIME_FORMAT),
        "deadline": deadline.strftime(TIME_FORMAT),
        "created_at": now(),
    })

    print("Setup complete.")


# =========================================================
# AES-256-CBC
# =========================================================

def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)

    ciphertext = cipher.encrypt(
        pad(plaintext.encode(), AES.block_size)
    )

    return cipher.iv.hex(), ciphertext.hex()


def aes_decrypt(ciphertext, key, iv):
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=bytes.fromhex(iv),
    )

    plaintext = unpad(
        cipher.decrypt(bytes.fromhex(ciphertext)),
        AES.block_size,
    )

    return plaintext.decode()


# =========================================================
# RSA-4096 KEY ENCRYPTION
# =========================================================

def rsa_encrypt_key(key):
    public_key = RSA.import_key(
        read("keys", "rsa_public.json")
    )

    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)

    return cipher.encrypt(key).hex()


def rsa_decrypt_key(ciphertext):
    private_key = RSA.import_key(
        read("keys", "rsa_private.json")
    )

    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)

    return cipher.decrypt(bytes.fromhex(ciphertext))


# =========================================================
# SHA-512 AND ELGAMAL DIGITAL SIGNATURE
# =========================================================

def hash_message(message):
    return hashlib.sha512(message.encode()).hexdigest()


def generate_signing_keys():
    parameters = read("keys", "elgamal.json")

    p = parameters["p"]
    g = parameters["g"]

    private_key = secrets.randbelow(p - 2) + 1

    public_key = {
        "p": p,
        "g": g,
        "y": pow(g, private_key, p),
    }

    return private_key, public_key


def sign_hash(digest, private_key, public_key):
    p = public_key["p"]
    g = public_key["g"]

    while True:
        k = secrets.randbelow(p - 2) + 1

        if gcd(k, p - 1) == 1:
            break

    r = pow(g, k, p)

    s = (
        (int(digest, 16) - private_key * r)
        * pow(k, -1, p - 1)
    ) % (p - 1)

    return [r, s]


def signature_values(digest, signature, public_key):
    p = public_key["p"]
    g = public_key["g"]
    y = public_key["y"]

    r, s = signature

    if not (0 < r < p and 0 <= s < p - 1):
        raise ValueError("Invalid ElGamal signature values.")

    expected = pow(g, int(digest, 16), p)

    actual = (
        pow(y, r, p) * pow(r, s, p)
    ) % p

    return expected, actual


def verify_signature(digest, signature, public_key):
    expected, actual = signature_values(
        digest, signature, public_key
    )

    return expected == actual


# =========================================================
# PAILLIER HOMOMORPHIC ENCRYPTION
# =========================================================

def paillier_encrypt(message, n):
    if not 0 <= message < n:
        raise ValueError("Message outside Paillier range.")

    while True:
        r = secrets.randbelow(n - 1) + 1

        if gcd(r, n) == 1:
            break

    ciphertext = (
        pow(n + 1, message, n * n)
        * pow(r, n, n * n)
    ) % (n * n)

    return ciphertext, r


# =========================================================
# SEARCHABLE INDEX AND LOCAL TIMESTAMP RECEIPTS
# =========================================================

def search_token(value):
    key = bytes.fromhex(read("keys", "search_key.json"))

    return hmac.new(
        key,
        value.encode(),
        hashlib.sha256,
    ).hexdigest()


def seal(value):
    key = bytes.fromhex(read("keys", "receipt_key.json"))

    data = json.dumps(value, sort_keys=True).encode()

    return hmac.new(
        key,
        data,
        hashlib.sha256,
    ).hexdigest()


def ballot_files(filename):
    folders = [
        "encrypted", "encrypted_key", "iv", "hashes",
        "signature", "public_key", "paillier",
        "metadata", "index",
    ]

    return {
        folder: read(folder, filename)
        for folder in folders
    }


def valid_receipt(filename):
    stored = read("receipts", filename)
    computed = seal(ballot_files(filename))

    return hmac.compare_digest(stored, computed)


# =========================================================
# VOTER: AUTOMATIC SUBMISSION WORKFLOW
# =========================================================

def cast_vote(ballot_id, candidate, constituency):
    require("voter")
    EVENTS.clear()

    filename = ballot_filename(ballot_id)

    if candidate not in CANDIDATES:
        raise ValueError("Candidate must be 1, 2 or 3.")

    if not re.fullmatch(r"[0-9]+", constituency):
        raise ValueError("Constituency must contain digits only.")

    if (BASE / "metadata" / filename).exists():
        raise ValueError("Ballot ID already exists.")

    if (BASE / "tally" / "aggregate.json").exists():
        raise ValueError("Election is already closed for tallying.")

    ballot = (
        f"CandidateID={candidate};"
        f"ConstituencyID={constituency}"
    )

    digest = timed("Hashing", hash_message, ballot)

    private_key, public_key = generate_signing_keys()

    signature = timed(
        "Signing",
        sign_hash,
        digest,
        private_key,
        public_key,
    )

    n = read("keys", "paillier_public.json")["n"]

    encrypted_id, id_randomness = timed(
        "Paillier encryption",
        paillier_encrypt,
        candidate,
        n,
    )

    # Adding candidate IDs alone does not give candidate-wise counts.
    # Encrypt a one-hot vector as well: one encrypted 1, other entries 0.
    counts = {}
    randomness = {}

    for cid in CANDIDATES:
        counts[str(cid)], randomness[str(cid)] = timed(
            "Paillier encryption",
            paillier_encrypt,
            int(candidate == cid),
            n,
        )

    # Randomness is encrypted alongside the ballot so the server can
    # check Paillier consistency by re-encryption, without decrypting it.
    payload = json.dumps({
        "ballot": ballot,
        "id_randomness": id_randomness,
        "count_randomness": randomness,
    })

    aes_key = os.urandom(32)

    iv, ciphertext = timed(
        "AES encryption",
        aes_encrypt,
        payload,
        aes_key,
    )

    wrapped_key = timed(
        "RSA key encryption",
        rsa_encrypt_key,
        aes_key,
    )

    # The trusted local submission service assigns this timestamp.
    timestamp = now()
    settings = read("keys", "settings.json")

    if not settings["start"] <= timestamp <= settings["deadline"]:
        raise ValueError("Submission is outside the voting period.")

    records = {
        "encrypted": ciphertext,
        "encrypted_key": wrapped_key,
        "iv": iv,
        "hashes": digest,
        "signature": signature,
        "public_key": public_key,
        "paillier": {
            "candidate_id": encrypted_id,
            "counts": counts,
        },
        "metadata": {
            "submitted_at": timestamp,
        },
        "index": {
            "constituency": search_token(
                "constituency:" + constituency
            ),
            "minute": search_token(
                "minute:" + timestamp[:16]
            ),
        },
    }

    for folder, value in records.items():
        save(folder, filename, value)

    # Binds timestamp, ciphertext, signature, public key and vote values.
    save("receipts", filename, seal(ballot_files(filename)))

    show_summary("Cast vote", {
        "Ballot ID": ballot_id,
        "SHA-512": digest,
        "ElGamal signature": signature,
        "IV": iv,
        "AES ciphertext": ciphertext,
        "RSA-wrapped AES key": wrapped_key,
        "Paillier candidate ID ciphertext": hex(encrypted_id),
        "Submission timestamp IST": timestamp,
        "Result": "Submitted and indexed",
    })


# =========================================================
# ELECTION SERVER: AUTOMATIC VERIFICATION WORKFLOW
# =========================================================

def verify_ballot(ballot_id):
    require("server")
    EVENTS.clear()

    filename = ballot_filename(ballot_id)

    if not valid_receipt(filename):
        raise ValueError(
            "Submission receipt mismatch: stored files were changed."
        )

    stored_hash = read("hashes", filename)
    signature = read("signature", filename)
    public_key = read("public_key", filename)

    key = timed(
        "RSA key decryption",
        rsa_decrypt_key,
        read("encrypted_key", filename),
    )

    plaintext = timed(
        "AES decryption",
        aes_decrypt,
        read("encrypted", filename),
        key,
        read("iv", filename),
    )

    payload = json.loads(plaintext)

    computed_hash = timed(
        "Hashing",
        hash_message,
        payload["ballot"],
    )

    hash_valid = timed(
        "Hash verification",
        hmac.compare_digest,
        stored_hash,
        computed_hash,
    )

    signature_valid = timed(
        "Signature verification",
        verify_signature,
        computed_hash,
        signature,
        public_key,
    )

    expected, actual = signature_values(
        computed_hash,
        signature,
        public_key,
    )

    timestamp = read("metadata", filename)["submitted_at"]
    settings = read("keys", "settings.json")

    datetime.strptime(timestamp, TIME_FORMAT)

    timestamp_valid = (
        settings["start"] <= timestamp <= settings["deadline"]
        and timestamp <= now()
    )

    details = {
        "Ballot ID": ballot_id,
        "Stored SHA-512": stored_hash,
        "Computed SHA-512": computed_hash,
        "Hash comparison": "MATCH" if hash_valid else "MISMATCH",
        "ElGamal signature": signature,
        "Expected verification value": expected,
        "Actual verification value": actual,
        "Signature comparison": (
            "MATCH" if signature_valid else "MISMATCH"
        ),
        "Submission timestamp IST": timestamp,
        "Timestamp valid": timestamp_valid,
    }

    if not (hash_valid and signature_valid and timestamp_valid):
        details["Result"] = "REJECTED"
        show_summary("Verify ballot", details)
        return False

    match = re.fullmatch(
        r"CandidateID=([0-9]+);ConstituencyID=([0-9]+)",
        payload["ballot"],
    )

    if not match:
        raise ValueError("Invalid ballot format.")

    candidate = int(match.group(1))
    constituency = match.group(2)

    if candidate not in CANDIDATES:
        raise ValueError("Invalid candidate.")

    n = read("keys", "paillier_public.json")["n"]
    encrypted = read("paillier", filename)

    checks = [
        (
            candidate,
            payload["id_randomness"],
            encrypted["candidate_id"],
        )
    ]

    for cid in CANDIDATES:
        checks.append((
            int(candidate == cid),
            payload["count_randomness"][str(cid)],
            encrypted["counts"][str(cid)],
        ))

    for message, randomness, ciphertext in checks:
        if not 0 < randomness < n or gcd(randomness, n) != 1:
            raise ValueError("Invalid Paillier randomness.")

        expected_ciphertext = (
            pow(n + 1, message, n * n)
            * pow(randomness, n, n * n)
        ) % (n * n)

        if ciphertext != expected_ciphertext:
            raise ValueError(
                "Paillier ciphertext does not match the signed ballot."
            )

    expected_index = {
        "constituency": search_token(
            "constituency:" + constituency
        ),
        "minute": search_token(
            "minute:" + timestamp[:16]
        ),
    }

    if read("index", filename) != expected_index:
        raise ValueError("Search index mismatch.")

    save("verified", filename, {
        "verified_at": now(),
        "receipt": read("receipts", filename),
    })

    details["Result"] = "ACCEPTED; Paillier values remain encrypted"
    show_summary("Verify ballot", details)

    return True


# =========================================================
# SERVER SEARCH: NO BALLOT DECRYPTION
# =========================================================

def search_ballots():
    require("server")
    EVENTS.clear()

    print("\n1. Search by constituency")
    print("2. Search by time range")

    choice = input("Enter choice: ").strip()

    if choice == "1":
        constituency = input("Constituency ID: ").strip()
        tokens = {search_token("constituency:" + constituency)}
        field = "constituency"
        start = end = None

    elif choice == "2":
        print("Use YYYY-MM-DD HH:MM:SS in IST.")

        start = datetime.strptime(
            input("Start: ").strip(), TIME_FORMAT
        )

        end = datetime.strptime(
            input("End: ").strip(), TIME_FORMAT
        )

        if end < start or end - start > timedelta(days=7):
            raise ValueError("Use an ordered range of at most 7 days.")

        tokens = set()
        minute = start.replace(second=0)

        while minute <= end:
            tokens.add(search_token(
                "minute:" + minute.strftime("%Y-%m-%d %H:%M")
            ))
            minute += timedelta(minutes=1)

        field = "minute"

    else:
        raise ValueError("Invalid search choice.")

    matches = []

    for file in sorted((BASE / "index").glob("*.json")):
        if not valid_receipt(file.name):
            continue

        index = read("index", file.name)

        if index[field] not in tokens:
            continue

        if start is not None:
            timestamp = datetime.strptime(
                read("metadata", file.name)["submitted_at"],
                TIME_FORMAT,
            )

            if not start <= timestamp <= end:
                continue

        matches.append(file.stem)

    show_summary("Search index", {
        "Matching ballot IDs": matches,
    })


# =========================================================
# HOMOMORPHIC AGGREGATION
# =========================================================

def build_aggregate():
    n = read("keys", "paillier_public.json")["n"]

    totals = {
        "candidate_id_sum": 1,
        **{str(cid): 1 for cid in CANDIDATES},
    }

    receipts = {}

    for file in sorted((BASE / "verified").glob("*.json")):
        if not valid_receipt(file.name):
            raise ValueError("Accepted ballot changed: " + file.stem)

        verified = read("verified", file.name)
        receipt = read("receipts", file.name)

        if verified["receipt"] != receipt:
            raise ValueError("Ballot needs verification again.")

        receipts[file.stem] = receipt
        encrypted = read("paillier", file.name)

        totals["candidate_id_sum"] = (
            totals["candidate_id_sum"] * encrypted["candidate_id"]
        ) % (n * n)

        for cid in CANDIDATES:
            totals[str(cid)] = (
                totals[str(cid)] * encrypted["counts"][str(cid)]
            ) % (n * n)

    submitted = len(list((BASE / "receipts").glob("*.json")))

    if len(receipts) < 2:
        raise ValueError("Verify at least two ballots before tallying.")

    if len(receipts) != submitted:
        raise ValueError("Verify every submitted ballot first.")

    if len(receipts) * max(CANDIDATES) >= n:
        raise ValueError("Vote total exceeds the Paillier range.")

    return {
        "ciphertexts": totals,
        "ballots": receipts,
    }


def aggregate_votes():
    require("tally")
    EVENTS.clear()

    aggregate = timed(
        "Homomorphic aggregation",
        build_aggregate,
    )

    save("tally", "aggregate.json", aggregate)
    save("tally", "aggregate_seal.json", seal(aggregate))

    show_summary("Aggregate votes", {
        "Included ballots": list(aggregate["ballots"]),
        "Aggregate ciphertexts": aggregate["ciphertexts"],
        "Result": "Election closed; no Paillier votes decrypted",
    })


# =========================================================
# TWO-OF-TWO AGGREGATE DECRYPTION
# =========================================================

def threshold_decrypt():
    require("tally")
    EVENTS.clear()

    aggregate = read("tally", "aggregate.json")
    stored_seal = read("tally", "aggregate_seal.json")

    if not hmac.compare_digest(seal(aggregate), stored_seal):
        raise ValueError("Aggregate was changed.")

    if aggregate != build_aggregate():
        raise ValueError("Aggregate is stale.")

    n = read("keys", "paillier_public.json")["n"]
    partials = []

    # Only the sealed aggregate is accepted here.
    # There is no menu for decrypting an individual Paillier vote.
    for number in (1, 2):
        password = getpass(f"Authority {number} password: ")

        share = timed(
            f"Authority {number} authentication",
            unlock_share,
            number,
            password,
        )

        partial = {}

        for name, ciphertext in aggregate["ciphertexts"].items():
            partial[name] = timed(
                f"Authority {number} partial decryption",
                pow,
                ciphertext,
                share,
                n * n,
            )

        save("tally", f"partial_{number}.json", {
            "created_at": now(),
            "aggregate_seal": stored_seal,
            "values": partial,
        })

        partials.append(partial)
        del share

    results = {}

    for name in aggregate["ciphertexts"]:
        combined = (
            partials[0][name] * partials[1][name]
        ) % (n * n)

        if (combined - 1) % n != 0:
            raise ValueError("Invalid combined partial decryption.")

        results[name] = ((combined - 1) // n) % n

    vote_count = len(aggregate["ballots"])

    if sum(results[str(cid)] for cid in CANDIDATES) != vote_count:
        raise ValueError("Candidate counts do not match ballot count.")

    expected_id_sum = sum(
        cid * results[str(cid)] for cid in CANDIDATES
    )

    if results["candidate_id_sum"] != expected_id_sum:
        raise ValueError("Candidate-ID sum is inconsistent.")

    save("tally", "final_totals.json", {
        "completed_at": now(),
        "results": results,
    })

    details = {
        f"Candidate {cid} count": results[str(cid)]
        for cid in CANDIDATES
    }

    details["Total votes"] = vote_count
    details["Candidate ID sum"] = results["candidate_id_sum"]
    details["Result"] = "Only aggregate Paillier values decrypted"

    show_summary("Threshold decryption", details)


# =========================================================
# VOTER MENU
# =========================================================

def voter():
    require("voter")

    while True:
        print("\n------ VOTER MENU ------")
        print("1. Cast vote")
        print("2. Back")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            ballot_id = input("Ballot ID: ").strip()
            candidate = int(input("Candidate ID (1, 2, 3): "))
            constituency = input("Constituency ID: ").strip()

            cast_vote(ballot_id, candidate, constituency)

        elif choice == "2":
            break

        else:
            print("Invalid choice.")


# =========================================================
# ELECTION SERVER MENU
# =========================================================

def election_server():
    require("server")

    while True:
        print("\n------ ELECTION SERVER MENU ------")
        print("1. Verify ballot")
        print("2. Search index")
        print("3. Back")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            verify_ballot(input("Ballot ID: ").strip())

        elif choice == "2":
            search_ballots()

        elif choice == "3":
            break

        else:
            print("Invalid choice.")


# =========================================================
# TALLY AUTHORITY MENU
# =========================================================

def tally_authority():
    require("tally")

    while True:
        print("\n------ TALLY AUTHORITY MENU ------")
        print("1. Aggregate votes and close election")
        print("2. Threshold decrypt aggregate")
        print("3. Back")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            aggregate_votes()

        elif choice == "2":
            threshold_decrypt()

        elif choice == "3":
            break

        else:
            print("Invalid choice.")


# =========================================================
# MAIN MENU
# =========================================================

def main():
    global ROLE

    setup()

    handlers = {
        "1": ("voter", voter),
        "2": ("server", election_server),
        "3": ("tally", tally_authority),
    }

    while True:
        print("\n" + "=" * 45)
        print("       SECURE ELECTRONIC VOTING")
        print("=" * 45)
        print("1. Voter")
        print("2. Election Server")
        print("3. Tally Authority")
        print("4. Exit")

        choice = input("Enter choice: ").strip()

        if choice == "4":
            print("Exiting system.")
            break

        if choice not in handlers:
            print("Invalid choice.")
            continue

        role, handler = handlers[choice]

        try:
            if login(role):
                ROLE = role
                handler()

        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            IndexError,
            PermissionError,
        ) as error:
            print("Operation stopped:", error)

        finally:
            ROLE = None


# =========================================================
# PROGRAM START
# =========================================================

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nProgram closed.")