import contextlib
import io
import json
import runpy
import tempfile
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(r"D:\IS-ENDSEM\LAB_ENDSEM_SAMPLE_QUESTIONS\WITHOUT_SOCKET_FILE_BASED_LAB_ENDSEM_SAMPLE_PAPER_SOLUTIONS\SecureEVoting.py")
compile(SOURCE.read_text(), str(SOURCE), "exec")
ns = runpy.run_path(str(SOURCE))
g = ns["setup"].__globals__
root = Path(tempfile.mkdtemp(prefix="evoting_check_", dir=r"D:\IS-ENDSEM\tmp"))
g["DATA"] = str(root)
passwords = ["vpass", "spass", "tpass", "firstshare", "secondshare"]
answers = []
for password in passwords:
    answers.extend([password, password])
with patch.dict(g, {"getpass": lambda prompt: answers.pop(0)}), contextlib.redirect_stdout(io.StringIO()):
    g["setup"]()
assert not answers
assert g["RSA"].import_key(g["read_text"]("keys", "rsa_public.pem")).size_in_bits() == 4096
assert set(g["read_json"]("keys", "paillier_public.json")) == {"n", "g"}
assert not (root / "tally" / "final_totals.json").exists()

def expect_error(fn, message):
    try:
        fn()
    except (ValueError, FileNotFoundError) as error:
        assert message in str(error), str(error)
    else:
        raise AssertionError("Expected rejection: " + message)

def quiet(fn):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn()

quiet(lambda: g["cast_vote"]("B001", 1, "101"))
quiet(lambda: g["cast_vote"]("B002", 2, "102"))
quiet(lambda: g["cast_vote"]("B003", 1, "101"))
expect_error(lambda: g["cast_vote"]("B001", 3, "101"), "already exists")
expect_error(lambda: g["cast_vote"]("../x", 1, "101"), "alphanumeric")
expect_error(lambda: g["cast_vote"]("B004", 4, "101"), "candidate")
expect_error(lambda: g["build_aggregate"](), "at least two")
for bid in ["B001", "B002", "B003"]:
    quiet(lambda: g["verify_ballot"](bid))

# Tamper with ciphertext: reject before AES or RSA decryption.
original = g["read_text"]("encrypted", "B001.txt")
g["save_text"]("encrypted", "B001.txt", "00" + original[2:])
expect_error(lambda: g["verify_ballot"]("B001"), "Tampering")
expect_error(lambda: g["build_aggregate"](), "changed")
g["save_text"]("encrypted", "B001.txt", original)

# Exercise verification independent of the receipt check.
for folder, replacement, expected in [
    ("hashes", "0" * 128, "signature failed"),
    ("metadata", json.dumps({"timestamp": "9999-12-31 00:00:00"}), "Timestamp"),
]:
    original = g["read_text"](folder, "B001.txt")
    receipt = g["read_text"]("receipts", "B001.txt")
    g["save_text"](folder, "B001.txt", replacement)
    g["save_text"]("receipts", "B001.txt", g["seal"](g["ballot_files"]("B001")))
    expect_error(lambda: g["verify_ballot"]("B001"), expected)
    g["save_text"](folder, "B001.txt", original)
    g["save_text"]("receipts", "B001.txt", receipt)
original = g["read_text"]("paillier", "B001.txt")
receipt = g["read_text"]("receipts", "B001.txt")
changed = json.loads(original)
changed["counts"]["1"] = 1
g["save_json"]("paillier", "B001.txt", changed)
g["save_text"]("receipts", "B001.txt", g["seal"](g["ballot_files"]("B001")))
expect_error(lambda: g["verify_ballot"]("B001"), "does not match")
g["save_text"]("paillier", "B001.txt", original)
g["save_text"]("receipts", "B001.txt", receipt)

# Restart from disk; no in-memory ballots or keys should be necessary.
ns = runpy.run_path(str(SOURCE))
g = ns["setup"].__globals__
g["DATA"] = str(root)
quiet(g["setup"])
for inputs, expected in [(["1", "101"], "['B001', 'B003']"),
                         (["2", g["now"]()[:10] + " 00:00:00", g["now"]()[:10] + " 23:59:59"], "['B001', 'B002', 'B003']"),
                         (["1", "999"], "[]")]:
    output = io.StringIO()
    with patch("builtins.input", side_effect=inputs), contextlib.redirect_stdout(output):
        g["search_ballots"]()
    assert expected in output.getvalue(), output.getvalue()

quiet(g["aggregate_votes"])
expect_error(lambda: g["cast_vote"]("B004", 1, "101"), "closed")
with patch.dict(g, {"getpass": lambda prompt: "wrong"}):
    expect_error(g["threshold_decrypt"], "MAC check failed")
assert not (root / "tally" / "final_totals.json").exists()
answers = ["firstshare", "wrong"]
with patch.dict(g, {"getpass": lambda prompt: answers.pop(0)}), contextlib.redirect_stdout(io.StringIO()):
    expect_error(g["threshold_decrypt"], "MAC check failed")
assert not (root / "tally" / "final_totals.json").exists()
answers = ["firstshare", "secondshare"]
with patch.dict(g, {"getpass": lambda prompt: answers.pop(0)}):
    quiet(g["threshold_decrypt"])
assert g["read_json"]("tally", "final_totals.json") == {"1": 2, "2": 1, "3": 0, "candidate_id_sum": 4}

# Changing a final ciphertext must not allow arbitrary decryption.
aggregate = g["read_text"]("tally", "aggregate.json")
g["save_json"]("tally", "aggregate.json", {"ciphertexts": {"1": 123}, "ballots": {}})
expect_error(g["threshold_decrypt"], "changed")
g["save_text"]("tally", "aggregate.json", aggregate)
for role, password in [("voter", "vpass"), ("server", "spass"), ("tally", "tpass")]:
    with patch.dict(g, {"getpass": lambda prompt: password}):
        assert g["login"](role)
    with patch.dict(g, {"getpass": lambda prompt: "wrong"}):
        assert not quiet(lambda: g["login"](role))
# All role menus return; wrong password never enters a role menu.
answers = ["vpass", "spass", "tpass", "wrong"]
output = io.StringIO()
with patch.dict(g, {"getpass": lambda prompt: answers.pop(0)}), patch("builtins.input", side_effect=["1", "2", "2", "3", "3", "3", "2", "4"]), contextlib.redirect_stdout(output):
    g["main"]()
assert "Access denied" in output.getvalue()
print("PASS: real RSA-4096/AES/ElGamal/Paillier, restart persistence, mixed-candidate totals, both threshold shares required, role passwords/menus, searches, duplicate/invalid input, changed files, invalid signatures/timestamps, inconsistent votes, closed election, and aggregate tampering.")
print("Isolated test data:", root)
