"""Run once before the offline exam: python SETUP_CHECK.py"""

import sys
from pathlib import Path


def stop(message):
    print("SETUP FAILED:", message)
    sys.exit(1)


try:
    import Crypto
except ImportError:
    stop("PyCryptodome is missing. While online run: pip install pycryptodome")

try:
    import LAB_1_BASIC_SYMMETRIC as lab1
    import LAB_2_ADVANCED_SYMMETRIC as lab2
    import LAB_3_ASYMMETRIC as lab3
    import LAB_4_KEY_MANAGEMENT_ACCESS_CONTROL as lab4
    import LAB_5_HASHING as lab5
    import LAB_6_DIGITAL_SIGNATURE as lab6
    import EASY_EXAM_TEMPLATE as template
except Exception as error:
    stop("A file could not be imported: " + str(error))


try:
    copy_folder = Path(__file__).parent / "STRAIGHT_COPY_PASTE"
    role_folder = Path(__file__).parent / "STANDARD_ROLE_TEMPLATES" / "READY_VARIANTS"
    assert len(list(copy_folder.glob("*.py"))) >= 30
    assert len(list(role_folder.glob("*.py"))) >= 31

    # Confirm the common function names exist where the operation is relevant.
    for module in [lab1, lab2, lab3, lab4, lab6, template]:
        assert callable(module.encrypt_data)
        assert callable(module.decrypt_data)
    for module in [lab3, lab4, lab6, template]:
        assert callable(module.generate_keys)
    for module in [lab3, lab4, lab5, lab6, template]:
        assert callable(module.hash_data)
    for module in [lab6, template]:
        assert callable(module.sign_data)
        assert callable(module.verify_signature)

    # Lab 1
    text = "INFORMATIONSECURITY"
    encrypted = lab1.encrypt_data(text, 20, "additive")
    assert lab1.decrypt_data(encrypted, 20, "additive") == text
    encrypted = lab1.encrypt_data(text, (15, 20), "affine")
    assert lab1.decrypt_data(encrypted, (15, 20), "affine") == text

    # Lab 2
    encrypted = lab2.encrypt_data("test", "A1B2C3D4", "des")
    assert lab2.decrypt_data(encrypted, "A1B2C3D4", "des") == "test"
    key = "0123456789ABCDEF0123456789ABCDEF"
    encrypted = lab2.encrypt_data("test", key, "aes-128")
    assert lab2.decrypt_data(encrypted, key, "aes-128") == "test"

    # Lab 3
    public, private = lab3.generate_keys("rsa")
    encrypted = lab3.encrypt_data("test", public, "rsa")
    assert lab3.decrypt_data(encrypted, private, "rsa") == "test"
    public, private = lab3.generate_keys("elgamal")
    encrypted = lab3.encrypt_data("test", public, "elgamal")
    assert lab3.decrypt_data(encrypted, private, "elgamal") == "test"

    # Lab 4
    public, private = lab4.generate_keys("rabin", bits=256)
    encrypted = lab4.encrypt_data("test", public, "rabin")
    assert lab4.decrypt_data(encrypted, private, "rabin") == "test"

    # Lab 5
    assert lab5.verify_hash("test", lab5.hash_data("test", "sha256"))

    # Lab 6
    public, private = lab6.generate_keys("elgamal")
    signature = lab6.sign_data("test", private, "elgamal")
    assert lab6.verify_signature("test", signature, public, "elgamal")

    # Exam template
    encrypted = template.encrypt_data("test")
    assert template.decrypt_data(encrypted) == "test"
except Exception as error:
    stop("A function test failed: " + repr(error))


print("SETUP OK")
print("Python:", sys.version.split()[0])
print("PyCryptodome:", Crypto.__version__)
print("All lab files imported and basic encryption/decryption tests passed.")
print("Straight-copy files:", len(list(copy_folder.glob("*.py"))))
print("Ready role templates:", len(list(role_folder.glob("*.py"))))
