import time


# =====================================================
# RSA
# =====================================================

def rsa_encrypt(m, e, n):
    return pow(m, e, n)


def rsa_decrypt(c, d, n):
    return pow(c, d, n)


# =====================================================
# ELGAMAL
# =====================================================

def elgamal_encrypt(m, p, g, x, k):
    y = pow(g, x, p)

    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p

    return c1, c2


def elgamal_decrypt(c1, c2, p, x):
    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)

    return (c2 * s_inv) % p


# =====================================================
# RABIN
# =====================================================

def rabin_encrypt(m, n):
    return (m * m) % n


def rabin_decrypt(c, p, q):
    # Simplified demonstration
    # In a real Rabin system, four possible roots exist.

    n = p * q

    roots = []

    for x in range(n):
        if (x * x) % n == c:
            roots.append(x)

    return roots


# =====================================================
# TIME MEASUREMENT
# =====================================================

def measure(label, function, loops=1000):

    start = time.perf_counter_ns()

    for i in range(loops):
        function()

    end = time.perf_counter_ns()

    total = end - start
    average = total / loops

    print(label)
    print("Total time   :", total, "ns")
    print("Average time :", average, "ns")
    print()


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":

    message = 42

    # =================================================
    # RSA PARAMETERS
    # =================================================

    n_rsa = 3233
    e = 17
    d = 2753

    print("========== RSA ==========")

    rsa_cipher = rsa_encrypt(message, e, n_rsa)
    rsa_plain = rsa_decrypt(rsa_cipher, d, n_rsa)

    print("Message     :", message)
    print("Ciphertext  :", rsa_cipher)
    print("Decrypted   :", rsa_plain)
    print()

    measure(
        "RSA Encryption",
        lambda: rsa_encrypt(message, e, n_rsa)
    )


    # =================================================
    # ELGAMAL PARAMETERS
    # =================================================

    print("========== ELGAMAL ==========")

    p = 467
    g = 2

    private_key = 127
    k = 53

    public_key = pow(g, private_key, p)

    c1, c2 = elgamal_encrypt(
        message,
        p,
        g,
        private_key,
        k
    )

    plaintext = elgamal_decrypt(
        c1,
        c2,
        p,
        private_key
    )

    print("Message     :", message)
    print("Public key  :", public_key)
    print("Ciphertext  :", (c1, c2))
    print("Decrypted   :", plaintext)
    print()

    measure(
        "ElGamal Encryption",
        lambda: elgamal_encrypt(
            message,
            p,
            g,
            private_key,
            k
        )
    )


    # =================================================
    # RABIN PARAMETERS
    # =================================================

    print("========== RABIN ==========")

    p_rabin = 499
    q_rabin = 547

    n_rabin = p_rabin * q_rabin

    rabin_cipher = rabin_encrypt(
        message,
        n_rabin
    )

    print("Message     :", message)
    print("n           :", n_rabin)
    print("Ciphertext  :", rabin_cipher)

    measure(
        "Rabin Encryption",
        lambda: rabin_encrypt(
            message,
            n_rabin
        )
    )

    print("Possible plaintexts:", rabin_decrypt(
        rabin_cipher,
        p_rabin,
        q_rabin
    ))