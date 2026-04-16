import secrets

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes


# nonce is a fresh 128-bit random value.
def new_128bit_nonce():
    return secrets.SystemRandom().randbytes(16)


# key is a random 16 byte string for AES-128
def aes128_keygen():
    return secrets.SystemRandom().randbytes(16)


# AES-CTR is a stream cipher mode of operation for block ciphers.
# It is not recommended to reuse the same nonce for multiple messages with the same key.
def encrypt_aes128_ctr(key, nonce, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()
    return ct


def decrypt_aes128_ctr(key, nonce, ct):
    try:
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        decryptor = cipher.decryptor()
        pt = decryptor.update(ct) + decryptor.finalize()
        return pt
    except Exception as _e:
        # print(f"Decryption failed: {e}")
        return None


PLAINTEXT_BYTES = bytes("Dude, send 500 rupees asap! need it urgently", "utf-8")


def test_aes128_random_key_nonce_reuse_insecure():
    key = aes128_keygen()
    nonce = new_128bit_nonce()

    assert len(key) == 16
    assert len(nonce) == 16

    ct = encrypt_aes128_ctr(key, nonce, PLAINTEXT_BYTES)

    # the ciphertext is not deterministic for a given key and plaintext, because of the nonce.
    # however, if we use the same nonce, we will get the same ciphertext for the same plaintext and key.
    ct2 = encrypt_aes128_ctr(key, nonce, PLAINTEXT_BYTES)
    assert ct == ct2

    # decryption should give us back the original plaintext
    pt = decrypt_aes128_ctr(key, nonce, ct)
    pt2 = decrypt_aes128_ctr(key, nonce, ct2)
    assert pt == pt2 == PLAINTEXT_BYTES


test_aes128_random_key_nonce_reuse_insecure()


def test_aes128_random_key_random_nonce():
    key = aes128_keygen()
    nonce = new_128bit_nonce()
    nonce2 = new_128bit_nonce()

    assert len(key) == 16
    assert len(nonce) == 16

    ct = encrypt_aes128_ctr(key, nonce, PLAINTEXT_BYTES)
    ct2 = encrypt_aes128_ctr(key, nonce2, PLAINTEXT_BYTES)
    assert ct != ct2

    pt = decrypt_aes128_ctr(key, nonce, ct)
    pt2 = decrypt_aes128_ctr(key, nonce2, ct2)
    assert pt == pt2 == PLAINTEXT_BYTES

    # we can reuse the same key with different nonces to encrypt multiple messages.
    # Notice the two assertions in the loop below: they assume unique ciphertext on each encryption.
    # The nonce MUST be truly fresh and random for this to hold.
    for _ in range(10):
        new_nonce = new_128bit_nonce()
        new_ct = encrypt_aes128_ctr(key, new_nonce, PLAINTEXT_BYTES)
        assert new_ct != ct
        assert new_ct != ct2
        new_pt = decrypt_aes128_ctr(key, new_nonce, new_ct)
        assert new_pt == PLAINTEXT_BYTES


test_aes128_random_key_random_nonce()
