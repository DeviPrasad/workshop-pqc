import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# nonce is a fresh 128-bit random value.
def new_13byte_nonce():
    return secrets.SystemRandom().randbytes(13)


def aes128_gcm_keygen():
    return AESGCM.generate_key(bit_length=128)


def encrypt_aes128_gcm(key, nonce, plaintext):
    aesgcm = AESGCM(key)  # tag_length=16, by default.
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return ct


def decrypt_aes128_gcm(key, nonce, ct):
    try:
        aesgcm = AESGCM(key)
        ct = bytearray(ct)
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt
    except Exception as _e:
        print(f"Decryption failed: {_e}")
        return None


PLAINTEXT_BYTES = bytes("Dude, send 500 rupees asap! need it urgently", "utf-8")


def test_aes128_gcm_random_key_nonce():
    key = aes128_gcm_keygen()
    nonce = new_13byte_nonce()

    assert len(key) == 16
    assert len(nonce) == 13

    ct = encrypt_aes128_gcm(key, nonce, PLAINTEXT_BYTES)

    # decryption should give us back the original plaintext
    pt = decrypt_aes128_gcm(key, nonce, ct)
    assert pt == PLAINTEXT_BYTES


test_aes128_gcm_random_key_nonce()


def test_aes128_gcm_random_key_random_nonce_twice():
    key = aes128_gcm_keygen()
    nonce = new_13byte_nonce()

    assert len(key) == 16
    assert len(nonce) == 13

    ct = encrypt_aes128_gcm(key, nonce, PLAINTEXT_BYTES)

    nonce2 = new_13byte_nonce()
    ct2 = encrypt_aes128_gcm(key, nonce2, PLAINTEXT_BYTES)
    assert ct != ct2

    # decryption should give us back the original plaintext
    pt = decrypt_aes128_gcm(key, nonce, ct)
    pt2 = decrypt_aes128_gcm(key, nonce2, ct2)
    assert pt == pt2 == PLAINTEXT_BYTES


test_aes128_gcm_random_key_random_nonce_twice()


def test_aes128_gcm_random_key_nonce_reuse_insecure():
    key = aes128_gcm_keygen()
    nonce = new_13byte_nonce()

    assert len(key) == 16
    assert len(nonce) == 13

    ct = encrypt_aes128_gcm(key, nonce, PLAINTEXT_BYTES)

    # the ciphertext is not deterministic for a given key and plaintext, because of the nonce.
    # however, if we use the same nonce, we will get the same ciphertext for the same plaintext and key.
    ct2 = encrypt_aes128_gcm(key, nonce, PLAINTEXT_BYTES)
    assert ct == ct2

    # decryption should give us back the original plaintext
    pt = decrypt_aes128_gcm(key, nonce, ct)
    pt2 = decrypt_aes128_gcm(key, nonce, ct2)
    assert pt == pt2 == PLAINTEXT_BYTES


test_aes128_gcm_random_key_nonce_reuse_insecure()
