import secrets

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes


# key is a random 16 byte string for AES-128
def aes128_keygen():
    return secrets.SystemRandom().randbytes(16)


def encrypt_aes128_ecb(key, plaintext):
    # assert that the plaintext is exactly 16 bytes long, because AES block size is 16 bytes.
    assert len(PLAINTEXT) == 16
    # what is a Cipher?
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext)


def decrypt_aes128_ecb(key, ct):
    # assert that the ciphertext is exactly 16 bytes long, because AES block size is 16 bytes.
    assert len(ct) == 16
    # what is a Cipher?
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ct)


PLAINTEXT = "send 500 rs asap"


# AES-ECB is not recommended for use in practice!
# However, it is a good starting point for understanding the basics of block ciphers.
def test_aes128_ecb_static_key_insecure():
    key = bytes.fromhex("fdb20a51b1735ff24adb8d8ba199a257")
    expected_ct = "d7aa52559f760bdcc8d891fdf4d304f0"

    assert len(key) == 16
    assert len(PLAINTEXT) == 16
    assert len(bytes.fromhex(expected_ct)) == 16

    ct = encrypt_aes128_ecb(key, PLAINTEXT.encode("utf-8"))
    # the ciphertext is deterministic for a given key and plaintext
    assert ct.hex() == expected_ct

    # decryption should give us back the original plaintext
    pt = decrypt_aes128_ecb(key, ct)
    assert pt.decode() == PLAINTEXT

    # we can reuse the same cipher object to encrypt multiple messages.
    # however, the ciphertext will always be the same for the same plaintext and key.
    # This is one of the reasons why it is not recommended for use in practice.
    for _ in range(10):
        ct = encrypt_aes128_ecb(key, PLAINTEXT.encode("utf-8"))
        assert ct.hex() == expected_ct


test_aes128_ecb_static_key_insecure()


def test_aes128_ecb_random_key_insecure():
    key = aes128_keygen()

    assert len(key) == 16
    assert len(PLAINTEXT) == 16

    # the ciphertext is deterministic for a given key and plaintext
    rct = encrypt_aes128_ecb(key, PLAINTEXT.encode("utf-8"))

    # decryption should give us back the original plaintext
    pt = decrypt_aes128_ecb(key, rct)
    assert pt.decode() == PLAINTEXT

    # we can reuse the same cipher object to encrypt multiple messages.
    # however, the ciphertext will always be the same for the same plaintext and key.
    # This is one of the reasons why it is not recommended for use in practice.
    for _ in range(10):
        _new_ct = encrypt_aes128_ecb(key, PLAINTEXT.encode("utf-8"))
        assert rct == _new_ct


test_aes128_ecb_random_key_insecure()
