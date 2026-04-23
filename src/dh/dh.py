from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Curve25519 - private key and public key are 32 bytes in length (256 bits).
class X25519Agent:
    def __init__(self):
        self.private = X25519PrivateKey.generate()
        self.public = self.private.public_key()
        assert len(self.private.private_bytes_raw()) == 32
        assert len(self.public.public_bytes_raw()) == 32

    def public_key(self):
        return self.public

    # Diffie-Hellman
    def dh(self, peer_public_key):
        assert isinstance(peer_public_key, X25519PublicKey)
        return self.private.exchange(peer_public_key)


def test_dh_exchange():
    cl = X25519Agent()
    server = X25519Agent()
    cl_shared_secret = cl.dh(server.public_key())
    assert len(cl_shared_secret) == 32
    server_shared_secret = server.dh(cl.public_key())
    assert len(server_shared_secret) == 32
    assert cl_shared_secret == server_shared_secret


def test_dh_bad_01():
    malicious_public_key = X25519PublicKey.from_public_bytes(bytes(32))
    server = X25519Agent()
    failed_dh = False
    try:
        server.dh(malicious_public_key)
    except Exception as e:
        failed_dh = True
    #
    assert failed_dh


# test 16K DH exchanges with random client public key
def test_random_key_dh():
    import os

    server = X25519Agent()
    for _ in range(1024 * 16):
        random_public_key = X25519PublicKey.from_public_bytes(os.urandom(32))
        shared_secret = server.dh(random_public_key)
        assert len(shared_secret) == 32


test_dh_exchange()
test_random_key_dh()

test_dh_bad_01()
