#!/usr/bin/env python3

import oqs
import logging


class Alice:
    def __init__(self):
        self.kem = oqs.KeyEncapsulation("ML-KEM-768")
        self.public_key = self.kem.generate_keypair()
        assert len(self.public_key) == 1184
        assert len(self.kem.export_secret_key()) == 2400

    def decapsulate(self, ciphertext):
        return self.kem.decap_secret(ciphertext)


class Bob:
    def __init__(self):
        self.kem = oqs.KeyEncapsulation("ML-KEM-768")

    def encapsulate(self, alice_public_key):
        (self.ct, self.ss) = self.kem.encap_secret(alice_public_key)
        return self.ct, self.ss


def test01():
    alice_kem768 = Alice()
    alice_pk = alice_kem768.public_key

    bob_kem768 = Bob()
    ct, ss = bob_kem768.encapsulate(alice_pk)

    assert len(ct) == 1088
    assert len(ss) == 32

    alice_ss = alice_kem768.decapsulate(ct)
    assert alice_ss == ss


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info("liboqs version: %s", oqs.oqs_version())
    logger.info("liboqs-python version: %s", oqs.oqs_python_version())

    test01()
