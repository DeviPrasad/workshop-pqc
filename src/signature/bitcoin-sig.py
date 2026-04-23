from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class Secp256K1Agent:
    # ephemeral keys
    # Exercise - what is the size of signing_key and verification_key?
    # Exercise - what is the size of verification_key and verification_key?
    # Exercise - write assertions here!
    # hint - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve.key_size
    def __init__(self):
        self.signing_key = ec.generate_private_key(ec.SECP256K1())
        self.verification_key = self.signing_key.public_key()
        assert self.signing_key.key_size == 256
        assert self.verification_key.key_size == 256

    # return a signature of 'data'.
    # Exercise - what is the size of the signature? How would you test it?
    def sign_deterministic(self, data):
        return self.signing_key.sign(data, ec.ECDSA(hashes.SHA256(), True))

    def verify_deterministic(self, data, signature):
        try:
            self.verification_key.verify(
                signature, data, ec.ECDSA(hashes.SHA256(), True)
            )
        except InvalidSignature:
            return False
        return True


def test_deterministic_ds():
    alex = Secp256K1Agent()
    data = b"Please prepare the document and email it to me before 3 pm today."
    sign1 = alex.sign_deterministic(data)
    sign2 = alex.sign_deterministic(data)
    assert alex.verify_deterministic(data, sign1)
    assert alex.verify_deterministic(data, sign2)
    assert sign1 == sign2
    print(len(sign1))


test_deterministic_ds()

# Exercise - modify Secp256K1Agent to introduce non-deterministic signing and verification.
# Exercise - write tests!
