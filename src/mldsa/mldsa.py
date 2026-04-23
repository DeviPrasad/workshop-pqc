import oqs
from sys import stdout


ALG_ML_DSA_44 = "ML-DSA-65"
ALG_ML_DSA_65 = "ML-DSA-65"
ALG_ML_DSA_87 = "ML-DSA-87"

signer = oqs.Signature(ALG_ML_DSA_65)
verifier = oqs.Signature(ALG_ML_DSA_65)

# Signer generates its keypair
signer_public_key = signer.generate_keypair()

message = b"This is a signed message"

# Signer signs the message
signature = signer.sign(message)

# Verifier verifies the signature
is_valid = verifier.verify(message, signature, signer_public_key)

print(f"Valid signature? %s", is_valid)
