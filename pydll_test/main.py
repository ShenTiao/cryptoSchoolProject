from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives import serialization


# param = input().encode()
#
# parameters = load_pem_parameters(param)
# isinstance(param,dh.DHParameters)
# peer_private_key = parameters.generate_private_key()
# peer_public_key_2 = parameters.generate_private_key().public_key()
# enpubkey = peer_public_key_2.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
# print(enpubkey.decode())

parameters =
peer_private_key = parameters.generate_private_key()
shared_key = server_private_key.exchange(peer_private_key.public_key())


encodeServerPriKey = server_private_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )

private_key_2 = parameters.generate_private_key()
peer_public_key_2 = parameters.generate_private_key().public_key()
shared_key_2 = private_key_2.exchange(peer_public_key_2)

test_2 = peer_public_key_2.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
print(test_2.decode())
test = server_private_key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
print(type(test))
print(test.decode())
key = load_pem_public_key(test)
isinstance(key,dh.DHPublicKey)
print(key)