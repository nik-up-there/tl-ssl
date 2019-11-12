from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class KeyPairRSA:
    def __init__(self):
        self.__key = rsa.generate_private_key(65537, 2048, default_backend())
        print('key pair created')

    def pubkey(self):
        return self.__key.public_key()

    def byte_pubkey(self):
        return self.__key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def privkey(self):
        return self.__key

    def byte_privkey(self):
        return self.__key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase")
        )
