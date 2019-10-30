import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class Certificate:
    def __init__(self, name, key_pair_rsa, validity_date):
        self.__key_pair_rsa = key_pair_rsa
        self.__name = name
        now = datetime.datetime.utcnow()
        # Creation du certificat
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        self.__cert = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(subject) \
            .public_key(key=key_pair_rsa.pubkey()) \
            .serial_number(number=x509.random_serial_number()) \
            .not_valid_before(now) \
            .not_valid_after(now + datetime.timedelta(days=validity_date)) \
            .add_extension(extension=x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                           critical=False) \
            .sign(private_key=key_pair_rsa.privkey(),
                  algorithm=hashes.SHA256(),
                  backend=default_backend())
        # print('certificate generated')
        # auto-certification
        key_pair_rsa.pubkey().verify(signature=self.__cert.signature,
                                   data=self.__cert.tbs_certificate_bytes,
                                   padding=padding.PKCS1v15(),
                                   algorithm=self.__cert.signature_hash_algorithm)
        print('certified with {}'.format(key_pair_rsa.pubkey))
        # affichage du certificat autosigné
        # print(self.__cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8"))

    def cert(self):
        return self.__cert

    def byte_cert(self):
        return self.__cert.public_bytes(encoding=serialization.Encoding.PEM)
