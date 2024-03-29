import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

from certificate import Certificate
from key_pair_rsa import KeyPairRSA


class Equipment:
    def __init__(self, name):
        self.__name = name
        print("{} created".format(name))
        self.__key = KeyPairRSA()
        self.__cert = Certificate(name=name, key_pair_rsa=self.__key, validity_date=10)

    def name(self):
        return self.__name

    def pubkey(self):
        return self.__key.pubkey()

    def byte_pubkey(self):
        return self.__key.byte_pubkey()

    def cert(self):
        return self.__cert.cert()

    def byte_cert(self):
        return self.__cert.byte_cert()

    def generate_certificate(self, issuer_name, issuer_pubkey, validity_date):
        now = datetime.datetime.utcnow()
        # Creation d'un certificat
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.__name)])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
        cert = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(issuer) \
            .public_key(key=issuer_pubkey) \
            .serial_number(number=x509.random_serial_number()) \
            .not_valid_before(now) \
            .not_valid_after(now + datetime.timedelta(days=validity_date)) \
            .add_extension(extension=x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                           critical=False) \
            .sign(private_key=self.__key.privkey(),
                  algorithm=hashes.SHA256(),
                  backend=default_backend())
        print('certificate generate by Equipment {} on Equipment {}\'s public key'.format(subject, issuer))
        return cert

    def verify_certif(self, cert_to_check, public_key):
        public_key.verify(signature=cert_to_check.signature,
                          data=cert_to_check.tbs_certificate_bytes,
                          padding=padding.PKCS1v15(),
                          algorithm=cert_to_check.signature_hash_algorithm)
        # print('Certificate verified')
        return True

