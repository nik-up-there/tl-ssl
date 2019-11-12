import datetime

import networkx as nx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

from certificate import Certificate
from key_pair_rsa import KeyPairRSA


def verify_cert(cert, public_key):
    try:
        public_key.verify(signature=cert.signature,
                          data=cert.tbs_certificate_bytes,
                          padding=padding.PKCS1v15(),
                          algorithm=cert.signature_hash_algorithm)
        return True
    except InvalidSignature:
        return False


class Equipment:
    def __init__(self, id_equipment):
        self.__id_equipment = id_equipment
        self.__name = "Equipment {}".format(id_equipment)
        self.__key = KeyPairRSA()
        self.__cert = Certificate(name=self.__name, key_pair_rsa=self.__key, validity_date=10)
        self.__graph = nx.MultiDiGraph()
        self.__graph.add_node(id_equipment, cert=self.cert())
        print('#################################################################')
        print("{} created".format(self.__name))
        print(self.PEM_pubkey()[:-2])
        print('#################################################################')

    def id_equipment(self):
        return self.__id_equipment

    def name(self):
        return self.__name

    def pubkey_object(self):
        return self.__key.pubkey()

    def byte_pubkey(self):
        return self.__key.byte_pubkey()

    def PEM_pubkey(self):
        return self.__key.byte_pubkey().decode("utf-8")

    def cert_object(self):
        return self.__cert.cert()

    def byte_cert(self):
        return self.__cert.byte_cert()

    def PEM_cert(self):
        return self.__cert.byte_cert().decode("utf-8")

    def graph(self):
        return self.__graph

    def generate_cert(self, issuer_name, issuer_pubkey, contract_length=10):
        today = datetime.datetime.utcnow()
        validity_day = today + datetime.timedelta(days=contract_length)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.__name)])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
        cert = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(issuer) \
            .public_key(key=issuer_pubkey) \
            .serial_number(number=x509.random_serial_number()) \
            .not_valid_before(today) \
            .not_valid_after(validity_day) \
            .add_extension(extension=x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                           critical=False) \
            .sign(private_key=self.__key.privkey(),
                  algorithm=hashes.SHA256(),
                  backend=default_backend())
        print('#################################################################')
        print("Certificate on {} pubkey created by {}".format(issuer_name, self.__name))
        print(cert)
        print('#################################################################')
        return cert
