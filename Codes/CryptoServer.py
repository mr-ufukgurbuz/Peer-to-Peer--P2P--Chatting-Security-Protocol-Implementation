from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import datetime

def generateRSAPrivateKey():
    privateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    return privateKey

def readCSRFile(fileName):
    with open(fileName, "rb") as f:
        csr_file = f.read()

    csr = x509.load_pem_x509_csr(csr_file, default_backend())

    return csr

def convertCsrContentToCsrObject(csrContent):
    csr = x509.load_pem_x509_csr(csrContent, default_backend())

    return csr

def validateCSRSignature(csr):
    # csr is CertificateSigningRequest type
    if csr.is_signature_valid:
        return True
    else:
        return False

def generateCertificateFile(fileName, csr, subjectPublicKey, privateKeyCA, validationDay=10):

    subject = issuer = csr.subject

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        subjectPublicKey
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for x days
        datetime.datetime.utcnow() + datetime.timedelta(days=validationDay)
    ).sign(privateKeyCA, hashes.SHA256(), default_backend())

    if fileName != None:
        with open(fileName, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert
