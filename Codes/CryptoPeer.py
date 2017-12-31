from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as ascpadding
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from cryptography import x509
import os
import datetime

def generateRSAPrivateKey():
    privateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    return privateKey

def encryptRSA(plainText, publicKey):
    ciphertext = publicKey.encrypt(plainText,
        ascpadding.OAEP(
        mgf=ascpadding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None
        )
    )

    return ciphertext

def decryptRSA(cipherText, privateKey):
    plainText = privateKey.decrypt(cipherText,
        ascpadding.OAEP(
        mgf = ascpadding.MGF1(algorithm=hashes.SHA1()),
        algorithm = hashes.SHA1(),
        label = None
        )
    )
    return plainText

def signWithRSA(plainText, privateKey):
    signature = privateKey.sign(
        plainText,
        ascpadding.PSS(
            mgf=ascpadding.MGF1(hashes.SHA256()),
            salt_length=ascpadding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    return signature

def verifySignRSA(plainText, signature, publicKey):
    try:
        publicKey.verify(
            signature,
            plainText,
            ascpadding.PSS(
                mgf = ascpadding.MGF1(hashes.SHA256()),
                salt_length = ascpadding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except(InvalidSignature):
        return False

    return True

def generatePEMKeyFile(fileName, key):
    if isinstance(key, rsa.RSAPrivateKey):
        with open(fileName, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
    elif isinstance(key, rsa.RSAPublicKey):
        with open(fileName, "wb") as f:
            f.write(key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    else:
        raise TypeError('Key type is not recognized!')

    return

def getPrivateKeyContent(key):
    return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

def getPublicKeyContent(key):
    return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

def readPEMPrivateKey(fileName):
    with open(fileName, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
        key_file.read(),
        password = None,
        backend = default_backend()
    )

    return private_key

def generateCSRFile(fileName, privateKey, orgName, commonName, countryName=u"TR", localityName=u"Istanbul"):
    # Generate a CSR
    # All string parameters are unicode type
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, countryName),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, localityName),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, orgName),
        x509.NameAttribute(NameOID.COMMON_NAME, commonName),
    ])).sign(privateKey, hashes.SHA256(), default_backend())

    # Write our CSR out to disk.
    if fileName != None:
        with open(fileName, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr

def validateCertificate(certData, publicKey):
    public1 = publicKey
    public2 = certData.public_key()
    pem1 = public1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    pem2 = public2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem1 == pem2

def getCertificatePublicKey(cert):
    certificate = x509.load_pem_x509_certificate(cert, default_backend())
    publicKey = certificate.public_key()

    return publicKey

def encryptAES(plainText, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plainText)
    padded_data += padder.finalize()

    cipherText = encryptor.update(padded_data) + encryptor.finalize()

    return cipherText

def decryptAES(cipherText, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    decryptor = cipher.decryptor()
    plainText = decryptor.update(cipherText) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(plainText)
    data += unpadder.finalize()

    return data

def getMAC(message, macKey):
    h = hmac.HMAC(macKey, hashes.SHA256(), default_backend())
    h.update(message)

    return h.finalize()

def encryptFragments(message, seqNumber, hmacKey, aesKey, ivKey, dataSize=16):
    messageLength = message.__len__()
    iteration = messageLength / dataSize

    dataArray = []

    for i in range(iteration+1):
        plainText = message[i*16:(i*16+dataSize)]
        sequenceNumberString = str(seqNumber).encode('ascii').zfill(6)
        if (iteration) == i:
            typeString = str(1).encode('ascii').zfill(1)
        else:
            typeString = str(0).encode('ascii').zfill(1)
        lengthString = str(plainText.__len__()).encode('ascii').zfill(6)

        macMessage = getMAC(plainText+sequenceNumberString+typeString+lengthString, hmacKey)

        cipherMessage = encryptAES(plainText+macMessage, aesKey, ivKey)

        dataArray.append(sequenceNumberString+typeString+lengthString+cipherMessage)

    return dataArray

def verifyFragmentGetMessage(fragment, hmacKey, aesKey, ivKey):
    fragmentSequence = fragment[0:6]
    fragmentType = fragment[6]
    fragmentLength = fragment[7:13]
    cipherText = fragment[13:]

    plainText = decryptAES(cipherText, aesKey, ivKey)
    data = plainText[0:int(fragmentLength)]
    mac = plainText[(int(fragmentLength)):]
    macNew = getMAC(data+fragmentSequence+fragmentType+fragmentLength, hmacKey)
    if mac == macNew:
        return data, int(fragmentSequence), int(fragmentType), int(fragmentLength)
    else:
        return False

def keyDerivation(key, salt, size=16):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=size,
        salt=salt,
        info=None,
        backend=default_backend()
    )
    resultKey = hkdf.derive(key)

    return resultKey

def getRandomValue(length):
    return os.urandom(length)

def readCSRFile(fileName):
    with open(fileName, "rb") as f:
        csr_file = f.read()

    csr = x509.load_pem_x509_csr(csr_file, default_backend())

    return csr