import base64
from collections import namedtuple
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKeyWithSerialization as RSAPrivateKey,
    RSAPublicKeyWithSerialization as RSAPublicKey,
)


KeyPair = namedtuple('KeyPair', ('private', 'public'))


def generate_rsa(bits=2048) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    '''
    Generate an RSA keypair with an exponent of 65537 in PEM format
    param: bits The key length in bits
    Return private key and public key
    '''

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    return KeyPair(private=private_key, public=public_key)


def load_private_key(data: str) -> RSAPrivateKey:
    return serialization.load_der_private_key(
        base64.b64decode(data), None, default_backend()
    )


def load_public_key(data: str) -> RSAPublicKey:
    return serialization.load_der_public_key(
        base64.b64decode(data), default_backend()
    )
