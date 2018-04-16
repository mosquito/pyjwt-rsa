import os

import base64
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from jwt.exceptions import InvalidSignatureError, InvalidAlgorithmError

from jwt_rsa.token import JWT
from jwt_rsa import rsa


def test_rsa_sign():
    bits = 2048
    private, public = rsa.generate_rsa(bits)

    assert private.key_size == bits

    payload = os.urandom(1024 * 16)

    signature = private.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("Signing OK")

    result = public.verify(
        signature,
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    assert result is None


def test_jwt_token():
    bits = 2048
    key, public = rsa.generate_rsa(bits)

    jwt = JWT(key, public)

    token = jwt.encode(foo='bar')

    assert token
    assert 'foo' in jwt.decode(token)

    header, data, signature = token.split('.')

    signature = signature[::-1]

    with pytest.raises(InvalidSignatureError):
        jwt.decode(".".join((header, data, signature)))

    header = base64.b64encode(b'{"alg":"none"}').decode()

    with pytest.raises(InvalidAlgorithmError):
        jwt.decode(".".join((header, data, '')))
