import datetime
import os

import base64
import time
from itertools import product

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


nbfs = [
    time.time() - 6,
    datetime.datetime.now() - datetime.timedelta(seconds=6),
    datetime.timedelta(seconds=6),
    int(time.time() - 6),
]

expires = [
    time.time() + 600,
    datetime.datetime.now() + datetime.timedelta(seconds=600),
    datetime.timedelta(seconds=600),
    int(time.time() + 600),
]


@pytest.mark.parametrize("expired,nbf", product(expires, nbfs))
def test_jwt_token(expired, nbf):
    bits = 2048
    key, public = rsa.generate_rsa(bits)

    jwt = JWT(key, public)

    token = jwt.encode(foo='bar', expired=expired, nbf=nbf)

    assert token
    assert 'foo' in jwt.decode(token)

    header, data, signature = token.split('.')

    signature = signature[::-1]

    with pytest.raises(InvalidSignatureError):
        jwt.decode(".".join((header, data, signature)))

    header = base64.b64encode(b'{"alg":"none"}').decode()

    with pytest.raises(InvalidAlgorithmError):
        jwt.decode(".".join((header, data, '')))
