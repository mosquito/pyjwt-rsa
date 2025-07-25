import base64
import datetime
import json
import os
import time
from itertools import product
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from jwt.exceptions import InvalidAlgorithmError, InvalidSignatureError

from jwt_rsa import rsa, rsa_to_jwk
from jwt_rsa.jwks import JWKFetcher
from jwt_rsa.token import JWT
from jwt_rsa.types import serialization


def test_rsa_sign():
    bits = 2048
    private, public = rsa.generate_rsa(bits)

    assert private.key_size == bits

    payload = os.urandom(1024 * 16)

    signature = private.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    print("Signing OK")

    result = public.verify(
        signature,
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    assert result is None


nbfs = [
    time.time() - 6,
    datetime.datetime.now() - datetime.timedelta(seconds=6),
    datetime.timedelta(seconds=6),
    int(time.time() - 6),
    # DEFAULT VALUE
    ...,
]

expires = [
    time.time() + 600,
    datetime.datetime.now() + datetime.timedelta(seconds=600),
    datetime.timedelta(seconds=600),
    int(time.time() + 600),
    # DEFAULT VALUE
    ...,
]


@pytest.mark.parametrize("expired,nbf", product(expires, nbfs))
def test_jwt_token(expired, nbf):
    bits = 2048
    jwt = JWT(rsa.generate_rsa(bits).private)

    token = jwt.encode(foo="bar", expired=expired, nbf=nbf)

    assert token
    assert "foo" in jwt.decode(token)

    header, data, signature = token.split(".")

    signature = signature[::-1]

    with pytest.raises(InvalidSignatureError):
        jwt.decode(".".join((header, data, signature)))

    header = base64.b64encode(b'{"alg":"none"}').decode()

    with pytest.raises(InvalidAlgorithmError):
        jwt.decode(".".join((header, data, "")))


def test_jwt_token_invalid_expiration():
    bits = 2048
    jwt = JWT(rsa.generate_rsa(bits).private)

    with pytest.raises(ValueError):
        jwt.encode(foo="bar", expired=None, nbf=None)


def test_encode_and_decode_with_private_key():
    bits = 2048
    key, _ = rsa.generate_rsa(bits)

    jwt = JWT(key)
    token = jwt.encode(foo="bar")

    jwt.decode(token)


def test_decode_only_ability():
    bits = 2048
    key, public = rsa.generate_rsa(bits)

    token = JWT(key).encode(foo="bar")

    jwt = JWT(public)
    assert "foo" in jwt.decode(token)

    with pytest.raises(AttributeError):
        jwt.encode(foo=None)


def test_jwt_init():
    bits = 2048
    key, public = rsa.generate_rsa(bits)

    assert JWT(key)

    assert JWT(public)

    with pytest.raises(TypeError):
        JWT(None)


def test_load_jwk():
    bits = 2048
    key, public = rsa.generate_rsa(bits)

    jwk = rsa.rsa_to_jwk(key)
    assert rsa.load_jwk(jwk).private
    assert rsa.load_jwk(jwk).public

    jwk = json.dumps(rsa.rsa_to_jwk(key))
    assert rsa.load_jwk(jwk).private
    assert rsa.load_jwk(jwk).public

    jwk = rsa.rsa_to_jwk(public)
    assert not rsa.load_jwk(jwk).private
    assert rsa.load_jwk(jwk).public

    bad_jwk = rsa.rsa_to_jwk(key)
    bad_jwk["kty"] = "bad"

    with pytest.raises(ValueError):
        rsa.load_jwk(bad_jwk)

    bad_jwk = rsa.rsa_to_jwk(public)
    bad_jwk["kty"] = "bad"

    with pytest.raises(ValueError):
        rsa.load_jwk(bad_jwk)

    with pytest.raises(ValueError):
        # noinspection PyTypeChecker
        rsa.rsa_to_jwk(None)  # type: ignore


def test_load_public_key(tmp_path):
    bits = 2048
    key, public = rsa.generate_rsa(bits)

    public_path = tmp_path / "public.pem"
    private_path = tmp_path / "private.pem"

    with open(public_path, "wb") as fp:
        fp.write(
            public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )

    with open(private_path, "wb") as fp:
        fp.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )

    assert rsa.load_public_key(public_path)
    assert rsa.load_public_key(public_path.read_text())
    assert rsa.load_public_key(rsa.rsa_to_jwk(public))
    assert rsa.load_public_key(json.dumps(rsa.rsa_to_jwk(public)))

    assert rsa.load_private_key(private_path)
    assert rsa.load_private_key(private_path.read_text())
    assert rsa.load_private_key(rsa.rsa_to_jwk(key))
    assert rsa.load_private_key(json.dumps(rsa.rsa_to_jwk(key)))


@pytest.fixture
def rsa_key_pair():
    private_key, public_key = rsa.generate_rsa(2048)
    return private_key, public_key


@pytest.fixture
def jwk_with_real_keys(rsa_key_pair):
    private_key, public_key = rsa_key_pair

    jwk1 = rsa_to_jwk(public_key)
    jwk1['kid'] = 'real-key-1'

    private_key2, public_key2 = rsa.generate_rsa(2048)
    jwk2 = rsa_to_jwk(public_key2)
    jwk2['kid'] = 'real-key-2'

    return {"keys": [jwk1, jwk2]}


def test_jwk_fetcher_keys_decode_flow(rsa_key_pair):
    private_key1, public_key1 = rsa_key_pair
    private_key2, public_key2 = rsa.generate_rsa(2048)

    jwk1 = rsa_to_jwk(public_key1)
    jwk1['kid'] = 'key-1'

    jwk2 = rsa_to_jwk(public_key2)
    jwk2['kid'] = 'key-2'

    class TestJWKFetcher(JWKFetcher):
        def refresh(self) -> Any:
            self.keys = self.parse_jwk({"keys": [jwk1, jwk2]})
            self.decoder.cache_clear()

    fetcher = TestJWKFetcher("http://example.com")
    fetcher.refresh()

    token1 = JWT(private_key1).encode(data="first", exp=9999999999, headers={'kid': 'key-1'})
    token2 = JWT(private_key2).encode(data="second", exp=9999999999, headers={'kid': 'key-2'})

    token_no_kid = JWT(private_key2).encode(data="second", exp=9999999999)

    with pytest.raises(ValueError):
        fetcher.decode(token_no_kid)

    fetcher.jws.get_unverified_header = lambda token: {"kid": "key-1"}
    result1 = fetcher.decode(token1)
    assert result1["data"] == "first"

    fetcher.jws.get_unverified_header = lambda token: {"kid": "key-2"}
    result2 = fetcher.decode(token2)
    assert result2["data"] == "second"

    decoder1 = fetcher.decoder("key-1")
    decoder2 = fetcher.decoder("key-2")

    assert decoder1 is fetcher.decoder("key-1")
    assert decoder2 is fetcher.decoder("key-2")

    fetcher.refresh()

    assert decoder1 is not fetcher.decoder("key-1")
    assert decoder2 is not fetcher.decoder("key-2")

    with pytest.raises(ValueError):
        fetcher.decoder("non-existent-key")
