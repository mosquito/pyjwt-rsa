import base64
import json
import os
from io import StringIO
from unittest import mock

import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from jwt_rsa.keygen import main as keygen
from jwt_rsa.rsa import generate_rsa, load_private_key, load_public_key
from jwt_rsa.verify import main as verify


def test_rsa_keygen(capsys):
    with mock.patch("sys.argv", ["jwt-rsa-keygen"]):
        keygen()

    stdout, stderr = capsys.readouterr()

    data = json.loads(stdout)

    assert "public" in data
    assert "private" in data

    private = load_private_key(data["private"])
    public = load_public_key(data["public"])

    payload = os.urandom(1024 * 16)

    signature = private.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    public.verify(
        signature,
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def test_pem_format(capsys):
    with mock.patch("sys.argv", ["jwt-rsa-keygen", "-P"]):
        keygen()

    stdout, stderr = capsys.readouterr()

    private_bytes, public_bytes = [
        x.strip().encode() for x in stdout.split("\n\n", 1)
    ]

    public = serialization.load_pem_public_key(public_bytes, default_backend())
    private = serialization.load_pem_private_key(
        private_bytes, None, default_backend(),
    )

    payload = os.urandom(1024 * 16)

    signature = private.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    public.verify(
        signature,
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def test_rsa_verify(capsys):
    with mock.patch("sys.argv", ["jwt-rsa-keygen"]):
        keygen()

    stdout, stderr = capsys.readouterr()

    with mock.patch("sys.stdin", StringIO(stdout)):
        verify()


def test_rsa_verify_bad_key():
    private1, public1 = generate_rsa()
    private2, public2 = generate_rsa()

    data = json.dumps(
        {
            "private": base64.b64encode(
                private1.private_bytes(
                    encoding=serialization.Encoding.DER,
                    encryption_algorithm=serialization.NoEncryption(),
                    format=serialization.PrivateFormat.PKCS8,
                ),
            ).decode(),
            "public": base64.b64encode(
                public2.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.PKCS1,
                ),
            ).decode(),
        }, indent="\t",
    )

    with mock.patch("sys.stdin", StringIO(data)):
        with pytest.raises(InvalidSignature):
            verify()
