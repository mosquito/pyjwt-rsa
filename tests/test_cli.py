import io
import json
import os
from io import StringIO
from unittest import mock

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from jwt_rsa.cli import parser
from jwt_rsa.key_tester import main as verify
from jwt_rsa.keygen import main as keygen
from jwt_rsa.rsa import (
    generate_rsa, load_private_key, load_public_key, rsa_to_jwk,
)


def test_rsa_keygen(capsys):
    with mock.patch("sys.argv", ["jwt-rsa", "keygen", "--raw", "-o", "jwk"]):
        keygen(parser.parse_args())

    stdout, stderr = capsys.readouterr()

    with io.StringIO(stdout) as f:
        public_key = json.loads(f.readline())
        private_key = json.loads(f.readline())

    assert private_key
    assert private_key

    private = load_private_key(private_key)
    public = load_public_key(public_key)

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
    with mock.patch("sys.argv", ["jwt-rsa", "keygen", "-o", "pem"]):
        keygen(parser.parse_args())

    stdout, stderr = capsys.readouterr()

    public_bytes, private_bytes = [
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


def test_keygen_no_force(capsys, tmp_path):
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

    keygen(
        parser.parse_args([
            "keygen", "-o", "pem",
            "-K", str(private_path), "-k", str(public_path),
        ])
    )

    assert private_path.exists()
    assert public_path.exists()

    public_content = public_path.read_text()
    private_content = private_path.read_text()

    assert public_content
    assert private_content

    # Try to generate keys again buy don't overwrite existing
    keygen(
        parser.parse_args([
            "keygen", "-o", "pem",
            "-K", str(private_path), "-k", str(public_path),
        ])
    )

    assert public_content == public_path.read_text()
    assert private_content == private_path.read_text()

    keygen(
        parser.parse_args([
            "keygen", "-o", "pem", "-f",
            "-K", str(private_path), "-k", str(public_path),
        ])
    )

    assert public_content != public_path.read_text()
    assert private_content != private_path.read_text()


def test_keygen_public_key_auto_naming(capsys, tmp_path):
    private_path = tmp_path / "key"
    public_path = tmp_path / "key.pub"
    keygen(parser.parse_args(["keygen", "-o", "pem", "-K", str(private_path)]))

    assert private_path.exists()
    assert public_path.exists()

    public_content = public_path.read_text()
    private_content = private_path.read_text()

    assert public_content
    assert private_content

    private_path.unlink()

    keygen(parser.parse_args(["keygen", "-o", "pem", "-K", str(private_path)]))

    assert private_path.exists()
    assert public_path.exists()

    assert public_content == public_path.read_text()
    assert private_content != private_path.read_text()


@pytest.mark.skip(reason="TODO")
def test_rsa_verify(capsys):
    with mock.patch("sys.argv", ["jwt-rsa", "keygen"]):
        keygen(parser.parse_args())

    stdout, stderr = capsys.readouterr()

    with mock.patch("sys.stdin", StringIO(stdout)):
        verify(parser.parse_args())


@pytest.mark.skip(reason="TODO")
def test_rsa_verify_bad_key():
    private1, public1 = generate_rsa()
    private2, public2 = generate_rsa()

    data = json.dumps(
        {
            "private_jwk": rsa_to_jwk(private1),
            "public_jwk": rsa_to_jwk(public2),
        }, indent=" ", sort_keys=True,
    )

    with mock.patch("sys.stdin", StringIO(data)):
        with pytest.raises(InvalidSignature):
            verify(parser.parse_args())
