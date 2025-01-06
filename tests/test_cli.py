import io
import json
import os

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from jwt_rsa.cli import parser
from jwt_rsa.key_tester import main as verify
from jwt_rsa.keygen import main as keygen
from jwt_rsa.rsa import load_private_key, load_public_key


def test_rsa_keygen(capsys):
    keygen(parser.parse_args(["keygen", "--raw", "-o", "jwk"]))

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
    keygen(parser.parse_args(["keygen", "-o", "pem"]))

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


@pytest.mark.parametrize("fmt", ["jwk", "pem", "base64"])
def test_rsa_verify(fmt, capsys, tmp_path):
    private_path = tmp_path / "private"
    public_path = tmp_path / "public"

    keygen(parser.parse_args(["keygen", "-o", fmt, "-K", str(private_path), "-k", str(public_path)]))
    verify(parser.parse_args(["testkey", "-K", str(private_path), "-k", str(public_path)]))
    stdout, stderr = capsys.readouterr()
    assert "Signing OK" in stderr
    assert "Verifying OK" in stderr


@pytest.mark.parametrize("fmt", ["jwk", "pem", "base64"])
def test_rsa_verify_bad_key(fmt, capsys, tmp_path):
    keys = (
        (tmp_path / "private1", tmp_path / "public1"),
        (tmp_path / "private2", tmp_path / "public2"),
    )

    for private_path, public_path in keys:
        keygen(parser.parse_args(["keygen", "-o", fmt, "-K", str(private_path), "-k", str(public_path)]))

    with pytest.raises(InvalidSignature):
        verify(parser.parse_args(["testkey", "-K", str(keys[0][0]), "-k", str(keys[1][1])]))
