import os
import sys
from types import SimpleNamespace

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from .rsa import load_private_key, load_public_key


def main(arguments: SimpleNamespace) -> None:
    public_key = load_public_key(arguments.public)
    private_key = load_private_key(arguments.private)

    payload = os.urandom(1024 * 16)

    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    print("Signing OK", file=sys.stderr)

    public_key.verify(
        signature,
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    print("Verifying OK", file=sys.stderr)
