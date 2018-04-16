import json
import sys
import os
import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from jwt_rsa.rsa import load_private_key, load_public_key


def main():
    logging.basicConfig(level=logging.INFO)

    logging.info("Awaiting JSON on stdin...")
    data = json.load(sys.stdin)

    public_key = load_public_key(data['public'])
    private_key = load_private_key(data['private'])

    payload = os.urandom(1024 * 16)

    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    logging.info("Signing OK")

    result = public_key.verify(
        signature,
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    assert result is None

    logging.info("Verifying OK")


if __name__ == '__main__':
    main()
