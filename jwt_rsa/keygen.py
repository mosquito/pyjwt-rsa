import base64
import json
import argparse

from .rsa import generate_rsa
from cryptography.hazmat.primitives import serialization


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--bits', dest="bits", type=int, default=2048)
    parser.add_argument('-P', '--pem', dest="pem", action='store_true')

    arguments = parser.parse_args()

    private_key, public_key = generate_rsa(arguments.bits)

    if arguments.pem:
        print(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            encryption_algorithm=serialization.NoEncryption(),
            format=serialization.PrivateFormat.PKCS8
        ).decode())
        print(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        ).decode())
    else:
        print(
            json.dumps({
                'private': base64.b64encode(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.DER,
                        encryption_algorithm=serialization.NoEncryption(),
                        format=serialization.PrivateFormat.PKCS8
                    )
                ).decode(),
                'public': base64.b64encode(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.PKCS1
                    )
                ).decode()
            }, indent='\t')
        )


if __name__ == '__main__':
    main()
