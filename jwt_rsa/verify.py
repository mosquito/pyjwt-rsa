import json
import sys
from types import SimpleNamespace

from .rsa import generate_rsa, load_private_key, load_public_key
from .token import JWT


def main(arguments: SimpleNamespace) -> None:
    if arguments.private_key:
        jwt = JWT(private_key=load_private_key(arguments.private_key))
    elif arguments.public_key:
        jwt = JWT(public_key=load_public_key(arguments.public_key))
    elif not arguments.verify:
        jwt = JWT(*generate_rsa(1024))
    else:
        print("Either private or public key must be provided", file=sys.stderr)
        exit(1)

    if arguments.interactive:
        token = input("Enter JWT token: ")
    else:
        token = sys.stdin.read()

    print("\nDecoded token:\n")
    print(
        json.dumps(
            jwt.decode(
                token,
                verify=arguments.verify,
                options=dict(
                    verify_signature=arguments.verify,
                    verify_exp=arguments.verify,
                    verify_nbf=arguments.verify,
                    verify_iat=arguments.verify,
                    verify_aud=False,
                ),
            ),
            indent=1,
            sort_keys=True,
        ),
    )
