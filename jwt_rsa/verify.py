import json
import sys
from types import SimpleNamespace

from .rsa import generate_rsa, load_private_key, load_public_key
from .token import JWT, JWTDecoder, JWTSigner


def main(arguments: SimpleNamespace) -> None:
    jwt: JWTSigner | JWTDecoder
    if arguments.private_key:
        jwt = JWT(load_private_key(arguments.private_key), algorithm=arguments.algorithm)
    elif arguments.public_key:
        jwt = JWT(load_public_key(arguments.public_key), algorithm=arguments.algorithm)
    elif not arguments.verify:
        key_pair = generate_rsa(1024)
        jwt = JWT(key_pair.private, algorithm=arguments.algorithm)
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
