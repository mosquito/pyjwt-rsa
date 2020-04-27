import argparse
import json

from .rsa import load_private_key
from .token import JWT


parser = argparse.ArgumentParser()
parser.add_argument(
    "-K", "--private-key", required=True,
    help="Private JWT key", type=load_private_key,
)
parser.add_argument(
    "--expired", help="Token expiration",
    type=float, default=...,
)
parser.add_argument(
    "--nbf", help="Token nbf claim",
    type=float, default=...,
)


def main() -> None:
    arguments = parser.parse_args()
    jwt = JWT(private_key=arguments.private_key)
    print(
        jwt.encode(
            expired=arguments.expired,
            nbf=arguments.nbf,
            **json.loads(input("Paste JSON content here: ")),
        ),
    )


if __name__ == "__main__":
    main()
