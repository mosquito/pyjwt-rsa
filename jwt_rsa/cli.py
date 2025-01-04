import os
from argparse import ArgumentParser
from pathlib import Path

from jwt_rsa.types import AlgorithmType

from . import convert, issue, key_tester, keygen, pubkey, verify


parser = ArgumentParser()

subparsers = parser.add_subparsers(dest="command", required=True)

keygen_parser = subparsers.add_parser("keygen", help="Generate a new RSA key pair")
keygen_parser.set_defaults(func=keygen.main)
keygen_parser.add_argument(
    "-b", "--bits", dest="bits", type=int, default=2048, choices=[2 ** i for i in range(10, 14)],
)
keygen_parser.add_argument(
    "--kid", dest="kid", type=str, default="", help="Key ID, will be generated if missing",
)
keygen_parser.add_argument(
    "-a", "--algorithm", choices=AlgorithmType.__args__,
    help="Key ID, will be generated if missing", default="RS512",
)
keygen_parser.add_argument("-u", "--use", dest="use", type=str, default="sig", choices=["sig", "enc"])
keygen_parser.add_argument("-o", "--format", choices=["pem", "jwk", "base64"], default="jwk")
keygen_parser.add_argument("-r", "--raw", action="store_false", help="Print JSON with indent", dest="pretty")
keygen_parser.add_argument("-k", "--save-public", type=Path)
keygen_parser.add_argument("-K", "--save-private", type=Path)
keygen_parser.add_argument("-f", "--force", action="store_true", help="Overwrite existing keys")

keys_test_parser = subparsers.add_parser("testkey", help="Test a JWT keypair")
keys_test_parser.set_defaults(func=key_tester.main)
keys_test_parser.add_argument("-K", "--private-key", type=Path, help="Private key", dest="private", required=True)
keys_test_parser.add_argument("-k", "--public-key", type=Path, help="Public key", dest="public", required=True)

pubkey_parser = subparsers.add_parser("pubkey", help="Extract public key from private key")
pubkey_parser.set_defaults(func=pubkey.main)
pubkey_parser.add_argument("-K", "--private-key", type=Path, help="Private key", required=True)
pubkey_parser.add_argument("-o", "--format", choices=["pem", "jwk", "base64"], default="jwk")
pubkey_parser.add_argument("-r", "--raw", action="store_false", help="Print JSON with indent", dest="pretty")

issue_parser = subparsers.add_parser("issue", help="Issue a new JWT token")
issue_parser.add_argument(
    "-K", "--private-key", required=True,
    help="Private JWT key", type=Path,
)
issue_parser.add_argument("--expired", help="Token expiration", type=int, default=86400 * 31)
issue_parser.add_argument("--nbf", help="Token nbf claim", type=int, default=-30)
issue_parser.add_argument(
    "-I", "--no-interactive", action="store_false", dest="interactive",
    help="Interactive mode, open editor for claims",
)
issue_parser.add_argument(
    "-e", "--editor", help="Editor to use in interactive mode",
    default=os.getenv("EDITOR", "vim"),
)
issue_parser.set_defaults(func=issue.main)


verify_parser = subparsers.add_parser("verify", help="Parse and verify JWT token")
verify_parser.add_argument("-K", "--private-key", required=False, help="Private key", type=Path)
verify_parser.add_argument("-k", "--public-key", required=False, help="Public key", type=Path)
verify_parser.add_argument("-V", "--no-verify", action="store_false", help="No verify signature", dest="verify")
verify_parser.add_argument(
    "-I", "--no-interactive", action="store_false", dest="interactive",
    help="Interactive mode or raw read token from stdin",
)
verify_parser.set_defaults(func=verify.main)


convert_parser = subparsers.add_parser("convert", help="Convert JWT token")
convert_parser.set_defaults(func=convert.main)
convert_parser.add_argument("private_key", help="Private key source", type=Path)
convert_parser.add_argument("-k", "--save-public", type=Path)
convert_parser.add_argument("-K", "--save-private", type=Path)
convert_parser.add_argument("-o", "--format", choices=["pem", "jwk", "base64"], default="jwk")
convert_parser.add_argument("-f", "--force", action="store_true", help="Overwrite existing keys")
convert_parser.add_argument("-r", "--raw", action="store_false", help="Print JSON with indent", dest="pretty")


def main() -> None:
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
