import argparse
import logging
import os
from argparse import ArgumentParser
from pathlib import Path

from jwt_rsa.issue import parse_interval
from . import convert, issue, key_tester, keygen, pubkey, verify, jwks
from .token import ALGORITHMS


class Formatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass


parser = ArgumentParser(formatter_class=Formatter)
parser.add_argument(
    "-a", "--algorithm", choices=ALGORITHMS,
    help="Algorithm for JWT keys", default="RS512"
)
parser.add_argument(
    "--log-level", choices=["debug", "info", "warning", "error", "critical"],
    type=lambda x: getattr(logging, x.upper(), logging.INFO), default=logging.INFO,
)

subparsers = parser.add_subparsers(dest="command", required=True)

keygen_parser = subparsers.add_parser("keygen", help="Generate a new RSA key pair", formatter_class=Formatter)
keygen_parser.set_defaults(func=keygen.main)
keygen_parser.add_argument(
    "-b", "--bits", dest="bits", type=int, default=2048, choices=[2 ** i for i in range(10, 14)],
)
keygen_parser.add_argument(
    "--kid", dest="kid", type=str, default="", help="Key ID, will be generated if missing",
)
keygen_parser.add_argument("-u", "--use", dest="use", type=str, default="sig", choices=["sig", "enc"])
keygen_parser.add_argument("-o", "--format", choices=["pem", "jwk", "base64"], default="jwk")
keygen_parser.add_argument("-r", "--raw", action="store_false", help="Print JSON with indent", dest="pretty")
keygen_parser.add_argument("-k", "--save-public", type=Path)
keygen_parser.add_argument("-K", "--save-private", type=Path)
keygen_parser.add_argument("-f", "--force", action="store_true", help="Overwrite existing keys")

keys_test_parser = subparsers.add_parser("testkey", help="Test a JWT keypair", formatter_class=Formatter)
keys_test_parser.set_defaults(func=key_tester.main)
keys_test_parser.add_argument("-K", "--private-key", type=Path, help="Private key", dest="private", required=True)
keys_test_parser.add_argument("-k", "--public-key", type=Path, help="Public key", dest="public", required=True)

pubkey_parser = subparsers.add_parser("pubkey", help="Extract public key from private key", formatter_class=Formatter)
pubkey_parser.set_defaults(func=pubkey.main)
pubkey_parser.add_argument("-K", "--private-key", type=Path, help="Private key", required=True)
pubkey_parser.add_argument("-o", "--format", choices=["pem", "jwk", "base64"], default="jwk")
pubkey_parser.add_argument("-r", "--raw", action="store_false", help="Print JSON with indent", dest="pretty")

ISSUE_PARSER_DESCRIPTION = (
    "Issue a new JWT token with claims.\n\n"
    "For time intervals you can use the following format:\n"
    "600 and +10m is means 10 minutes, +30d, -1h, +1M, -2w, etc.\n"
    "The time interval can be prefixed with '+' or '-' to indicate future or past time.\n"
    "Values without any prefix and sign are interpreted as count of seconds after current time.\n"
    "You can also use a simple integer value, which will be interpreted as seconds.\n"
    "\nThe following suffixes are supported:\n"
    " * 's' means seconds\n"
    " * 'm' means minutes\n"
    " * 'h' means hours\n"
    " * 'd' means days\n"
    " * 'w' means weeks\n"
    " * 'M' means months\n"
    " * 'y' means years\n"
)
issue_parser = subparsers.add_parser(
    "issue",
    help="Issue a new JWT token\n",
    description=ISSUE_PARSER_DESCRIPTION,
    formatter_class=Formatter
)
issue_parser.add_argument(
    "-K", "--private-key", required=True,
    help="Private JWT key", type=Path,
)
issue_parser.add_argument("--expired", help="Token expiration", type=parse_interval, default="+1M")
issue_parser.add_argument("--nbf", help="Token nbf claim", type=parse_interval, default="-1m")
issue_parser.add_argument(
    "-I", "--no-interactive", action="store_false", dest="interactive",
    help="No interactive mode, do not open editor for claims, just read JSON from stdin",
)
issue_parser.add_argument(
    "-e", "--editor", help="Editor to use in interactive mode",
    default=os.getenv("EDITOR", "vim"),
)
issue_parser.set_defaults(func=issue.main)


verify_parser = subparsers.add_parser("verify", help="Parse and verify JWT token", formatter_class=Formatter)
verify_parser.add_argument("-K", "--private-key", required=False, help="Private key", type=Path)
verify_parser.add_argument("-k", "--public-key", required=False, help="Public key", type=Path)
verify_parser.add_argument("-V", "--no-verify", action="store_false", help="No verify signature", dest="verify")
verify_parser.add_argument(
    "-I", "--no-interactive", action="store_false", dest="interactive",
    help="Interactive mode or raw read token from stdin",
)
verify_parser.set_defaults(func=verify.main)


convert_parser = subparsers.add_parser("convert", help="Convert JWT token", formatter_class=Formatter)
convert_parser.set_defaults(func=convert.main)
convert_parser.add_argument("private_key", help="Private key source", type=Path)
convert_parser.add_argument("-k", "--save-public", type=Path)
convert_parser.add_argument("-K", "--save-private", type=Path)
convert_parser.add_argument("-o", "--format", choices=["pem", "jwk", "base64"], default="jwk")
convert_parser.add_argument("-f", "--force", action="store_true", help="Overwrite existing keys")
convert_parser.add_argument("-r", "--raw", action="store_false", help="Print JSON with indent", dest="pretty")

jwks_parser = subparsers.add_parser("jwks", help="Fetch JWKs from remote hosts", formatter_class=Formatter)
jwks_parser.set_defaults(func=jwks.main)
jwks_parser.add_argument("url", help="URL for JWKs", type=str)


def main() -> None:
    args = parser.parse_args()
    logging.basicConfig(level=args.log_level, format="%(levelname)s: %(message)s")
    args.func(args)


if __name__ == "__main__":
    main()
