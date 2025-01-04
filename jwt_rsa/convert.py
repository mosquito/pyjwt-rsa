import base64
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Literal

from .rsa import load_private_key, rsa_to_jwk
from .types import AlgorithmType, RSAPrivateKey, RSAPublicKey, serialization


def generate_kid(key: RSAPrivateKey) -> str:
    public_numbers = key.public_key().public_numbers()
    modulus_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder="big")
    hash_object = hashlib.sha256(modulus_bytes)
    kid = base64.urlsafe_b64encode(hash_object.digest()).decode("utf-8").rstrip("=")
    return kid[:16]


def convert(
    private: RSAPrivateKey, public: RSAPublicKey,
    fmt: Literal["pem", "jwk", "base64"],
    pretty: bool = False, algorithm: AlgorithmType = "RS512",
) -> tuple[str, str]:
    if fmt == "pem":
        return (
            public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.PKCS1,
            ).decode(),
            private.private_bytes(
                encoding=serialization.Encoding.PEM,
                encryption_algorithm=serialization.NoEncryption(),
                format=serialization.PrivateFormat.PKCS8,
            ).decode(),
        )

    elif fmt == "jwk":
        kid = generate_kid(private)
        public_jwk = rsa_to_jwk(public, kid=kid, alg=algorithm)
        private_jwk = rsa_to_jwk(private, kid=kid, alg=algorithm)

        return (
            json.dumps(public_jwk, sort_keys=True, indent=" " if pretty else None),
            json.dumps(private_jwk, sort_keys=True, indent=" " if pretty else None),
        )
    elif fmt == "base64":
        return (
            base64.b64encode(
                public.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.PKCS1,
                ),
            ).decode(),
            base64.b64encode(
                private.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ),
            ).decode(),
        )
    raise NotImplementedError("Unknown format", format)


def main(arguments: SimpleNamespace) -> None:
    private = load_private_key(arguments.private_key)
    public = private.public_key()

    if not arguments.force:
        if arguments.save_public and arguments.save_public.exists():
            print("Public key file already exists, use --force to overwrite. Not saving.", file=sys.stderr)
            arguments.save_public = None

        if arguments.save_private and arguments.save_private.exists():
            print("Private key file already exists, use --force to overwrite. Not saving.", file=sys.stderr)
            arguments.save_private = None

    if isinstance(arguments.save_private, Path) and not arguments.save_public:
        save_public = arguments.save_private.with_name(arguments.save_private.stem + ".pub")
        if arguments.force or not save_public.exists():
            arguments.save_public = save_public
            print("Public key file not specified, saving public key to", save_public, file=sys.stderr)

    public_data, private_data = convert(
        private,
        public,
        arguments.format,
        arguments.pretty,
    )

    if arguments.save_public:
        print("Saving public key to", arguments.save_public, "in PEM format", file=sys.stderr)
        with open(arguments.save_public, "w") as fp:
            fp.write(public_data)
    else:
        print("Public key in", arguments.format, "format:", file=sys.stderr)
        print(public_data)

    if arguments.save_private:
        print("Saving private key to", arguments.save_private, "in PEM format", file=sys.stderr)
        with open(arguments.save_private, "w") as fp:
            fp.write(private_data)
    else:
        print("Private key in", arguments.format, "format:", file=sys.stderr)
        print(private_data)
