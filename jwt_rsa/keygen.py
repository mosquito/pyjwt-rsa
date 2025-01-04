import sys
from pathlib import Path
from types import SimpleNamespace

from .convert import convert
from .rsa import generate_rsa


def main(arguments: SimpleNamespace) -> None:
    key_pair = generate_rsa(arguments.bits)

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
        key_pair.private,
        key_pair.public,
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
