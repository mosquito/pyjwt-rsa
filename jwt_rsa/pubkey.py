import logging
from types import SimpleNamespace

from .convert import convert
from .rsa import load_private_key


def main(arguments: SimpleNamespace) -> None:
    logging.basicConfig(level=logging.INFO)

    private_key = load_private_key(arguments.private_key)
    public_key = private_key.public_key()

    public_data, _ = convert(
        private_key,
        public_key,
        arguments.format,
        pretty=arguments.pretty,
    )

    print(public_data)
