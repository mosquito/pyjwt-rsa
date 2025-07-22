import argparse
import http.client
import json
import logging
import ssl
from abc import ABC, abstractmethod
from contextlib import closing
from functools import lru_cache
from typing import TypedDict, Any
from urllib.parse import urlparse

from jwt.api_jws import PyJWS

from . import JWTDecoder
from .rsa import RSAJWKPublicKey, load_jwk_public_key
from .types import RSAPublicKey

log = logging.getLogger(__name__)


class JWKsStructure(TypedDict, total=True):
    keys: list[RSAJWKPublicKey]


class JWKFetcher(ABC):
    keys: dict[str, RSAPublicKey]
    ca: dict[str, RSAPublicKey]

    def __init__(self, url: str, **kwargs: Any) -> None:
        self.url = url
        self.keys = {}
        self.ca = {}
        self.jws = PyJWS(**kwargs)

    def load_key(self, key: RSAJWKPublicKey) -> RSAPublicKey | None:
        return load_jwk_public_key(key)

    def parse_jwk(self, jwk: dict[str, Any]) -> dict[str, RSAPublicKey]:
        keys = {}
        for key in jwk["keys"]:
            jwk = RSAJWKPublicKey(**key)  # type: ignore
            loaded_key = self.load_key(key)
            if loaded_key is None:
                log.warning("Skipping JWK key: %s", key)
                continue
            keys[jwk['kid']] = loaded_key
        return keys

    @abstractmethod
    def refresh(self) -> Any:
        raise NotImplementedError()

    @lru_cache(1024)
    def decoder(self, kid: str) -> JWTDecoder:
        if kid not in self.keys:
            raise ValueError(f"Key with kid '{kid}' is unknown")
        return JWTDecoder(key=self.keys[kid])

    def decode(self, token: str) -> dict[str, Any]:
        header = self.jws.get_unverified_header(token)
        if 'kid' not in header:
            raise ValueError("Token does not contain 'kid' header")

        decoder = self.decoder(header['kid'])
        return decoder.decode(token)


class HTTPSJWKFetcher(JWKFetcher):
    CLIENT_CLASS = http.client.HTTPSConnection

    def __init__(self, url: str, *, ssl_context: ssl.SSLContext | None = None, **kwargs: Any) -> None:
        super().__init__(url, **kwargs)
        self.ssl_context = ssl_context or ssl.create_default_context()

    def refresh(self) -> None:
        url_parts = urlparse(self.url)
        host, port = (
            url_parts.netloc.split(":")
            if ":" in url_parts.netloc
            else (url_parts.netloc, 443)
        )
        with closing(self.CLIENT_CLASS(host, int(port), context=self.ssl_context)) as client:
            client.request("GET", url_parts.path)
            response = client.getresponse()
            if response.status != 200:
                raise ValueError(f"Failed to fetch JWKs: {response.status} {response.reason}")
            self.keys = self.parse_jwk(json.load(response))
            # Clear the cache for the decoder to ensure it uses the latest keys
            self.decoder.cache_clear()


def main(args: argparse.Namespace) -> None:
    from .rsa import rsa_to_jwk
    fetcher = HTTPSJWKFetcher(args.url)
    fetcher.refresh()

    log.info("JWKs fetched from %r found %s keys", fetcher.url, len(fetcher.keys))

    for kid, key in fetcher.keys.items():
        log.info("Key ID: %s", kid)
        print(json.dumps(rsa_to_jwk(key)))
