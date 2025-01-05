import base64
import json
from pathlib import Path
from typing import NamedTuple, Optional, TypedDict, Union, overload

from cryptography.hazmat.backends import default_backend

from .types import (
    AlgorithmType, RSAPrivateKey, RSAPublicKey, rsa, serialization,
)


class KeyPair(NamedTuple):
    private: Optional[RSAPrivateKey]
    public: RSAPublicKey


class RSAJWKPublicKey(TypedDict):
    kty: str
    e: str
    n: str
    kid: str
    alg: str
    use: str


class RSAJWKPrivateKey(RSAJWKPublicKey):
    d: str
    p: str
    q: str
    dp: str
    dq: str
    qi: str


def generate_rsa(bits: int = 2048) -> KeyPair:
    """
    Generate an RSA keypair with an exponent of 65537 in PEM format
    param: bits The key length in bits
    Return private key and public key
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    public_key = private_key.public_key()
    return KeyPair(private=private_key, public=public_key)


def base64url_decode(data: str) -> bytes:
    rem = len(data) % 4
    if rem > 0:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data)


def load_jwk_public_key(jwk: RSAJWKPublicKey) -> RSAPublicKey:
    if jwk["kty"] != "RSA":
        raise ValueError("Not an RSA key")

    e = int.from_bytes(base64url_decode(jwk["e"]), "big")
    n = int.from_bytes(base64url_decode(jwk["n"]), "big")

    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())


def load_jwk_private_key(jwk: RSAJWKPrivateKey) -> RSAPrivateKey:
    if jwk["kty"] != "RSA":
        raise ValueError("Not an RSA key")

    e = int.from_bytes(base64url_decode(jwk["e"]), "big")
    n = int.from_bytes(base64url_decode(jwk["n"]), "big")
    d = int.from_bytes(base64url_decode(jwk["d"]), "big")
    p = int.from_bytes(base64url_decode(jwk["p"]), "big")
    q = int.from_bytes(base64url_decode(jwk["q"]), "big")
    dp = int.from_bytes(base64url_decode(jwk["dp"]), "big")
    dq = int.from_bytes(base64url_decode(jwk["dq"]), "big")
    qi = int.from_bytes(base64url_decode(jwk["qi"]), "big")

    public_numbers = rsa.RSAPublicNumbers(e, n)
    private_numbers = rsa.RSAPrivateNumbers(p, q, d, dp, dq, qi, public_numbers)

    return private_numbers.private_key(default_backend())


def load_jwk(jwk: Union[RSAJWKPublicKey, RSAJWKPrivateKey, str]) -> KeyPair:
    jwk_dict: Union[RSAJWKPublicKey, RSAJWKPrivateKey]

    if isinstance(jwk, str):
        jwk_dict = json.loads(jwk)
    else:
        jwk_dict = jwk

    if "d" in jwk_dict:  # Private key
        private_key = load_jwk_private_key(jwk_dict)    # type: ignore
        public_key = private_key.public_key()
    else:  # Public key
        public_key = load_jwk_public_key(jwk_dict)   # type: ignore
        private_key = None

    return KeyPair(private=private_key, public=public_key)


def int_to_base64url(value: int) -> str:
    return base64.urlsafe_b64encode(
        value.to_bytes((value.bit_length() + 7) // 8, byteorder="big"),
    ).rstrip(b"=").decode("ascii")


@overload
def rsa_to_jwk(
    key: RSAPublicKey, *, kid: str = "", alg: AlgorithmType = "RS256", use: str = "sig"
) -> RSAJWKPublicKey: ...


@overload
def rsa_to_jwk(    # type: ignore[overload-cannot-match]
    key: RSAPrivateKey, *, kid: str = "", alg: AlgorithmType = "RS256", use: str = "sig",
) -> RSAJWKPrivateKey: ...


def rsa_to_jwk(
    key: Union[RSAPrivateKey, RSAPublicKey],
    *,
    kid: str = "",
    alg: AlgorithmType = "RS256",
    use: str = "sig",
    kty: str = "RSA",
) -> Union[RSAJWKPublicKey, RSAJWKPrivateKey]:
    if isinstance(key, RSAPublicKey):
        public_numbers = key.public_numbers()
        private_numbers = None
    elif isinstance(key, RSAPrivateKey):
        public_numbers = key.public_key().public_numbers()
        private_numbers = key.private_numbers()
    else:
        raise ValueError("Invalid key type: {}".format(type(key)))

    result = RSAJWKPublicKey(
        kty=kty,
        kid=kid,
        alg=alg,
        use=use,
        n=int_to_base64url(public_numbers.n),
        e=int_to_base64url(public_numbers.e),
    )

    if private_numbers is None:
        return result

    return RSAJWKPrivateKey(
        kty=kty,
        kid=kid,
        alg=alg,
        use=use,
        n=int_to_base64url(public_numbers.n),
        e=int_to_base64url(public_numbers.e),
        d=int_to_base64url(private_numbers.d),
        p=int_to_base64url(private_numbers.p),
        q=int_to_base64url(private_numbers.q),
        dp=int_to_base64url(private_numbers.dmp1),
        dq=int_to_base64url(private_numbers.dmq1),
        qi=int_to_base64url(private_numbers.iqmp),
    )


def load_private_key(data: Union[str, RSAJWKPrivateKey, Path]) -> RSAPrivateKey:
    if isinstance(data, Path):
        data = data.read_text()
    if isinstance(data, str):
        if data.startswith("-----BEGIN "):
            return serialization.load_pem_private_key(data.encode(), None, default_backend())
        if data.strip().startswith("{"):
            return load_jwk_private_key(json.loads(data))
    if isinstance(data, dict):
        return load_jwk_private_key(json.loads(json.dumps(data)))
    key = serialization.load_der_private_key(base64.b64decode(data), None, default_backend())
    if not isinstance(key, RSAPrivateKey):
        raise ValueError("Key {!r} is not an RSA key".format(key))
    return key


def load_public_key(data: Union[str, RSAJWKPublicKey, Path]) -> RSAPublicKey:
    if isinstance(data, Path):
        data = data.read_text()
    if isinstance(data, str):
        if data.startswith("-----BEGIN "):
            return serialization.load_pem_public_key(data.encode(), default_backend())
        if data.strip().startswith("{"):
            return load_jwk_public_key(json.loads(data))
    if isinstance(data, dict):
        return load_jwk_public_key(json.loads(json.dumps(data)))
    key = serialization.load_der_public_key(base64.b64decode(data), default_backend())
    if not isinstance(key, RSAPublicKey):
        raise ValueError("Key {!r} is not an RSA key".format(key))
    return key


__all__ = (
    "RSAJWKPrivateKey",
    "RSAJWKPublicKey",
    "KeyPair",
    "base64url_decode",
    "generate_rsa",
    "int_to_base64url",
    "load_jwk",
    "load_jwk_private_key",
    "load_jwk_public_key",
    "load_private_key",
    "load_public_key",
    "rsa_to_jwk",
)
