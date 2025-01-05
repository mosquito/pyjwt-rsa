from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKeyWithSerialization as RSAPrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicKeyWithSerialization as RSAPublicKey,
)


AlgorithmType = Literal["RS256", "RS384", "RS512"]


__all__ = (
    "AlgorithmType",
    "RSAPrivateKey",
    "RSAPublicKey",
    "serialization",
    "rsa",
)
