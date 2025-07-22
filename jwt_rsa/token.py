import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from operator import add, sub
from types import EllipsisType
from typing import Any, Callable, Dict, Optional, Sequence, TypeVar, overload

from jwt import PyJWT

from .types import AlgorithmType, DateType, RSAPrivateKey, RSAPublicKey


R = TypeVar("R")
DAY = 86400
DEFAULT_EXPIRATION = timedelta(days=31).total_seconds()
NBF_DELTA = 20
ALGORITHMS: Sequence[AlgorithmType] = ("RS256", "RS384", "RS512")


def date_to_timestamp(
    value: DateType | EllipsisType,
    default: Callable[[], R],
    timedelta_func: Callable[[float, float], int] = add,
) -> int | float | R:
    if isinstance(value, timedelta):
        return timedelta_func(time.time(), value.total_seconds())
    elif isinstance(value, datetime):
        return value.timestamp()
    elif isinstance(value, (int, float)):
        return value
    elif value is Ellipsis:
        return default()

    raise ValueError(type(value))


@dataclass(frozen=True, init=False)
class JWTDecoder:
    jwt: PyJWT = field(repr=False, compare=False)
    public_key: RSAPublicKey = field(repr=False, compare=True)
    expires: int | float
    nbf_delta: int | float
    algorithm: AlgorithmType
    algorithms: Sequence[AlgorithmType]

    def __init__(
        self,
        key: RSAPublicKey,
        *, options: dict[str, Any] | None = None,
        expires: int | float = DEFAULT_EXPIRATION,
        nbf_delta: int | float = NBF_DELTA,
        algorithm: AlgorithmType = "RS512",
        algorithms: Sequence[AlgorithmType] = ALGORITHMS,
    ):
        super().__setattr__("public_key", key)
        super().__setattr__("jwt", PyJWT(options))
        super().__setattr__("expires", expires)
        super().__setattr__("nbf_delta", nbf_delta)
        super().__setattr__("algorithm", algorithm)
        super().__setattr__("algorithms", algorithms)

    def decode(self, token: str, verify: bool = True, **kwargs: Any) -> Dict[str, Any]:
        return self.jwt.decode(token, key=self.public_key, verify=verify, algorithms=self.algorithms, **kwargs)


@dataclass(frozen=True, init=False)
class JWTSigner(JWTDecoder):
    private_key: RSAPrivateKey = field(repr=False, compare=True)

    def __init__(self, key: RSAPrivateKey, *, options: Optional[Dict[str, Any]] = None, **kwargs: Any):
        super(JWTDecoder, self).__setattr__("private_key", key)
        super().__init__(key.public_key(), options=options, **kwargs)

    def encode(
        self,
        expired: DateType | EllipsisType = ...,
        nbf: DateType | EllipsisType = ...,
        headers: Optional[Dict[str, Any]] = None,
        **claims: Any
    ) -> str:
        claims.setdefault("exp", int(date_to_timestamp(expired, lambda: time.time() + self.expires)))
        claims.setdefault("nbf", int(date_to_timestamp(nbf, lambda: time.time() - self.nbf_delta, timedelta_func=sub)))
        return self.jwt.encode(claims, self.private_key, algorithm=self.algorithm, headers=headers)


@overload
def JWT(
    key: RSAPrivateKey, *,
    options: dict[str, Any] | None = None,
    expires: int | float = DEFAULT_EXPIRATION,
    nbf_delta: int | float = NBF_DELTA,
    algorithm: AlgorithmType = "RS512",
    algorithms: Sequence[AlgorithmType] = ALGORITHMS,
) -> JWTSigner: ...


@overload
def JWT(
    key: RSAPublicKey, *,
    options: dict[str, Any] | None = None,
    expires: int | float = DEFAULT_EXPIRATION,
    nbf_delta: int | float = NBF_DELTA,
    algorithm: AlgorithmType = "RS512",
    algorithms: Sequence[AlgorithmType] = ALGORITHMS,
) -> JWTDecoder: ...


def JWT(
    key: RSAPrivateKey | RSAPublicKey,
    *,
    options: dict[str, Any] | None = None,
    expires: int | float = DEFAULT_EXPIRATION,
    nbf_delta: int | float = NBF_DELTA,
    algorithm: AlgorithmType = "RS512",
    algorithms: Sequence[AlgorithmType] = ALGORITHMS,
) -> JWTSigner | JWTDecoder:
    kwargs: dict[str, Any] = dict(
        expires=expires,
        nbf_delta=nbf_delta,
        algorithm=algorithm,
        algorithms=algorithms,
        options=options,
    )

    if isinstance(key, RSAPrivateKey):
        return JWTSigner(key, **kwargs)
    elif isinstance(key, RSAPublicKey):
        return JWTDecoder(key, **kwargs)
    else:
        raise TypeError(f"Invalid key type: {type(key)}")
