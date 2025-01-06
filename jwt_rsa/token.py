import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from operator import add, sub
from typing import (
    TYPE_CHECKING, Any, Callable, Dict, Optional, Sequence, TypeVar, Union, overload,
)

from jwt import PyJWT

from .types import AlgorithmType, RSAPrivateKey, RSAPublicKey


if TYPE_CHECKING:
    # pylama:ignore=E0602
    DateType = Union[timedelta, datetime, float, int, ellipsis]
else:
    DateType = Union[timedelta, datetime, float, int, type(Ellipsis)]


R = TypeVar("R")
DAY = 86400
DEFAULT_EXPIRATION = timedelta(days=31).total_seconds()
NBF_DELTA = 20
ALGORITHMS = tuple(AlgorithmType.__args__)


def date_to_timestamp(
    value: DateType,
    default: Callable[[], R],
    timedelta_func: Callable[[float, float], int] = add,
) -> Union[int, float, R]:
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
    public_key: RSAPublicKey = field(repr=False, compare=False)
    expires: Union[int, float]
    nbf_delta: Union[int, float]
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
        super().__setattr__('public_key', key)
        super().__setattr__('jwt', PyJWT(options))
        super().__setattr__('expires', expires)
        super().__setattr__('nbf_delta', nbf_delta)
        super().__setattr__('algorithm', algorithm)
        super().__setattr__('algorithms', algorithms)

    def decode(self, token: str, verify: bool = True, **kwargs: Any) -> Dict[str, Any]:
        return self.jwt.decode(token, key=self.public_key, verify=verify, algorithms=self.algorithms, **kwargs)


@dataclass(frozen=True, init=False)
class JWTSigner(JWTDecoder):
    private_key: RSAPrivateKey = field(repr=False, compare=False)

    def __init__(self, key: RSAPrivateKey, *, options: Optional[Dict[str, Any]] = None, **kwargs: Any):
        super(JWTDecoder, self).__setattr__('private_key', key)
        super().__init__(key.public_key(), options=options, **kwargs)

    def encode(self, expired: DateType = ..., nbf: DateType = ..., **claims: Any) -> str:
        claims.setdefault('exp', int(date_to_timestamp(expired, lambda: time.time() + self.expires)))
        claims.setdefault('nbf', int(date_to_timestamp(nbf, lambda: time.time() - self.nbf_delta, timedelta_func=sub)))
        return self.jwt.encode(claims, self.private_key, algorithm=self.algorithm)


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
def JWT(    # type: ignore[overload-cannot-match]
    key: RSAPublicKey, *,
    options: dict[str, Any] | None = None,
    expires: int | float = DEFAULT_EXPIRATION,
    nbf_delta: int | float = NBF_DELTA,
    algorithm: AlgorithmType = "RS512",
    algorithms: Sequence[AlgorithmType] = ALGORITHMS,
) -> JWTDecoder: ...


def JWT(
    key: Union[RSAPrivateKey, RSAPublicKey],
    *,
    options: dict[str, Any] | None = None,
    expires: int | float = DEFAULT_EXPIRATION,
    nbf_delta: int | float = NBF_DELTA,
    algorithm: AlgorithmType = "RS512",
    algorithms: Sequence[AlgorithmType] = ALGORITHMS,
) -> Union[JWTSigner, JWTDecoder]:
    kwargs = dict(
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
