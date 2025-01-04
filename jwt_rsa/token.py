import time
from datetime import datetime, timedelta
from operator import add, sub
from typing import (
    TYPE_CHECKING, Any, Callable, Dict, Optional, Sequence, TypeVar, Union,
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


class JWT:
    __slots__ = (
        "__private_key", "__public_key", "__jwt",
        "__expires", "__nbf_delta", "__algorithm",
        "__algorithms",
    )

    DEFAULT_EXPIRATION = 31 * DAY  # one month
    NBF_DELTA = 20
    ALGORITHMS = tuple(AlgorithmType.__args__)

    def __init__(
        self,
        private_key: Optional[RSAPrivateKey] = None,
        public_key: Optional[RSAPublicKey] = None,
        expires: Optional[int] = None,
        nbf_delta: Optional[int] = None,
        algorithm: AlgorithmType = "RS512",
        algorithms: Sequence[AlgorithmType] = ALGORITHMS,
        options: Optional[Dict[str, Any]] = None,
    ):

        self.__public_key: RSAPublicKey
        self.__private_key: Optional[RSAPrivateKey] = private_key

        if public_key is None:
            if isinstance(self.__private_key, RSAPrivateKey):
                self.__public_key = self.__private_key.public_key()
            else:
                raise ValueError("You must provide either a public or private key")
        else:
            self.__public_key = public_key

        self.__jwt = PyJWT(options)
        self.__expires = expires or self.DEFAULT_EXPIRATION
        self.__nbf_delta = nbf_delta or self.NBF_DELTA
        self.__algorithm = algorithm
        self.__algorithms = list(algorithms)

    @staticmethod
    def _date_to_timestamp(
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

    def encode(
        self,
        expired: DateType = ...,
        nbf: DateType = ...,
        **claims: Any,
    ) -> str:
        if not self.__private_key:
            raise RuntimeError("Can't encode without private key")

        claims.update(
            dict(
                exp=int(
                    self._date_to_timestamp(
                        expired,
                        lambda: time.time() + self.__expires,
                    ),
                ),
                nbf=int(
                    self._date_to_timestamp(
                        nbf,
                        lambda: time.time() - self.__nbf_delta,
                        timedelta_func=sub,
                    ),
                ),
            ),
        )

        return self.__jwt.encode(
            claims,
            self.__private_key,
            algorithm=self.__algorithm,
        )

    def decode(
        self, token: str, verify: bool = True, **kwargs: Any,
    ) -> Dict[str, Any]:
        return self.__jwt.decode(
            token,
            key=self.__public_key,
            verify=verify,
            algorithms=self.__algorithms,
            **kwargs,
        )
