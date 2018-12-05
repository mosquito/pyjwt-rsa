import time
from datetime import timedelta, datetime
from operator import sub, add
from typing import Union

from jwt import PyJWT
from jwt_rsa.rsa import RSAPrivateKey, RSAPublicKey


DateType = Union[timedelta, datetime, float, int, type(Ellipsis)]


class JWT:
    __slots__ = ('__private_key', '__public_key', '__jwt',
                 '__expires', '__nbf_delta', '__algorithm')

    DEFAULT_EXPIRATION = 86400 * 30  # one month
    NBF_DELTA = 20
    ALGORITHMS = tuple({
        'RS256', 'RS384', 'RS512', 'ES256', 'ES384',
        'ES521', 'ES512', 'PS256', 'PS384', 'PS512'
    })

    def __init__(self, private_key: RSAPrivateKey=None,
                 public_key: RSAPublicKey=None, expires=None,
                 nbf_delta=None, algorithm="RS512"):

        self.__private_key = private_key
        self.__public_key = public_key
        self.__jwt = PyJWT(algorithms=self.ALGORITHMS)
        self.__expires = expires or self.DEFAULT_EXPIRATION
        self.__nbf_delta = nbf_delta or self.NBF_DELTA
        self.__algorithm = algorithm

    def _date_to_timestamp(self, value, default, timedelta_func=add):
        if isinstance(value, timedelta):
            return timedelta_func(time.time(), value.total_seconds())
        elif isinstance(value, datetime):
            return value.timestamp()
        elif isinstance(value, (int, float)):
            return value
        elif value is Ellipsis:
            return default()

        raise ValueError(type(value))

    def encode(self, expired: DateType=..., nbf: DateType=..., **claims) -> str:
        if not self.__private_key:
            raise RuntimeError("Can't encode without private key")

        claims.update(
            dict(
                exp=int(
                    self._date_to_timestamp(
                        expired,
                        lambda: time.time() + self.__expires
                    )
                ),
                nbf=int(
                    self._date_to_timestamp(
                        nbf,
                        lambda: time.time() - self.__nbf_delta,
                        timedelta_func=sub
                    )
                ),
            )
        )

        return self.__jwt.encode(
            claims,
            self.__private_key,
            algorithm=self.__algorithm,
        ).decode()

    def decode(self, token: str, verify=True, **kwargs) -> dict:
        if not self.__public_key:
            raise RuntimeError("Can't decode without public key")

        return self.__jwt.decode(
            token,
            key=self.__public_key,
            verify=verify,
            algorithms=self.ALGORITHMS,
            **kwargs
        )


if __name__ == '__main__':
    from jwt_rsa.rsa import generate_rsa

    key, public = generate_rsa(2048)

    jwt = JWT(key, public)

    token = jwt.encode()

    print('Token', token)
    print('Content', jwt.decode(token))
