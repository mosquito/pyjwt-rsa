PyJWT RSA Helper
================


Helpers for JWT tokens with RSA.


.. code-block:: python

    >>> from jwt_rsa.token import JWT
    >>> from jwt_rsa.rsa import generate_rsa
    >>>
    >>> bits = 2048
    >>>
    >>> private_key, public_key = generate_rsa(bits)
    >>>
    >>> jwt = JWT(private_key, public_key)
    >>>
    >>> token = jwt.encode(foo='bar')
    >>> result = jwt.decode(token)
    >>> result
    {'foo': 'bar', 'exp': 1525941819.638339, 'nbf': 1523349799.638342}
    >>> # Expired token
    >>> token = jwt.encode(foo='bar', expired=-1)
    >>> jwt.decode(token)
    Traceback (most recent call last):
    ...
    jwt.exceptions.ExpiredSignatureError: Signature has expired
    >>> # No verify token signature and expiration
    >>> jwt.decode(token, verify=False)
    {'foo': 'bar', 'exp': -1, 'nbf': 1523350046.935803}
