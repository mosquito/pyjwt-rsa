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


Command line utilities
----------------------

Module provides following utilities

jwt-rsa-keygen
++++++++++++++

Creates a new key pair:

.. code-block::

   $ jwt-rsa-keygen -h                                                                                                                                                                                              ±8 ?3 master
   usage: jwt-rsa-keygen [-h] [-b BITS] [-P]

   optional arguments:
     -h, --help            show this help message and exit
     -b BITS, --bits BITS
     -P, --pem


By default this utility return JSON-serialized key pair:

.. code-block::

   $ jwt-rsa-keygen                                                                                                                                                                                                 ±8 ?3 master
   {
      "private": "MIIEvgIBADANBg......h3MBsSzx",
      "public": "MIIBCgKCAQEAxUU......5niBEjAB"
   }

Add parameter `-P` for return in PEM format:

.. code-block::

   $ jwt-rsa-keygen -P                                                                                                                                                                                              ±8 ?3 master
   -----BEGIN PRIVATE KEY-----
   MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDDeiI5V/O/Mbff
   ...
   LGQgWf5ch0t1+Rh3tjIuuSc=
   -----END PRIVATE KEY-----

   -----BEGIN RSA PUBLIC KEY-----
   MIIBCgKCAQEAw3oiOVfzvzG331nAL5hGHbblcCaV3pbfoCiFRgwpNPf7snIJtw97
   ...
   3k2mMT1z6NFO6e6LMxg2zrqs3zgqwx5/9wIDAQAB
   -----END RSA PUBLIC KEY-----


jwt-rsa-verify
++++++++++++++

Verify JSON serialized key pair:

.. code-block::

   $ jwt-rsa-keygen | jwt-rsa-verify                                                                                                                                                                                ±8 ?3 master
   INFO:root:Awaiting JSON on stdin...
   INFO:root:Signing OK
   INFO:root:Verifying OK

Or failed when key pair is invalid or doesn't match:

.. code-block::

   $ jwt-rsa-keygen | sed 's/M/j/' | jwt-rsa-verify                                                                                                                                                                 ±8 ?3 master
   INFO:root:Awaiting JSON on stdin...
   Traceback (most recent call last):
     ...
   ValueError: Could not deserialize key data.
