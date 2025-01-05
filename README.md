PyJWT RSA Helper
================

jwt-rsa is a versatile command-line utility and Python library for managing JSON Web Tokens (JWT) using RSA
cryptography. It enables you to generate RSA key pairs, issue and verify JWTs, convert keys between various formats,
and perform comprehensive key management tasks with ease.

## Installation

Ensure you have Python 3.10 or higher installed. You can install `pyjwt-rsa` using pip:

```
pip install pyjwt-rsa
```

## Python Library

`pyjwt-rsa` can also be used as a Python library for integrating JWT and RSA key management into
your Python applications.

### JWT Class

The `JWT` class provides methods to encode and decode JWT tokens.

#### Importing and Basic Usage

```python
from jwt_rsa import JWT, generate_rsa

# Generate RSA key pair
key_pair = generate_rsa(bits=2048)

# Initialize JWT with private and public keys
jwt = JWT(private_key=key_pair.private, public_key=key_pair.public)

# Encode a JWT token
token = jwt.encode(foo='bar')

# Decode a JWT token
claims = jwt.decode(token)
print(claims)
```

#### Handling Expiration and Not Before Claims

```python
# Encode with custom expiration and nbf
token = jwt.encode(foo='bar', expired=3600, nbf=0)

# Decode without verification
claims = jwt.decode(token, verify=False)
print(claims)
```

#### RSA Key Management

`pyjwt-rsa` provides functions to generate, load, and convert RSA keys.

**Generating RSA Keys:**

```python
from jwt_rsa import generate_rsa

# Generate a 2048-bit RSA key pair
key_pair = generate_rsa(bits=2048)
private_key = key_pair.private
public_key = key_pair.public
```

**Loading RSA Keys:**

```python
from jwt_rsa import load_private_key, load_public_key
from pathlib import Path

# Load private key from a file in one of the supported formats (PEM, JWK, Base64)
private_key = load_private_key(Path('./private.pem'))

# Load public key from a file in one of the supported formats (PEM, JWK, Base64)
public_key = load_public_key(Path('./public.pem'))
```

**Converting RSA Keys to JWK:**

```python
from jwt_rsa import rsa_to_jwk, generate_rsa

private_key, public_key = generate_rsa(bits=2048)

# Convert private key to JWK
private_jwk = rsa_to_jwk(private_key, kid='my-key-id')

# Convert public key to JWK
public_jwk = rsa_to_jwk(public_key, kid='my-key-id')
```

## Command line utility `jwt-rsa`

**jwt-rsa** is a versatile command-line utility for managing JSON Web Tokens (JWT) using RSA cryptography.
It allows you to generate RSA key pairs, issue and verify JWTs, convert keys between formats, and perform
various other key management tasks with ease.

## Features

- **Generate RSA Key Pairs:** Create new RSA public and private keys with customizable parameters.
- **Issue JWTs:** Generate JWT tokens with configurable claims and expiration.
- **Verify JWTs:** Parse and verify the authenticity of JWT tokens.
- **Key Conversion:** Convert keys between PEM, JWK, and Base64 formats.
- **Extract Public Keys:** Derive the public key from a private key.
- **Key Testing:** Validate the integrity of RSA key pairs.

## Installation

Ensure you have Python 3.10 or higher installed. You can install `pyjwt-rsa` using `pip`:

```bash
pip install jwt-rsa
```

## Usage

`jwt-rsa` is operated via the command line with various subcommands to perform different tasks.
Below is an overview of the available commands and their options.

### Commands

#### `keygen`

Generate a new RSA key pair.

**Usage:**

```bash
jwt-rsa keygen [options]
```

**Options:**

- `-b`, `--bits`: Number of bits for the RSA key (default: 2048). Choices: 1024, 2048, 4096, 8192.
- `--kid`: Key ID. If not provided, one will be generated.
- `-a`, `--algorithm`: Algorithm to use (`RS256`, `RS384`, `RS512`). Default: `RS512`.
- `-u`, `--use`: Key usage (`sig` for signature, `enc` for encryption). Default: `sig`.
- `-o`, `--format`: Output format (`pem`, `jwk`, `base64`). Default: `jwk`.
- `-r`, `--raw`: Output raw JSON without indentation.
- `-k`, `--save-public`: Path to save the public key.
- `-K`, `--save-private`: Path to save the private key.
- `-f`, `--force`: Overwrite existing keys if they exist.

**Examples:**

By default `jwt-rsa keygen` generates keys to the standard output.

```bash
$ jwt-rsa keygen -b 1024 -o jwk
Public key in jwk format:
{
 "alg": "RS256",
 "e": "AQAB",
 "kid": "N-ls95OIH-FhdrfM",
 "kty": "RSA",
 "n": "3QHB3jCki6iFYEsYyQ9L9Jmn05bytXYzeaPckyMEdmhti4VPCVI8inec",
 "use": "sig"
}
Private key in jwk format:
{
 "alg": "RS256",
 "d": "...",
 "dp": "...",
 "dq": "...",
 "e": "AQAB",
 "kid": "N-ls95OIH-FhdrfM",
 "kty": "RSA",
 "n": "3QHB3jCki6iFYEsYyQ9L9Jmn05bytXYzeaPckyMEdmhti4VPCVI8inec",
 "p": "...",
 "q": "...",
 "qi": "...",
 "use": "sig"
}
```

If you want to save the keys to files, you can use the `-K`/`--save-private` and `-k`/`--save-public` options:

```bash

Generate a 4096-bit RSA key pair and save them in PEM format:

```bash
$ jwt-rsa keygen -b 4096 -o pem -K /tmp/private.pem -k /tmp/public.pem
Saving public key to /tmp/public.pem in PEM format
Saving private key to /tmp/private.pem in PEM format
```

Generate shorter version. The public key will be saved in a file with the same name as the private key
but with the `.pub` extension:

```bash
$ jwt-rsa keygen -b 4096 -o pem -K /tmp/key
Public key file not specified, saving public key to /tmp/key.pub
Saving public key to /tmp/key.pub in PEM format
Saving private key to /tmp/key in PEM format
```

#### `testkey`

Test the validity of a JWT key pair. Make a round-trip test signing and verifying a random message.

**Usage:**

```bash
jwt-rsa testkey -K PRIVATE_KEY_PATH -k PUBLIC_KEY_PATH
```

**Options:**

- `-K`, `--private-key`: Path to the private key (required).
- `-k`, `--public-key`: Path to the public key (required).

**Examples:**

Ensure that your RSA key pair is valid:

```bash
$ jwt-rsa testkey -K /tmp/key -k /tmp/key.pub
Signing OK
Verifying OK
```


#### `pubkey`

Extract the public key from a private key.

**Usage:**

```bash
jwt-rsa pubkey -K PRIVATE_KEY_PATH [options]
```

**Options:**

- `-K`, `--private-key`: Path to the private key (required).
- `-o`, `--format`: Output format (`pem`, `jwk`, `base64`). Default: `jwk`.
- `-r`, `--raw`: Output raw JSON without indentation.

**Examples:**

Extract the public key from a private key and save it in Base64 format:

```bash
$ jwt-rsa pubkey -K /tmp/key -o base64
MIICCg...EAAQ==
```

#### `issue`

Issue a new JWT token.

**Usage:**

```bash
jwt-rsa issue -K PRIVATE_KEY_PATH [options]
```

**Options:**

- `-K`, `--private-key`: Path to the private JWT key (required).
- `--expired`: Token expiration time in seconds (default: `2678400` seconds, which is 31 days).
- `--nbf`: "Not Before" claim in seconds (default: `-30`).
- `-I`, `--no-interactive`: Disable interactive mode. By default, interactive mode is enabled.
- `-e`, `--editor`: Editor to use in interactive mode. Defaults to the `EDITOR` environment variable or `vim`.

**Examples:**

Issue a JWT token with default expiration and interactive mode:

```bash
jwt-rsa issue -K ./private.pem
```

By default will be opened the default editor to edit the claims, the format is python dictionary, with comments and
pre-filled values:

```python
# This modules functions and constants are available:

#  * DAY = 86400
#  * HOSTNAME = 'NB-J2X12GGXQF'
#  * HOUR = 3600
#  * YEAR = 31536000
#  * datetime = <class 'datetime.datetime'>
#  * format = <built-in function format>
#  * int = <class 'int'>
#  * now = datetime.datetime(2025, 1, 4, 1, 42, 25, 890287)
#  * sum = <built-in function sum>
#  * time = <module 'time' (built-in)>
#  * timestamp = 1735951345
#  * whoami = pwd.struct_passwd(pw_name='example', pw_passwd='********', pw_uid=1000, pw_gid=1000, pw_gecos='Example User')

{
    # === Standard JWT Claims (As per RFC 7519) ===

    # Issuer of the token
    "iss": "{} <{}@{}>".format(whoami.pw_name, whoami.pw_gecos, HOSTNAME),

    # Subject of the token (usually the user ID)
    "sub": "JohnDoe <johndoe@localhost>",

    # Audience for the token
    "aud": "your-audience",

    # Expiration time (Unix timestamp)
    "exp": timestamp + 2678400,

    ...
}
```

After saving and closing the editor, the token will be issued and printed to the stdout.

If you want to disable interactive mode, you can use the `-I`/`--no-interactive` option:

```bash
$ echo '{"foo": "bar"}' | jwt-rsa issue -K /tmp/key -I --expired 3600
eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJleHAiOjE3Mzg2MzAwNDcsIm5iZiI6MTczNTk1MTYyN30.HRCQ
```

In non interactive mode, the input must be a JSON object with the claims to issue the token.

#### `verify`

Parse and verify a JWT token.

**Usage:**

```bash
jwt-rsa verify [options] TOKEN
```

**Options:**

- `-K`, `--private-key`: Path to the private key.
- `-k`, `--public-key`: Path to the public key. If ommited, the public key will be extracted from the private key.
- `-V`, `--no-verify`: Do not verify the token's signature.
- `-I`, `--no-interactive`: Disable interactive mode. By default, interactive mode is enabled.

**Examples:**

Verify a JWT token using the public key:

```bash
$ echo '{"foo": "bar"}' | jwt-rsa issue -K /tmp/key -I --expired 3600 | jwt-rsa verify -k /tmp/key.pub
Enter JWT token:
Decoded token:

{
 "exp": 1738630217,
 "foo": "bar",
 "nbf": 1735951797
}
```

#### `convert`

Convert a JWT token's key format.

**Usage:**

```bash
jwt-rsa convert PRIVATE_KEY_PATH [options]
```

**Options:**

- `private_key`: Path to the source private key (positional argument).
- `-k`, `--save-public`: Path to save the converted public key. If omitted,
  the public key will be saved to the same directory as the private key with a `.pub` extension.
- `-K`, `--save-private`: Path to save the converted private key.
- `-o`, `--format`: Output format (`pem`, `jwk`, `base64`). Default: `jwk`.
- `-f`, `--force`: Overwrite existing keys if they exist.
- `-r`, `--raw`: Output raw JSON without indentation.

**Examples:**

Convert a private key from PEM to JWK format:

```bash
jwt-rsa convert /tmp/key -o jwk -K /tmp/jwk
Public key file not specified, saving public key to /tmp/jwk.pub
Saving public key to /tmp/jwk.pub in PEM format
Saving private key to /tmp/jwk in PEM format
```

Convert a private key from PEM to base64 format and print the output:

```bash
$ jwt-rsa convert /tmp/key -o base64
Public key in base64 format:
MIICCg...EAAQ==
Private key in base64 format:
MIIJQgIBA....DANBgkqhkiG==
```

## License

This project is licensed under the [MIT License](LICENSE).
