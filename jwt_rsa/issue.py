import argparse
import json
import os
import platform
import pwd
import re
import sys
import time
from datetime import datetime
from subprocess import check_call
from tempfile import NamedTemporaryFile
from types import SimpleNamespace

from .rsa import load_private_key
from .token import JWT


TEMPLATE = """# THIS FILE SUPPORTS COMMENTS AND TRAILING COMMAS
# Actually it's a Python dictionary that will be evaluated as a JSON object
# Anyway it supports Python-style single and double quotes, math expressions, etc.

%(preamble)s
{
    # === Standard JWT Claims (As per RFC 7519) ===

    # Issuer of the token
    "iss": "{} <{}@{}>".format(whoami.pw_name, whoami.pw_gecos, HOSTNAME),

    # Subject of the token (usually the user ID)
    "sub": "JohnDoe <johndoe@localhost>",

    # Audience for the token
    "aud": "your-audience",

    # Expiration time (Unix timestamp)
    "exp": timestamp + %(exp)d,

    # Not before time (Unix timestamp)
    # Best practice is to set it to current time minus 1 minute to avoid clock skew
    # "nbf": timestamp + (%(nbf)d),

    # Issued at time (Unix timestamp)
    # "iat": int(time.time()),

    # JWT ID - Unique identifier for the token
    # "jti": "unique-token-id",

    # ===      Custom/User-Defined Claims       ===
    # === Not a part of the standard JWT claims ===

    # Username of the authenticated user
    "username": "johndoe",

    # Roles assigned to the user
    "roles": ["admin", "user"],

    # Optional custom fields (commented out)

    # "email": "johndoe@example.com",
    # "permissions": ["read", "write", "delete"],
    # "profile": {
    #   "firstName": "John",
    #   "lastName": "Doe",
    #   "age": 30
    # },
    # "lastLogin": "2025-01-02T12:34:56Z",
    # "theme": "dark",
    # "locale": "en-US"
}
"""


TIMEINTERVAL_EXP = re.compile(r"^((?P<is_interval>[+-])?(?P<value>[0-9]+)(?P<suffix>[smhdMy]?))+$")
SUFFIXES = {"s": 1, "m": 60, "h": 3600, "d": 86400, "M": 2592000, "y": 31536000}


def parse_interval(value: str) -> int:
    match = TIMEINTERVAL_EXP.match(value)
    if not match:
        raise argparse.ArgumentTypeError(f"Invalid time interval format: {value}")

    groups = match.groupdict()
    if groups["is_interval"] is not None:
        seconds = int(groups["value"])
        if groups["is_interval"] == "-":
            seconds = -seconds
        suffix = SUFFIXES.get(groups["suffix"], 1)
        return int(seconds * suffix)
    elif groups["is_interval"] is None and groups["suffix"]:
        raise argparse.ArgumentTypeError("Invalid time interval format, missing sign: " + value)
    else:
        return int(int(groups["value"]))


def main(arguments: SimpleNamespace) -> None:
    jwt = JWT(
        load_private_key(arguments.private_key),
        expires=arguments.expired,
        nbf_delta=-arguments.nbf,
        algorithm=arguments.algorithm
    )

    whoami = pwd.getpwuid(os.getuid())

    if arguments.interactive:
        globals = {
            "HOUR": 3600,
            "DAY": 86400,
            "YEAR": 365 * 86400,
            "HOSTNAME": platform.node(),
            "datetime": datetime,
            "now": datetime.now(),
            "timestamp": int(time.time()),
            "time": time,
            "int": int,
            "format": format,
            "sum": sum,
            "whoami": whoami,
        }

        preable = "# This modules functions and constants are available:\n\n"
        for key, value in sorted(globals.items(), key=lambda x: x[0]):
            preable += f"#  * {key} = {value!r}\n"

        with NamedTemporaryFile("wt", suffix=".py") as fp:
            if arguments.interactive:
                fp.write(
                    TEMPLATE % {
                        "exp": arguments.expired,
                        "nbf": arguments.nbf,
                        "preamble": preable,
                    },
                )
                fp.flush()

                while True:
                    check_call([arguments.editor, fp.name])

                    try:
                        claims = eval(open(fp.name).read(), globals, {})
                        break
                    except (ValueError, TypeError) as exc:
                        print(f"Error parsing JSON: {exc}", file=sys.stderr)
                        input("Press Enter to try again... Press Ctrl+C to abort")
            else:
                claims = json.load(sys.stdin)
    else:
        claims = json.loads(sys.stdin.read())
    print(jwt.encode(**claims))
