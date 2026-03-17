# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

pyjwt-rsa — Python library and CLI for JWT token management with RSA cryptography. Built on `pyjwt` and `cryptography`.

## Commands

```bash
# Install dependencies
poetry install

# Run all tests (includes coverage + pylama linting)
poetry run pytest

# Run tests without coverage
poetry run pytest --no-cov

# Run a single test file or test
poetry run pytest tests/test_rsa.py
poetry run pytest tests/test_rsa.py::test_jwt_token

# Type checking (strict mode)
poetry run mypy jwt_rsa

# Linting
poetry run pylama jwt_rsa tests

# Build
poetry build
```

## Architecture

- **`jwt_rsa/rsa.py`** — Core RSA key operations: generation, format conversion (PEM/JWK/base64), loading keys from various sources. Uses `NamedTuple` for key pairs, `TypedDict` for JWK structures, `@overload` for polymorphic `rsa_to_jwk` and `load_*` functions.
- **`jwt_rsa/token.py`** — JWT encoding/decoding. `JWT()` factory returns `JWTSigner` (private key) or `JWTDecoder` (public key). Both are frozen dataclasses.
- **`jwt_rsa/jwks.py`** — JWKS support. `JWKFetcher` (ABC) with `HTTPSJWKFetcher` implementation. Uses LRU-cached decoders by `kid`.
- **`jwt_rsa/cli.py`** — Argparse dispatcher routing to handler modules (`keygen`, `issue`, `verify`, `convert`, `pubkey`, `key_tester`).
- **Handler modules** (`keygen.py`, `issue.py`, `verify.py`, `convert.py`, `pubkey.py`, `key_tester.py`) — Thin CLI handlers, each exposing `parser()` and `main(args)`.

## Code Quality

- **mypy strict** — all public functions must have full type annotations. Tests have `ignore_errors = true`.
- **pylama** — pycodestyle + pyflakes + mccabe. Max line length 119. Ignored: E704.
- **pytest** — `addopts` integrates coverage, doctests, and pylama in a single run.
- Python 3.10+ required. CI tests on 3.10–3.13.
