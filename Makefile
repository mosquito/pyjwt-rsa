.PHONY: test tests mypy pytest lint format

format:
	uv run --group dev ruff check --fix jwt_rsa tests
	uv run --group dev ruff format jwt_rsa tests

lint:
	uv run --group dev ruff check jwt_rsa tests
	uv run --group dev ruff format --check jwt_rsa tests

mypy:
	uv run --group dev mypy jwt_rsa

pytest:
	uv run --group dev pytest

test: lint mypy pytest
tests: test
