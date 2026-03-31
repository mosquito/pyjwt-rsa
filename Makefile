.PHONY: test tests mypy pytest lint

lint:
	uv run --group dev ruff check jwt_rsa tests

mypy:
	uv run --group dev mypy jwt_rsa

pytest:
	uv run --group dev pytest

test: lint mypy pytest
tests: test
