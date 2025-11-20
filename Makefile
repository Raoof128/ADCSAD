.PHONY: format lint test ci

format:
	black .

lint:
	ruff check .
	ruff format --check . || true

ci: lint test

test:
	pytest
