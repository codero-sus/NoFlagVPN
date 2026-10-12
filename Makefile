PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: help venv dev test lint fmt typecheck check selftest demo update clean

help:
	@echo "NoFlagVPN make targets"
	@echo "  make venv       create .venv (runtime needs nothing, this is for tooling)"
	@echo "  make dev        install dev/test dependencies into .venv"
	@echo "  make test       run the test suite"
	@echo "  make check      lint + typecheck + test (what CI runs)"
	@echo "  make selftest   end-to-end loopback: server <- client <- origin, asserts no leaks"
	@echo "  make demo       start a local demo server + client against a local origin"
	@echo "  make update     pull the latest code into this checkout (updater.py)"
	@echo "  make clean      remove caches"

venv:
	$(PY) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip

dev: venv
	$(BIN)/pip install -r requirements-dev.txt

test:
	$(BIN)/python -m pytest

lint:
	$(BIN)/ruff check nfvpn tests tools updater.py

fmt:
	$(BIN)/ruff check --fix nfvpn tests tools updater.py
	$(BIN)/ruff format nfvpn tests tools updater.py

typecheck:
	$(BIN)/mypy

check: lint typecheck test

selftest:
	$(BIN)/python -m nfvpn selftest

demo:
	$(BIN)/python -m nfvpn demo

update:
	$(PY) updater.py

update-check:
	$(PY) updater.py --check

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
