# Everything a contributor needs, without reading the CI files.
.PHONY: help install check offline lint test serve-dev image clean

PY ?= .venv/bin/python
BIN ?= .venv/bin

help:
	@echo "make install    venv with the hashed lock, the package and dev tools"
	@echo "make check      catalogue doctor, lint and the offline test suite"
	@echo "make offline    the test suite in replay mode: no network, no secrets"
	@echo "make lint       ruff"
	@echo "make serve-dev  core against ./data with nothing sent (dry run)"
	@echo "make image      build the container image locally"

install:
	python3 -m venv .venv
	$(BIN)/pip install --require-hashes --no-deps -r requirements.lock
	$(BIN)/pip install --no-deps -e .
	$(BIN)/pip install "pytest==8.4.2" "pytest-asyncio==1.2.0" "ruff==0.14.4"

check:
	$(BIN)/tgx-monitor doctor
	$(BIN)/ruff check src tests scripts
	$(BIN)/pytest -q

lint:
	$(BIN)/ruff check src tests scripts

test:
	$(BIN)/pytest -q

# The important target. If this passes, no check depends on the network to be tested,
# and the project can be handed over or forked without anyone's credentials.
offline:
	TGXMON_HTTP_MODE=replay TGXMON_SECRETS_DIR=/nonexistent $(BIN)/pytest -q
	@echo "\n  tested offline, with no network and no secrets"

# Local core: own database and snapshot under ./data, secrets from ./secrets if present,
# never sends anything. The private UI is on http://127.0.0.1:8000.
serve-dev:
	mkdir -p data/public data/hb
	TGXMON_DRY_RUN=1 TGXMON_DB=data/monitor.db TGXMON_PUBLIC_DIR=data/public \
	TGXMON_HB_DIR=data/hb TGXMON_SECRETS_DIR=secrets TGXMON_CATALOGUE=catalogue \
	$(BIN)/tgx-monitor run

image:
	docker build -t tgx-monitor:dev .

clean:
	rm -rf build dist src/*.egg-info .pytest_cache .ruff_cache
