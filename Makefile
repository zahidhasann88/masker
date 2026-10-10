# Masker development tasks.
#
#   make help      list targets
#   make check     everything CI runs

PYTHON ?= .venv/bin/python
PIP    ?= $(PYTHON) -m pip
PYTEST ?= $(PYTHON) -m pytest
RUFF   ?= $(PYTHON) -m ruff
MYPY   ?= $(PYTHON) -m mypy

.DEFAULT_GOAL := help

.PHONY: help install install-all venv lint format typecheck test test-cov check \
        demo bench build clean distclean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

venv: ## Create .venv
	python3 -m venv .venv
	@echo "created .venv -- run: source .venv/bin/activate"

install: ## Install the package with dev extras (editable)
	$(PIP) install -e '.[dev]'

install-all: ## Install with dev, postgres and mysql extras
	$(PIP) install -e '.[dev,postgres,mysql]'

lint: ## ruff check
	$(RUFF) check src tests scripts

format: ## ruff format
	$(RUFF) format src tests scripts
	$(RUFF) check --fix src tests scripts

typecheck: ## mypy --strict on src/
	$(MYPY)

test: ## pytest
	$(PYTEST)

test-cov: ## pytest with coverage
	$(PYTEST) --cov=masker --cov-report=term-missing

check: lint typecheck test-cov ## lint + typecheck + tests with coverage

demo: ## Run the end-to-end SQLite demo
	bash examples/demo.sh

bench: ## Mask 100k rows per table and print the timings
	$(PYTHON) scripts/bench_sqlite.py

perf: ## Run the opt-in performance test
	MASKER_RUN_PERF=1 $(PYTEST) -m perf -q

build: ## Build the sdist and wheel
	$(PYTHON) -m build

clean: ## Remove caches and build artefacts
	rm -rf .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov dist build
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '*.py[co]' -delete

distclean: clean ## Also remove .venv
	rm -rf .venv
