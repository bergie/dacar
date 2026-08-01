# Dacar — install dependencies and run tests across implementations.
#
# Each implementation gets its own install-<lang> / test-<lang> / clean-<lang>
# targets and is wired into the matching aggregator below. To add a language,
# copy a <lang> stanza and append its targets to the install / test / clean
# dependency lists.
#
#   make                 show this help
#   make install         install dependencies for every implementation
#   make test            run tests for every implementation
#   make clean           remove build/test artifacts
#   make test-python     run a single implementation's tests

PYTHON ?= python3

.PHONY: help install test clean
.PHONY: install-python test-python clean-python
.DEFAULT_GOAL := help

help: ## Show this help
	@echo "Dacar runner"
	@echo
	@echo "Targets:"
	@echo "  install   install dependencies for every implementation"
	@echo "  test      run tests for every implementation"
	@echo "  clean     remove build/test artifacts"
	@echo
	@echo "  install-python   $(PYTHON) -m pip install -e ."
	@echo "  test-python      $(PYTHON) -m unittest discover -s tests"

# --- aggregators (append new -<lang> targets here) -------------------------
install: install-python
test: test-python
clean: clean-python

# --- python ----------------------------------------------------------------
install-python: ## Install Python dependencies
	cd python && $(PYTHON) -m pip install -e .

test-python: ## Run Python tests
	cd python && $(PYTHON) -m unittest discover -s tests

clean-python: ## Remove Python build/test artifacts
	cd python && rm -rf build dist *.egg-info .pytest_cache
	find python -type d -name __pycache__ -prune -exec rm -rf {} +

# --- javascript ------------------------------------------------------------
# install-js:
# 	cd javascript && npm install
# test-js:
# 	cd javascript && npm test
# clean-js:
# 	cd javascript && rm -rf node_modules
