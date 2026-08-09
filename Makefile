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

.PHONY: help install test clean release release-dry
.PHONY: install-python test-python clean-python
.PHONY: install-js test-js clean-js
.PHONY: release-python release-python-dry
.PHONY: release-js release-js-dry
.PHONY: release-jsr release-jsr-dry
.DEFAULT_GOAL := help

help: ## Show this help
	@echo "Dacar runner"
	@echo
	@echo "Targets:"
	@echo "  install   install dependencies for every implementation"
	@echo "  test      run tests for every implementation"
	@echo "  clean     remove build/test artifacts"
	@echo
	@echo "  install-python   $(PYTHON) -m pip install -e .[transport]"
	@echo "  test-python      $(PYTHON) -m unittest discover -s tests"
	@echo "  install-js       npm install"
	@echo "  test-js          node/deno/bun (whichever are installed)"
	@echo
	@echo "  release          publish PyPI + npm + JSR"
	@echo "  release-dry      validate all three without uploading"
	@echo "  release-python   twine upload to PyPI  (release-python-dry validates)"
	@echo "  release-js       npm publish          (release-js-dry validates)"
	@echo "  release-jsr      deno publish         (release-jsr-dry validates)"

# --- aggregators (append new -<lang> targets here) -------------------------
install: install-python install-js
test: test-python test-js
clean: clean-python clean-js

# --- python ----------------------------------------------------------------
install-python: ## Install Python dependencies (core + transport extra)
	cd python && $(PYTHON) -m pip install -e ".[transport]"

test-python: ## Run Python tests
	cd python && $(PYTHON) -m unittest discover -s tests

clean-python: ## Remove Python build/test artifacts
	cd python && rm -rf build dist *.egg-info .pytest_cache
	find python -type d -name __pycache__ -prune -exec rm -rf {} +

# --- javascript ------------------------------------------------------------
install-js: ## Install JavaScript dependencies
	cd javascript && npm install

test-js: ## Run JavaScript tests (node, deno, bun — whichever are installed)
	cd javascript && npm test

clean-js: ## Remove JavaScript build/test artifacts
	cd javascript && rm -rf node_modules

# --- release ---------------------------------------------------------------
# Publish per implementation. Each has a -dry twin that validates packaging
# (builds artifacts, runs metadata checks) WITHOUT uploading anything.
#
#   make release             publish PyPI + npm + JSR
#   make release-dry         validate all three without uploading
#
# Toolchain on PATH: python (-m build, twine), npm, deno.
#
# npm: prerelease versions need a dist-tag, so NPM_DIST_TAG defaults to "rc".
#      For a stable release run: make release-js NPM_DIST_TAG=latest
#      Provenance is opt-in via NPM_PUBLISH_FLAGS (used by CI, not local).
#
# PyPI: `release-python` uses twine with local creds (~/.pypirc or TWINE_*).
#       CI instead builds via release-python-dry and uploads through OIDC
#       trusted publishing (pypa/gh-action-pypi-publish, no token).
#
# JSR:  the package is plain JSDoc JS, so --allow-slow-types is always passed.
#       JSR versions are immutable: a published version can never be reused.

NPM_DIST_TAG ?= rc
NPM_PUBLISH_FLAGS ?= --access public
JSR_PUBLISH_FLAGS ?= --allow-slow-types

release: release-python release-js release-jsr
release-dry: release-python-dry release-js-dry release-jsr-dry

release-python: ## Build sdist+wheel and upload to PyPI (twine)
	cd python && rm -rf dist && $(PYTHON) -m build && $(PYTHON) -m twine upload dist/*

release-python-dry: ## Build sdist+wheel and validate metadata (twine check)
	cd python && rm -rf dist && $(PYTHON) -m build && $(PYTHON) -m twine check dist/*

release-js: ## Publish to npm with dist-tag $(NPM_DIST_TAG)
	cd javascript && npm publish $(NPM_PUBLISH_FLAGS) --tag $(NPM_DIST_TAG)

release-js-dry: ## Validate npm packaging without uploading
	cd javascript && npm publish --dry-run --tag $(NPM_DIST_TAG)

release-jsr: ## Publish to JSR
	cd javascript && deno publish $(JSR_PUBLISH_FLAGS)

release-jsr-dry: ## Validate JSR packaging without uploading (--allow-dirty for local WIP)
	cd javascript && deno publish --dry-run $(JSR_PUBLISH_FLAGS) --allow-dirty
