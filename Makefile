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

# Parallel build jobs for the C++ target. A bare `cmake --build -j` means
# UNLIMITED jobs, which OOMs small machines on a clean build (the fetched
# dependency tree is large); default to the core count instead.
J ?= $(shell nproc 2>/dev/null || echo 2)

.PHONY: help install test clean release release-dry
.PHONY: install-python test-python clean-python
.PHONY: install-js test-js clean-js js-types
.PHONY: install-cpp test-cpp clean-cpp
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
	@echo "  install-cpp      cmake configure (fetches native deps)"
	@echo "  test-cpp         cmake build + ctest (native Unity suites)"
	@echo
	@echo "  release          publish PyPI + npm + JSR"
	@echo "  release-dry      validate all three without uploading"
	@echo "  release-python   twine upload to PyPI  (release-python-dry validates)"
	@echo "  release-js       npm publish          (release-js-dry validates)"
	@echo "  release-jsr      deno publish         (release-jsr-dry validates)"

# --- aggregators (append new -<lang> targets here) -------------------------
install: install-python install-js install-cpp
test: test-python test-js test-cpp
clean: clean-python clean-js clean-cpp

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

# --- cpp (C++ port for microReticulum-class MCU nodes) ----------------------
# Native tests run the Unity suites via CMake (dependency fetches happen on
# first configure; a local ../reticulum.js/microReticulum checkout is used
# automatically when present). Embedded builds: cd cpp && pio test -e <env>.

ifneq ($(wildcard ../reticulum.js/microReticulum),)
CMAKE_CONFIGURE_FLAGS += -DDACAR_MICRORETICULUM_SOURCE_DIR=../reticulum.js/microReticulum
endif

install-cpp: ## Configure the C++ native build (fetches dependencies)
	cd cpp && cmake -B build -S . $(CMAKE_CONFIGURE_FLAGS)

test-cpp: ## Build and run the C++ (native) tests
	cd cpp && cmake -B build -S . $(CMAKE_CONFIGURE_FLAGS) \
		&& cmake --build build -j$(J) \
		&& ctest --test-dir build --output-on-failure

clean-cpp: ## Remove C++ build/test artifacts
	rm -rf cpp/build cpp/.pio cpp/.deps

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
# JSR:  the .d.ts declarations under javascript/types/ are GENERATED at release
#       time (npm run types) — they are not committed. They are wired to the JS
#       sources via @ts-self-types pragmas, so JSR fast-check passes and slow
#       types need not be allowed. If a publish fails on slow types, regenerate
#       the declarations and re-run. JSR versions are immutable: a published
#       version can never be reused.

NPM_DIST_TAG ?= rc
NPM_PUBLISH_FLAGS ?= --access public
JSR_PUBLISH_FLAGS ?=

release: release-python release-js release-jsr
release-dry: release-python-dry release-js-dry release-jsr-dry

release-python: ## Build sdist+wheel and upload to PyPI (twine)
	cd python && rm -rf dist && $(PYTHON) -m build && $(PYTHON) -m twine upload dist/*

release-python-dry: ## Build sdist+wheel and validate metadata (twine check)
	cd python && rm -rf dist && $(PYTHON) -m build && $(PYTHON) -m twine check dist/*

js-types: install-js ## Generate the JS declaration files (javascript/types/)
	cd javascript && npm run types

release-js: ## Publish to npm with dist-tag $(NPM_DIST_TAG) (prepublishOnly regenerates types/)
	cd javascript && npm publish $(NPM_PUBLISH_FLAGS) --tag $(NPM_DIST_TAG)

release-js-dry: ## Validate npm packaging without uploading
	cd javascript && npm publish --dry-run --tag $(NPM_DIST_TAG)

release-jsr: js-types ## Publish to JSR
	cd javascript && deno publish $(JSR_PUBLISH_FLAGS)

release-jsr-dry: js-types ## Validate JSR packaging without uploading (--allow-dirty for local WIP)
	cd javascript && deno publish --dry-run $(JSR_PUBLISH_FLAGS) --allow-dirty
