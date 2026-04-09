.PHONY: run
run: ## Run the main script in the current environment. Usage: make run
	@echo "🚀 Running main script in current environment"
	@python src/DomainChecker/checkdomain.py
.PHONY: install
install: ## Install the virtual environment and install the pre-commit hooks
	@echo "🚀 Creating virtual environment using uv"
	@uv sync
	@uv run pre-commit install

.PHONY: check
check: ## Run code quality tools.
	@echo "🚀 Checking lock file consistency with 'pyproject.toml'"
	@uv lock --locked
	@echo "🚀 Linting code: Running pre-commit"
	@uv run pre-commit run -a
	@echo "🚀 Static type checking: Running mypy"
	@uv run mypy

.PHONY: test
test: ## Test the code with pytest
	@echo "🚀 Testing code: Running pytest"
	@uv run python -m pytest --doctest-modules

.PHONY: build
build: clean-build ## Build wheel file
	@echo "🚀 Creating wheel file"
	@uvx --from build pyproject-build --installer uv

.PHONY: clean-build
clean-build: ## Clean build artifacts
	@echo "🚀 Removing build artifacts"
	@uv run python -c "import shutil; import os; shutil.rmtree('dist') if os.path.exists('dist') else None"

# Detect container runtime (docker or podman). Falls back to podman-compose if needed
CONTAINER_CLI := $(shell command -v docker >/dev/null 2>&1 && echo docker || (command -v podman >/dev/null 2>&1 && echo podman || echo ""))
COMPOSE_CMD := $(shell if command -v docker >/dev/null 2>&1; then echo "docker compose"; elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then echo "podman compose"; elif command -v podman >/dev/null 2>&1; then echo "podman-compose"; else echo ""; fi)

.PHONY: docker-build
docker-build: ## Build the container image (generates uv.lock if missing)
	@echo "🚀 Ensuring uv.lock exists"
	@test -f uv.lock || uv lock
	@echo "🚀 Using: $(COMPOSE_CMD)"
	@test -n "$(COMPOSE_CMD)" || (echo "No container runtime found (docker or podman). Install docker or podman." >&2; exit 1)
	@echo "🚀 Building container image"
	@$(COMPOSE_CMD) build

.PHONY: docker-up
docker-up: ## Run domain checker once in container and write results.csv
	@echo "🚀 Running domain checker (one-shot container)"
	@test -n "$(COMPOSE_CMD)" || (echo "No container runtime found (docker or podman). Install docker or podman." >&2; exit 1)
	@$(COMPOSE_CMD) run --rm domain-checker

.PHONY: dev
dev: docker-build ## Start a development container and leave it running for VSCode to attach
	@echo "🚀 Starting development container 'domain-checker-dev'"
	@echo "🚀 Using: $(COMPOSE_CMD)"
	@test -n "$(COMPOSE_CMD)" || (echo "No container runtime found (docker or podman). Install docker or podman." >&2; exit 1)
	@$(COMPOSE_CMD) build
	-@$(CONTAINER_CLI) rm -f domain-checker-dev >/dev/null 2>&1 || true
	@$(COMPOSE_CMD) run --name domain-checker-dev -d --service-ports --entrypoint tail domain-checker -f /dev/null || $(CONTAINER_CLI) start domain-checker-dev >/dev/null 2>&1 || true
	@echo "In VSCode: use 'Remote-Containers: Attach to Running Container...' and select 'domain-checker-dev'"

.PHONY: docker-down
docker-down: ## Stop containers (graceful)
	@echo "🚀 Stopping containers"
	@bash -c '\
	if command -v docker >/dev/null 2>&1; then \
	  docker compose down; \
	elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then \
	  podman compose down; \
	elif command -v podman-compose >/dev/null 2>&1; then \
	  podman-compose down; \
	else \
	  echo "No container runtime found (docker or podman). Install docker or podman." >&2; exit 1; \
	fi'

.PHONY: docker-clean
docker-clean: ## Force remove containers, images and volumes (aggressive)
	@echo "🚀 Forcing cleanup of containers, images and volumes (use with care)"
	@bash -c '\
	if command -v docker >/dev/null 2>&1; then \
	  docker compose down --rmi all -v --remove-orphans || true; \
	  docker system prune -a --volumes -f || true; \
	elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then \
	  podman compose down --rmi all -v || true; \
	  podman system prune -a -f --volumes || true; \
	elif command -v podman-compose >/dev/null 2>&1; then \
	  podman-compose down || true; \
	  podman ps -a -q | xargs -r podman rm -f || true; \
	  podman images -q | xargs -r podman rmi -f || true; \
	  podman volume ls -q | xargs -r podman volume rm -f || true; \
	else \
	  echo "No container runtime found (docker or podman). Install docker or podman." >&2; exit 1; \
	fi'



.PHONY: docker-logs
docker-logs: ## Tail container logs
	@test -n "$(COMPOSE_CMD)" || (echo "No container runtime found (docker or podman). Install docker or podman." >&2; exit 1)
	@$(COMPOSE_CMD) logs -f

.PHONY: help
help:
	@uv run python -c "import re; \
	[[print(f'\033[36m{m[0]:<20}\033[0m {m[1]}') for m in re.findall(r'^([a-zA-Z_-]+):.*?## (.*)$$', open(makefile).read(), re.M)] for makefile in ('$(MAKEFILE_LIST)').strip().split()]"

.DEFAULT_GOAL := help
