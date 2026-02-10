# Makefile for Nginx Sentinel

APP_NAME = nginx-sentinel
CARGO = cargo
DOCKER = docker
IMAGE_NAME = nginx-sentinel

.PHONY: all build release run test clean docker-build docker-run help

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: build ## Build the project in debug mode

build: ## Build the project (debug)
	$(CARGO) build

release: ## Build the project (release)
	$(CARGO) build --release

run: ## Run the project (requires sudo for ipset/iptables)
	@echo "Running with sudo..."
	sudo $(CARGO) run

test: ## Run tests
	$(CARGO) test

clean: ## Clean build artifacts
	$(CARGO) clean

docker-build: ## Build Docker image
	$(DOCKER) build -t $(IMAGE_NAME) .

docker-run: ## Run Docker container (requires access.log and config)
	@touch access.log
	$(DOCKER) run -d \
		--name $(APP_NAME) \
		--cap-add=NET_ADMIN \
		--cap-add=NET_RAW \
		--net=host \
		-v $$(pwd)/access.log:/var/log/nginx/access.log \
		-v $$(pwd)/sentinel_config.yaml:/app/sentinel_config.yaml \
		$(IMAGE_NAME)
	@echo "Container started. Logs:"
	@$(DOCKER) logs -f $(APP_NAME)

docker-stop: ## Stop and remove Docker container
	$(DOCKER) rm -f $(APP_NAME) || true

fmt: ## Format code
	$(CARGO) fmt

check: ## Check code for errors
	$(CARGO) check
