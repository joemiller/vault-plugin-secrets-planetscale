
VAULT_CLI ?= vault

export VAULT_TOKEN ?= root
export VAULT_ADDR ?= http://localhost:8200

LOG_LEVEL ?= DEBUG

PLUGIN_DIR := ./bin
BINARY_NAME := vault-plugin-secrets-planetscale
PLUGIN_NAME := planetscale

test:
	go test -race -cover -coverprofile=cover.out -v ./...

cov:
	@echo "--- Coverage:"
	go tool cover -html=cover.out
	go tool cover -func cover.out

build:
	CGO_ENABLED=0 go build -o $(PLUGIN_DIR)/$(BINARY_NAME) ./cmd/$(BINARY_NAME)

start:
	$(VAULT_CLI) server -dev -dev-root-token-id=$(VAULT_TOKEN) -dev-plugin-dir=$(PLUGIN_DIR) -log-level=$(LOG_LEVEL) & echo "$$!" > vault.pid
	sleep 2 # wait for vault to start
	cat vault.pid

stop:
	test -f vault.pid && kill `cat vault.pid` && rm vault.pid || echo "No vault.pid file found. Try 'pkill vault' if its really running."

register:
	$(VAULT_CLI) plugin register \
		-sha256=$(shell sha256sum $(PLUGIN_DIR)/$(BINARY_NAME) | cut -d ' ' -f1) \
		-command=$(BINARY_NAME) \
		secret $(PLUGIN_NAME)

deregister:
	$(VAULT_CLI) plugin deregister secret $(PLUGIN_NAME)

enable:
	$(VAULT_CLI) secrets enable -path=$(MOUNT_PATH) -plugin-name=$(PLUGIN_NAME) plugin

disable:
	$(VAULT_CLI) secrets disable $(MOUNT_PATH)

reload:
	$(VAULT_CLI) plugin reload -plugin=$(PLUGIN_NAME)

# configure:
# 	$(VAULT_CLI) write $(MOUNT_PATH)/config \
# 		service_token_id="example-token-id" \
# 		service_token="example-token" \
# 		org_id="example-org-id"

dev: build deregister register reload enable

setup: clean build disable deregister register enable configure

.PHONY: build test cov clean fmt start stop register deregister enable disable reload configure dev setup