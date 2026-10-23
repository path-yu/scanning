VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
BIN := bin/scanning$(shell go env GOEXE)
LDFLAGS := -s -w -X scanning/internal/version.Version=$(VERSION)
# 进程注入 Hook DLL 使用 Zig/MinGW 交叉编译，不依赖 MSVC。
HOOK_CC ?= zig
HOOK_DLL := bin/hook/scanning_hook_x64.dll

.PHONY: web build build-wpcap hook run dev test vet clean release release-windows release-linux release-darwin

web:
	cd web && npm install --no-audit --no-fund && npm run build

hook:
	@mkdir -p bin/hook
	$(HOOK_CC) cc -target x86_64-windows-gnu -shared -O2 -o $(HOOK_DLL) internal/hook/native/scanning_hook.c -lws2_32

build: web
	go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/scanning

# Windows 实时网卡抓包（Npcap）构建；纯 Go + syscall，不依赖 cgo。
build-wpcap: web
	go build -tags wpcap -ldflags "$(LDFLAGS)" -o bin/scanning-wpcap.exe ./cmd/scanning

run: build
	$(BIN) --no-open

dev:
	@echo "终端 1: cd web && npm run dev"
	@echo "终端 2: go run -tags dev ./cmd/scanning --dev"

test:
	go test ./...
	cd web && npm run typecheck

vet:
	go vet ./...

clean:
	go clean
	rm -rf web/dist bin/hook

# 先构建一次前端，再交叉编译各平台产物到 bin/。
release: web release-windows release-linux release-darwin

release-windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -tags wpcap -ldflags "$(LDFLAGS)" -o bin/scanning-windows-amd64.exe ./cmd/scanning

release-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/scanning-linux-amd64 ./cmd/scanning
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/scanning-linux-arm64 ./cmd/scanning

release-darwin:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/scanning-darwin-amd64 ./cmd/scanning
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/scanning-darwin-arm64 ./cmd/scanning
