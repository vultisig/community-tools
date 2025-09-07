all: webserver wasm

webserver:
	@echo "Building web server..."
	@mkdir -p dist
	go build -tags server -o dist/webserver ./cmd/server.go

wasm:
	@echo "Building WASM..."
	@mkdir -p web
	GOOS=js GOARCH=wasm go build -tags wasm -o web/main.wasm ./cmd/wasm.go

build: all

test:
	@echo "Running tests..."
	go test ./...

check:
	@echo "Checking code formatting..."
	go fmt ./...
	@echo "Running go vet..."
	go vet ./...

clean:
	@echo "Cleaning build artifacts..."
	rm -rf dist/
	rm -f static/main.wasm

.PHONY: all webserver wasm build test check clean