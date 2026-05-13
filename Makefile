.PHONY: build-server build-nativehost build-electron build-extension-chrome build-extension-firefox build-extension-edge build-all test docker migrate lint clean

# Go binaries
build-server:
	go build -trimpath -ldflags="-s -w" -o bin/server ./cmd/server/main.go

build-standalone:
	go build -trimpath -ldflags="-s -w" -o bin/server-standalone ./cmd/server/main.go

build-nativehost:
	go build -trimpath -ldflags="-s -w" -o bin/neopass-native-host ./cmd/nativehost/main.go

# Electron desktop app
build-electron:
	cd electron && npm run build

# Browser extensions
build-extension-chrome:
	cd extension && npx cross-env TARGET_BROWSER=chrome npx webpack --mode production

build-extension-firefox:
	cd extension && npx cross-env TARGET_BROWSER=firefox npx webpack --mode production

build-extension-edge:
	cd extension && npx cross-env TARGET_BROWSER=edge npx webpack --mode production

build-extensions: build-extension-chrome build-extension-firefox build-extension-edge

# All targets
build-all: build-server build-standalone build-nativehost build-electron build-extensions

# Testing
test:
	go test ./...
	cd electron && npm test
	cd extension && npm test

test-go:
	go test ./...

test-electron:
	cd electron && npm test

test-extension:
	cd extension && npm test

# Docker
docker:
	docker compose build

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

# Linting
lint:
	golangci-lint run ./...
	cd electron && npm run lint
	cd extension && npm run lint

lint-go:
	golangci-lint run ./...

# Extension packaging (zip for store submission)
package-extension-chrome: build-extension-chrome
	cd extension && cd dist/chrome && zip -r ../../neopass-chrome.zip .

package-extension-firefox: build-extension-firefox
	cd extension && cd dist/firefox && zip -r ../../neopass-firefox.zip .

package-extension-edge: build-extension-edge
	cd extension && cd dist/edge && zip -r ../../neopass-edge.zip .

package-extensions: package-extension-chrome package-extension-firefox package-extension-edge

# Electron distribution
dist-electron:
	cd electron && npm run dist

dist-electron-win:
	cd electron && npm run dist:win

dist-electron-mac:
	cd electron && npm run dist:mac

dist-electron-linux:
	cd electron && npm run dist:linux

# Database migrations
migrate:
	go run cmd/server/main.go -migrate

# Clean
clean:
ifeq ($(OS),Windows_NT)
	if exist bin rmdir /s /q bin
	if exist electron\dist rmdir /s /q electron\dist
	if exist electron\release rmdir /s /q electron\release
	if exist extension\dist rmdir /s /q extension\dist
else
	rm -rf bin/ electron/dist/ electron/release/ extension/dist/
endif
