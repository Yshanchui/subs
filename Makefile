.PHONY: test build run
test:
	go test -race ./...
	go vet ./...
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/subs .
	cp LICENSE THIRD_PARTY_NOTICES.md bin/
	cp -R licenses bin/
run:
	go run .
