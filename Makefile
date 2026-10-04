.PHONY: test build check

test:
	go test -race ./...

build:
	go build -trimpath -o loop-event-bridge .

check:
	go vet ./...
	go test -race ./...
