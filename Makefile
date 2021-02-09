build:
	CGO_ENABLED=0 GO111MODULE=on go build -mod vendor -o _output/bin/cloud-network-config-controller cmd/cloud-network-config-controller/main.go
test:
	go test ./...
