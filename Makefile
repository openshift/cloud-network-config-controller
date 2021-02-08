build:
	CGO_ENABLED=0 GO111MODULE=on go build -mod vendor -o _output/bin/cloud-network-config-controller cmd/cloud-network-config-controller/cloud-network-config-controller.go
test:
	go test ./...
codegen:
	hack/update-codegen.sh
