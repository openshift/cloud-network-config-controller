## Project Overview

This is the cloud-network-config-controller (CNCC). It is an OpenShift controller/operator that interfaces with cloud provider APIs (AWS, Azure, GCP,
OpenStack) to manage private IP address assignments on VM instances associated with Kubernetes nodes. It manages the CloudPrivateIPConfig CRD (cloud.network.openshift.io/v1) and annotates node objects with egress IP capacity and subnet information.
See [README.md](README.md) for further information.

## Repository Layout

- `cmd/cloud-network-config-controller/`: entry point, flags and controller wiring.
- `pkg/controller/`: clould network config controller implementation.
- `pkg/cloudprovider/`: cloud provider interface implementations.
- `pkg/cloudprivateipconfig/`: IP/name conversion helpers;
- `pkg/signals/`: shutdown handling.
- `hack/`: development scripts.

## Build and Test

From the repository root:

- `make build`: builds with vendored dependencies into `_output/bin/cloud-network-config-controller`.
- `make test`: runs `go test ./... -count=1`.
- `make lint`: runs `golangci-lint` using `.golangci.yaml` (requires the tool installed).

