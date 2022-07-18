build:
	CGO_ENABLED=0 GO111MODULE=on go build -mod vendor -o _output/bin/cloud-network-config-controller cmd/cloud-network-config-controller/main.go
test:
	# This is commenting out the racy tests. The test file:
	# cloudprivateipconfig_controller_racy_test.go has the following go build
	# tag: "// +build race", which means it won't run if -race isn't provided to
	# "go test", hence why commenting out the test execution below with the
	# -race flag, effectively comments out the tests. The racy tests are
	# dependent upon fakeClient, which doesn't adhere to the real API server
	# implementation of UpdateStatus. UpdateStatus only modifies the status and
	# does not update the entire object against a real API server, fakeClient
	# does. Since our racy tests validate that we don't override any client
	# inputs while syncing, with fakeClient and its version of UpdateStatus: we
	# will. We could perform a kubeClient GET call just before calling
	# UpdateStatus, but given that this is not accurate behavior and not needed
	# IRL, let's not do that. We can instead change the racy tests to use
	# envtest from the controller-runtime. Once that is done, uncomment the racy
	# test below.
	# go test ./... -count=1 -race
	go test ./... -count=1
lint:
	golangci-lint run
