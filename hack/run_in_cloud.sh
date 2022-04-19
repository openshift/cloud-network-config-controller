#!/bin/bash

set -eux

DIR=$(dirname "${BASH_SOURCE[0]}")

CNCC_REPOSITORY=${CNCC_REPOSITORY:-""}
if [ -z "${CNCC_REPOSITORY}" ]; then
	echo "Please set environment variable CNCC_REPOSITORY and point it to your container repository"
	exit 1
fi

CONTAINER_ENGINE="${CONTAINER_ENGINE:-podman}"
PODMAN_BIN="podman"
PODMAN_BUILD_CMD="podman build"
PODMAN_CMD="podman"
if [ "$CONTAINER_ENGINE" == "docker" ]; then
	PODMAN_BIN="docker"
	PODMAN_BUILD_CMD="docker build"
	PODMAN_CMD="docker"
fi

for command in mktemp awk oc uuidgen $PODMAN_BIN; do
	if ! command -v $command &> /dev/null
	then
		echo "$command not found"
		exit 1
	fi
done

UUID=$(uuidgen)
IMAGE="${CNCC_REPOSITORY}:${UUID}"

pushd $DIR/../
	$PODMAN_BUILD_CMD -t ${IMAGE} .
	$PODMAN_CMD push ${IMAGE}
popd

oc patch clusterversion version --type json -p '[{"op":"add","path":"/spec/overrides","value":[{"kind":"Deployment","group":"apps","name":"network-operator","namespace":"openshift-network-operator","unmanaged":true}]}]'
oc scale -n openshift-network-operator deployment.apps/network-operator --replicas=0
oc patch -n openshift-network-operator deployment.apps network-operator -p '{"spec":{"template":{"spec":{"containers":[{"name":"network-operator","env":[{"name":"CLOUD_NETWORK_CONFIG_CONTROLLER_IMAGE","value":"'${IMAGE}'"}]}]}}}}'
oc describe -n openshift-network-operator deployment.apps network-operator | grep CLOUD_NETWORK_CONFIG_CONTROLLER_IMAGE
oc scale -n openshift-network-operator deployment.apps/network-operator --replicas=1

# Support for jsonpath expressions only starting with 4.10
if oc wait --for=jsonpath='{.status.phase}'=Running --timeout=1s pod/busybox1 2>&1 | grep -q 'unrecognized condition' ; then
	sleep 120
else
	oc wait --for=condition=available --timeout=60s deployment/network-operator -n openshift-network-operator
	oc wait --for=jsonpath='{.spec.template.spec.containers[0].image}'="${IMAGE}" --timeout=120s deployment -n openshift-cloud-network-config-controller cloud-network-config-controller
	oc wait --for=condition=available --timeout=60s deployment/cloud-network-config-controller -n openshift-cloud-network-config-controller
	oc wait --for=jsonpath='{.status.phase}'=Running pods -l app=cloud-network-config-controller -n openshift-cloud-network-config-controller
fi

oc get pods -n openshift-cloud-network-config-controller -l app=cloud-network-config-controller -o jsonpath='{.items[0].spec.containers[0].image}'
oc logs -n openshift-cloud-network-config-controller -l app=cloud-network-config-controller
