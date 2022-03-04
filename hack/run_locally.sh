#!/bin/bash

set -eo pipefail

for cmd in go jq oc; do
   if ! command -v "$cmd" &> /dev/null; then
      echo "$cmd is not available"
      exit 1
   fi
done

# This script expects you to have KUBECONFIG exported in your env

HERE=$(dirname "$(readlink --canonicalize "$BASH_SOURCE")")
ROOT=$(readlink --canonicalize "$HERE/..")
SECRET_LOCATION=$ROOT/tmp-secret-location/
mkdir -p $SECRET_LOCATION

platformtype=$(oc get infrastructures.config.openshift.io cluster  -o jsonpath='{.status.platform}')

# This won't work on platforms != AWS, but we don't care. 
# The command won't fail and `cloudregion` is only used on AWS
platformregion=$(oc get infrastructures.config.openshift.io cluster  -o jsonpath='{.status.platformStatus.aws.region}')

json=$(oc get secret cloud-credentials -n openshift-cloud-network-config-controller -o jsonpath='{.data}')
for key in $(echo $json | jq -r 'keys[]'); do
    value=$(echo $json | jq -r ".[\"$key\"]" | base64 -d)
    echo $value>$SECRET_LOCATION/$key
done

export CONTROLLER_NAMESPACE="openshift-cloud-network-config-controller"
export CONTROLLER_NAME="tmp-local-controller"

oc scale deployment network-operator -n openshift-network-operator --replicas 0
oc scale deployment cloud-network-config-controller -n openshift-cloud-network-config-controller --replicas 0

go run $ROOT/cmd/cloud-network-config-controller/main.go \
	-kubeconfig $KUBECONFIG \
	-platform-type $platformtype \
	-secret-name "cloud-credentials" \
	-secret-override "$SECRET_LOCATION" \
	-platform-region "$platformregion"
