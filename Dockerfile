FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.22 AS builder

WORKDIR /go/src/github.com/openshift/cloud-network-config-controller
COPY . .
RUN make build

FROM registry.ci.openshift.org/ocp/4.22:base-rhel9

COPY --from=builder /go/src/github.com/openshift/cloud-network-config-controller/_output/bin/cloud-network-config-controller /usr/bin/

LABEL io.k8s.display-name="Cloud Network Config Controller" \
      io.k8s.description="Controller performing cloud level network modification" \
      io.openshift.tags="openshift" \
      maintainer="Alexander Constantinescu <aconstan@redhat.com>"
