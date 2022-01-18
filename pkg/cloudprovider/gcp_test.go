package cloudprovider

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestSplitGCPNode(t *testing.T) {
	n := corev1.Node{
		Spec: corev1.NodeSpec{
			ProviderID: "gce://openshift-qe/us-central1-a/lwanstsg0118f-tvpsk-master-0",
		},
	}

	project, zone, instance, err := splitGCPNode(&n)
	if err != nil {
		t.Fatal(err)
	}
	if project != "openshift-qe" {
		t.Fatalf("wrong project: %s", project)
	}

	if zone != "us-central1-a" {
		t.Fatalf("wrong zone: %s", zone)
	}

	if instance != "lwanstsg0118f-tvpsk-master-0" {
		t.Fatalf("wrong name: %s", instance)
	}
}
