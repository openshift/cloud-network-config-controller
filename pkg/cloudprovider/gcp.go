package cloudprovider

import (
	"net"

	ocpconfigv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
)

const (
	gcp = string(ocpconfigv1.GCPPlatformType)
)

// GCP implements the API wrapper for talking
// to the GCP cloud API
type GCP struct {
	CloudProvider
}

func (a *GCP) initCredentials() error {
	return nil
}

func (a *GCP) AssignPrivateIP(ip net.IP, node *corev1.Node) error {
	return nil
}

func (a *GCP) ReleasePrivateIP(ip net.IP, node *corev1.Node) error {
	return nil
}

func (a *GCP) WaitForResponse(interface{}) error {
	return nil
}

func (a *GCP) GetNodeEgressIPConfiguration(node *corev1.Node) ([]*NodeEgressIPConfiguration, error) {
	return nil, nil
}
