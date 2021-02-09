package cloudprovider

import (
	"net"

	ocpconfigv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
)

const (
	azure = string(ocpconfigv1.AzurePlatformType)
)

// Azure implements the API wrapper for talking
// to the Azure cloud API
type Azure struct {
	CloudProvider
}

func (a *Azure) initCredentials() error {
	return nil
}

func (a *Azure) AssignPrivateIP(ip net.IP, node *corev1.Node) error {
	return nil
}

func (a *Azure) ReleasePrivateIP(ip net.IP, node *corev1.Node) error {
	return nil
}

func (a *Azure) WaitForResponse(interface{}) error {
	return nil
}

func (a *Azure) GetNodeEgressIPConfiguration(node *corev1.Node) ([]*NodeEgressIPConfiguration, error) {
	return nil, nil
}
