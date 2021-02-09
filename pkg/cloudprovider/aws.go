package cloudprovider

import (
	"net"

	ocpconfigv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
)

const (
	aws = string(ocpconfigv1.AWSPlatformType)
)

// AWS implements the API wrapper for talking to the AWS cloud API
type AWS struct {
	CloudProvider
}

func (a *AWS) initCredentials() error {
	return nil
}

func (a *AWS) AssignPrivateIP(ip net.IP, node *corev1.Node) error {
	return nil
}

func (a *AWS) ReleasePrivateIP(ip net.IP, node *corev1.Node) error {
	return nil
}

func (a *AWS) GetNodeEgressIPConfiguration(node *corev1.Node) ([]*NodeEgressIPConfiguration, error) {
	return nil, nil
}
