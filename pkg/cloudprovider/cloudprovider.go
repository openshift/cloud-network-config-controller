package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

var (
	cloudProviderSecretLocation = "/etc/secret/cloudprovider/"
	NoNetworkInterfaceError     = errors.New("no retrievable network interface")
	AlreadyExistingIPError      = errors.New("the requested IP for assignment is already assigned")
	NonExistingIPError          = errors.New("the requested IP for removal is not assigned")
)

type CloudProviderIntf interface {
	// initCredentials initializes the cloud API credentials by reading the
	// secret data which has been mounted in cloudProviderSecretLocation. The
	// mounted secret data in Kubernetes is generated following a one-to-one
	// mapping between each .data field and a corresponding file. Hence
	// .data.foo will generate a file foo in that location with the decoded
	// secret data, similarity we would have a file bar if .data.bar was
	// defined.
	initCredentials() error

	// AssignPrivateIP attempts to assigning the IP address provided to the VM
	// instance corresponding to the corev1.Node provided on the cloud the
	// cluster is deployed on. NOTE: this operation is only performed against
	// the first network interface defined for the VM. It will return an
	// AlreadyExistingIPError if the IP provided is already associated with the
	// node, it's up to the caller to decide what to do with that.
	AssignPrivateIP(ip net.IP, node *corev1.Node) error

	// ReleasePrivateIP attempts to releasing the IP address provided from the
	// VM instance corresponding to the corev1.Node provided on the cloud the
	// cluster is deployed on. NOTE: this operation is only performed against
	// the first network interface defined for the VM.
	ReleasePrivateIP(ip net.IP, node *corev1.Node) error

	// GetNodeEgressIPConfiguration retrieves the egress IP configuration for
	// the node, following the convention the cloud uses. This means
	// specifically that: the IP capacity can be either hard-coded and global
	// for all instance types and IP families (GCP, Azure) or variable per
	// instance and IP family (AWS), also: the interface is either keyed by name
	// (GCP) or ID (Azure, AWS). Note: this function should only be called when
	// no egress IPs have been added to the node, it will return an incorrect
	// "egress IP capacity" otherwise
	GetNodeEgressIPConfiguration(node *corev1.Node) ([]*NodeEgressIPConfiguration, error)
}

type CloudProvider struct {
	CloudProviderIntf
	ctx context.Context
}

type ifAddr struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

type capacity struct {
	IPv4 int `json:"ipv4,omitempty"`
	IPv6 int `json:"ipv6,omitempty"`
	IP   int `json:"ip,omitempty"`
}

//  NodeEgressIPConfiguration stores details - specific to each cloud - which are
//  important for performing egress IP assignments by the network plugin.
//  Specifically this is:

//  - Interface - ID / Name, depending on the cloud's convention
//  - IP address capacity for each node, where the capacity is either IP family
//    agnostic or not.
//  - Subnet information for the first network interface, IP family specific
type NodeEgressIPConfiguration struct {
	Interface string   `json:"interface"`
	IFAddr    ifAddr   `json:"ifaddr"`
	Capacity  capacity `json:"capacity"`
}

func NewCloudProviderClient(platformType string) (CloudProviderIntf, error) {
	var cloudProviderIntf CloudProviderIntf

	// Initialize a separate context from the main context, rationale: cloud
	// provider operations might take more time to run than any "API server" /
	// "in-cluster" operations, hence: if the main program gets terminated we'd
	// like to finish processing everything we are currently processing and
	// update our store (the cloud provider) before terminating, thus we can't
	// use the main context because it will be cancelled in such events.
	cloudProviderCtx := context.Background()

	switch platformType {
	case azure:
		cloudProviderIntf = &Azure{
			CloudProvider: CloudProvider{
				ctx: cloudProviderCtx,
			},
		}
	case aws:
		cloudProviderIntf = &AWS{
			CloudProvider: CloudProvider{
				ctx: cloudProviderCtx,
			},
		}
	case gcp:
		cloudProviderIntf = &GCP{
			CloudProvider: CloudProvider{
				ctx: cloudProviderCtx,
			},
		}
	default:
		return nil, fmt.Errorf("unsupported cloud provider platform type: %s", platformType)
	}
	return cloudProviderIntf, cloudProviderIntf.initCredentials()
}
