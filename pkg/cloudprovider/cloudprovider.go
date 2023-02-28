package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	v1 "github.com/openshift/api/cloudnetwork/v1"
	corev1 "k8s.io/api/core/v1"
)

var (
	NoNetworkInterfaceError  = errors.New("no retrievable network interface")
	AlreadyExistingIPError   = errors.New("the requested IP for assignment is already assigned")
	NonExistingIPError       = errors.New("the requested IP for removal is not assigned")
	UnexpectedURIErrorString = "the URI is not expected"
)

const UserAgent = "cloud-network-config-controller"

func UnexpectedURIError(uri string) error {
	return fmt.Errorf("%s: %s", UnexpectedURIErrorString, uri)
}

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
	// (GCP) or ID (Azure, AWS).
	GetNodeEgressIPConfiguration(node *corev1.Node, cloudPrivateIPConfigs []*v1.CloudPrivateIPConfig) ([]*NodeEgressIPConfiguration, error)
}

// CloudProviderWithMoveIntf is additional interface that can be added to cloud
// plugins that can benefit from a separate set of operations on IP address
// failover, instead of running ReleasePrivateIP followed by AssignPrivateIP.
type CloudProviderWithMoveIntf interface {
	// MovePrivateIP is called instead of ReleasePrivateIP followed by
	// AssignPrivateIP if plugin implements CloudProviderWithMoveIntf. It
	// should effectively move IP address from nodeToDel to nodeToAdd, but not
	// necessarily remove resources from the cloud. E.g. in case of OpenStack
	// we don't want to delete the reservation Neutron port, but rather just
	// manipulate allowedAddressPairs on the nodeToDel and nodeToAdd ports to
	// move the IP from one node to another.
	MovePrivateIP(ip net.IP, nodeToAdd *corev1.Node, nodeToDel *corev1.Node) error
}

// CloudProviderConfig is all the command-line options needed to initialize
// a cloud provider client.
type CloudProviderConfig struct {
	PlatformType  string // one of AWS, Azure, GCP
	APIOverride   string // override the API endpoint URL. Used by all platforms.
	CredentialDir string // override the default credential directory
	ConfigDir     string // override the default config directory

	Region        string // region, only used by AWS
	AWSCAOverride string

	AzureEnvironment string // The azure "environment", which is a set of API endpoints
}

type CloudProvider struct {
	CloudProviderIntf
	cfg CloudProviderConfig
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

//   - Interface - ID / Name, depending on the cloud's convention
//   - IP address capacity for each node, where the capacity is either IP family
//     agnostic or not.
//   - Subnet information for the first network interface, IP family specific
type NodeEgressIPConfiguration struct {
	Interface string   `json:"interface"`
	IFAddr    ifAddr   `json:"ifaddr"`
	Capacity  capacity `json:"capacity"`
}

// String implements the stringer interface for pointers to NodeEgressIPConfiguration. This is used for the unit tests
// as it simplifies printing of the actual values instead of returning the memory address that is being pointed to.
func (n *NodeEgressIPConfiguration) String() string {
	return fmt.Sprintf("%v", *n)
}

func NewCloudProviderClient(cfg CloudProviderConfig) (CloudProviderIntf, error) {
	var cloudProviderIntf CloudProviderIntf

	// Initialize a separate context from the main context, rationale: cloud
	// provider operations might take more time to run than any "API server" /
	// "in-cluster" operations, hence: if the main program gets terminated we'd
	// like to finish processing everything we are currently processing and
	// update our store (the cloud provider) before terminating, thus we can't
	// use the main context because it will be cancelled in such events.
	cloudProviderCtx := context.Background()
	cp := CloudProvider{
		ctx: cloudProviderCtx,
		cfg: cfg,
	}

	switch cfg.PlatformType {
	case PlatformTypeAzure:
		cloudProviderIntf = &Azure{
			CloudProvider: cp,
			nodeLockMap:   make(map[string]*sync.Mutex),
		}
	case PlatformTypeAWS:
		cloudProviderIntf = &AWS{
			CloudProvider: cp,
		}
	case PlatformTypeGCP:
		cloudProviderIntf = &GCP{
			CloudProvider: cp,
		}
	case PlatformTypeOpenStack:
		cloudProviderIntf = &OpenStack{
			CloudProvider: cp,
		}
	default:
		return nil, fmt.Errorf("unsupported cloud provider platform type: %s", cfg.PlatformType)
	}
	return cloudProviderIntf, cloudProviderIntf.initCredentials()
}

func (c *CloudProvider) readSecretData(secret string) (string, error) {
	data, err := os.ReadFile(filepath.Join(c.cfg.CredentialDir, secret))
	if err != nil {
		return "", fmt.Errorf("unable to read secret data, err: %v", err)
	}
	return string(data), nil
}
