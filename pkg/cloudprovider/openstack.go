package cloudprovider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	novaservers "github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	neutronports "github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	neutronsubnets "github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"
	"github.com/gophercloud/gophercloud/v2/pagination"
	"github.com/gophercloud/utils/v2/openstack/clientconfig"
	v1 "github.com/openshift/api/cloudnetwork/v1"
	"github.com/openshift/cloud-network-config-controller/pkg/cloudprivateipconfig"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

const (
	// PlatformTypeOpenStack is the string representation for the OpenStack platform type.
	PlatformTypeOpenStack   = "OpenStack"
	openstackCloudName      = "openstack"
	openstackProviderPrefix = "openstack:///"
	egressIPTag             = "OpenShiftEgressIP"

	// NOTE: Capacity is defined on a per interface basis as:
	// - IP address capacity for each node, where the capacity is either IP family
	//   agnostic or not.
	// However, in OpenStack, we do have several possible ceilings such as port quotas and max_allowed_address_pairs.
	// PortQuotas is the quota for the entire project and it might change based on admin settings. On the other hand,
	// the PortQuota value should always be high enough and we should most likely not bother looking it up.
	// However, max_allowed_address_pairs defaults to 10. It is only configurable in neutron.conf and there is no way
	// to retrieve it through the API. In RHOSP, it defaults to 10, as well. Therefore, our best option is to set this
	// to the default value of 10, always; and we might want to document that OSP environments must set
	// max_allowed_address_pairs >= 10. For more details, see:
	// https://github.com/openstack/neutron/blob/800f863ccc502b334cb2dd79ec54066440e43e27/neutron/conf/extensions/allowedaddresspairs.py#L21
	openstackMaxCapacity = 10
)

// OpenStack implements the API wrapper for talking
// to the OpenStack API
type OpenStack struct {
	CloudProvider
	CloudProviderWithMoveIntf
	novaClient       *gophercloud.ServiceClient
	neutronClient    *gophercloud.ServiceClient
	portLockMapMutex sync.Mutex
	portLockMap      map[string]*sync.Mutex
}

var novaDeviceOwnerRegex = regexp.MustCompile("^compute:.*")

// initCredentials initializes the cloud API credentials by reading the
// secret data which has been mounted in cloudProviderSecretLocation. The
// mounted secret data in Kubernetes is generated following a one-to-one
// mapping between each .data field and a corresponding file.
// For OpenStack, read the generated clouds.yaml file inside
// cloudProviderSecretLocation for auth purposes.
func (o *OpenStack) initCredentials() error {
	var err error

	// Read the clouds.yaml file.
	// That information is stored in secret cloud-credentials.
	clientConfigFile := filepath.Join(o.cfg.CredentialDir, "clouds.yaml")
	content, err := os.ReadFile(clientConfigFile)
	if err != nil {
		return fmt.Errorf("could read file %s, err: %q", clientConfigFile, err)
	}

	// Unmarshal YAML content into Clouds object.
	var clouds clientconfig.Clouds
	err = yaml.Unmarshal(content, &clouds)
	if err != nil {
		return fmt.Errorf("could not parse cloud configuration from %s, err: %q", clientConfigFile, err)
	}
	// We expect that the cloud in clouds.yaml be named "openstack".
	cloud, ok := clouds.Clouds[openstackCloudName]
	if !ok {
		return fmt.Errorf("invalid clouds.yaml file. Missing section for cloud name '%s'", openstackCloudName)
	}

	// Set AllowReauth to enable reauth when the token expires. Otherwise, we'll get endless ""Authentication failed"
	// errors after the token expired.
	// https://github.com/gophercloud/gophercloud/blob/a5d8e32ad107b1b72635a2e823ddd6c28fa0d4e7/auth_options.go#L70
	// https://github.com/gophercloud/gophercloud/blob/513734676e6495f6fec60e7aaf1f86f1ce807428/openstack/client.go#L151
	cloud.AuthInfo.AllowReauth = true

	// Prepare the options.
	clientOpts := &clientconfig.ClientOpts{
		Cloud:      cloud.Cloud,
		AuthType:   cloud.AuthType,
		AuthInfo:   cloud.AuthInfo,
		RegionName: cloud.RegionName,
	}
	opts, err := clientconfig.AuthOptions(clientOpts)
	if err != nil {
		return err
	}
	provider, err := openstack.NewClient(opts.IdentityEndpoint)
	if err != nil {
		return err
	}

	// Read CA information - needed for self-signed certificates.
	// That information is stored in ConfigMap kube-cloud-config.
	caBundle := filepath.Join(o.cfg.ConfigDir, "ca-bundle.pem")
	userCACert, err := os.ReadFile(caBundle)
	if err == nil && string(userCACert) != "" {
		klog.Infof("Custom CA bundle found at location '%s' - reading certificate information", caBundle)
		certPool, err := x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("could not initialize x509 SystemCertPool, err: %q", err)
		}
		transport := http.Transport{}
		certPool.AppendCertsFromPEM([]byte(userCACert))
		transport.TLSClientConfig = &tls.Config{RootCAs: certPool}
		transport.Proxy = http.ProxyFromEnvironment
		provider.HTTPClient = http.Client{Transport: &transport}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("could not parse file '%s', err: %q", caBundle, err)
	} else {
		klog.Infof("Could not find custom CA bundle in file '%s' - some environments require a custom CA to work correctly", caBundle)
	}

	// Now, authenticate.
	err = openstack.Authenticate(context.TODO(), provider, *opts)
	if err != nil {
		return err
	}

	// And create a client for nova (compute / servers).
	o.novaClient, err = openstack.NewComputeV2(provider, gophercloud.EndpointOpts{
		//	Region: cloud.RegionName,
	})
	if err != nil {
		return err
	}

	// And another client for neutron (network).
	o.neutronClient, err = openstack.NewNetworkV2(provider, gophercloud.EndpointOpts{
		//	Region: cloud.RegionName,
	})
	if err != nil {
		return err
	}

	return nil
}

// findAssignSubnetAndPort attempts to identify a subnet and server port for an AssignPrivateIP operation on a given node.
func (o *OpenStack) findAssignSubnetAndPort(ip net.IP, node *corev1.Node) (*neutronsubnets.Subnet, *neutronports.Port, error) {
	if node == nil {
		return nil, nil, fmt.Errorf("invalid nil pointer provided for node when trying to assign private IP %s", ip.String())
	}
	// List all ports that are attached to this server.
	serverID, err := getNovaServerIDFromProviderID(node.Spec.ProviderID)
	if err != nil {
		return nil, nil, err
	}
	serverPorts, err := o.listNovaServerPorts(serverID)
	if err != nil {
		return nil, nil, err
	}

	// Loop over all ports that are attached to this nova instance and find the subnets
	// that are attached to the port's network.
	for _, serverPort := range serverPorts {
		// If this IP address is already allowed on the port (speak: part of allowed_address_pairs),
		// then return an AlreadyExistingIPError and skip all further steps.
		if isIPAddressAllowedOnNeutronPort(serverPort, ip) {
			// This is part of normal operation.
			// Callers will likely ignore this and go on with their business logic and
			// report success to the user.
			return nil, nil, AlreadyExistingIPError
		}

		// Get all subnets that are attached to this port.
		subnets, err := o.getNeutronSubnetsForNetwork(serverPort.NetworkID)
		if err != nil {
			klog.Warningf("Could not find subnet information for network %s, err: %q", serverPort.NetworkID, err)
			continue
		}
		// 1) Loop over all subnets of the port and check if the IP address fits inside the subnet CIDR.
		//   If the IP address is inside the subnet:
		//   2) Return it as this is the subnet and port we were looking for.
		// 3) Throw an error if the IP address does not fit in any of the attached network's subnets.
		var matchingSubnet *neutronsubnets.Subnet
		for _, s := range subnets {
			// Because we're dealing with a pointer here for matchingSubnet:
			// we must reassign s:= s or we'd overwrite the content that we point
			// to.
			s := s
			// 1) Loop over all subnets and check if the IP address matches the subnet CIDR. If the IP
			//    addresses matches multiple subnets on the same server port, then something is wrong
			//    with this server's configuration and we should refuse to continue by throwing an error.
			_, ipnet, err := net.ParseCIDR(s.CIDR)
			if err != nil {
				klog.Warningf("Could not parse subnet information %s for network %s, err: %q",
					s.CIDR, serverPort.NetworkID, err)
				continue
			}
			if !ipnet.Contains(ip) {
				continue
			}
			if matchingSubnet != nil {
				return nil, nil, fmt.Errorf("requested IP address %s for node %s and port %s matches 2 different subnets, %s and %s",
					ip, node.Name, serverPort.ID, matchingSubnet.ID, s.ID)
			}
			matchingSubnet = &s
		}
		if matchingSubnet != nil {
			// 2) Return the matching subnet and port.
			return matchingSubnet, &serverPort, nil
		}
	}

	// 3) The IP address does not fit in any of the attached networks' subnets.
	return nil, nil, fmt.Errorf("could not assign IP address %s to node %s", ip, node.Name)
}

// AssignPrivateIP attempts to assigning the IP address provided to the VM
// instance corresponding to the corev1.Node provided on the cloud the
// cluster is deployed on.
// NOTE: This operation is performed against all interfaces that are attached
// to the server. In case that an instance has 2 interfaces with the same CIDR
// that this IP address could fit in, the first interface that is found will be used.
// No guarantees about the correct interface ordering are given in such a case.
// Throw an AlreadyExistingIPError if the IP provided is already associated with the
// node, it's up to the caller to decide what to do with that.
// NOTE: For OpenStack, this is a 2 step operation which is not atomic:
//
//	a) Reserve a neutron port.
//	b) Add the IP address to the allowed_address_pairs field.
//
// If step b) fails, then we will try to undo step a). However, if this undo fails,
// then we will be in a situation where the user or an upper layer will have to call
// ReleasePrivateIP to get out of this situation.
func (o *OpenStack) AssignPrivateIP(ip net.IP, node *corev1.Node) error {
	if node == nil {
		return fmt.Errorf("invalid nil pointer provided for node when trying to assign private IP %s", ip.String())
	}
	serverID, err := getNovaServerIDFromProviderID(node.Spec.ProviderID)
	if err != nil {
		return err
	}

	matchingSubnet, matchingPort, err := o.findAssignSubnetAndPort(ip, node)
	if err != nil {
		return err
	}

	// Reserve the IP address on the subnet by creating a new unattached neutron port.
	unboundPort, err := o.reserveNeutronIPAddress(*matchingSubnet, ip, serverID)
	if err != nil {
		return err
	}
	// Then, add the IP address to the port's allowed_address_pairs.
	//    TODO: use a more elegant retry mechanism.
	if err = o.allowIPAddressOnNeutronPort(matchingPort.ID, ip); err != nil && !errors.Is(err, AlreadyExistingIPError) {
		// Try to clean up the allocated port if adding the IP to allowed_address_pairs failed.
		// Try this 10 times, but if this operation fails more than that, then user intervention is needed or
		// the upper layer must call ReleasePrivateIP (because if the neutron port exists and holds
		// a reservation, then the assign step will not continue after step 2).
		var errRelease error
		var releaseStatus string
		for i := 0; i < 10; i++ {
			errRelease = o.releaseNeutronIPAddress(*unboundPort, serverID)
			// If the release operation was successful, then we are done.
			if errRelease == nil {
				releaseStatus = "Released neutron port reservation."
				break
			}
			// Otherwise store the error message and retry.
			releaseStatus = fmt.Sprintf("Could not release neutron port reservation after %d tries, err: %q", i+1, errRelease)
		}
		return fmt.Errorf("could not allow IP address %s on port %s, err: %q. %s", ip.String(), matchingPort.ID, err, releaseStatus)
	}
	// Return nil to indicate success if steps 2 and 3 passed.
	return nil
}

// MovePrivateIP implements moving the IP from one node to another to serve cases like a failover.
// What's different from calling ReleasePrivateIP followed by AssignPrivateIP is that the reservation
// Neutron port will not get deleted - MovePrivateIP will only change the allowed_address_pairs on the node's
// ports to remove IP from nodeToDel and add it to nodeToAdd and update the existing reservation port with the DeviceID
// of nodeToAdd. Additionally, if reservation port is missing MovePrivateIP will attempt to recreate it (this is a
// corner case and should not happen in normal operation).
func (o *OpenStack) MovePrivateIP(ip net.IP, nodeToAdd, nodeToDel *corev1.Node) error {
	if nodeToAdd == nil || nodeToDel == nil {
		return fmt.Errorf("invalid nil pointer provided for node when trying to move IP %s", ip.String())
	}

	// List all ports that are attached to this server.
	serverID, err := getNovaServerIDFromProviderID(nodeToDel.Spec.ProviderID)
	if err != nil {
		return err
	}
	serverPorts, err := o.listNovaServerPorts(serverID)
	if err != nil {
		return err
	}

	// Loop over all ports that are attached to this nova instance.
	for _, serverPort := range serverPorts {
		if isIPAddressAllowedOnNeutronPort(serverPort, ip) {
			if err = o.unallowIPAddressOnNeutronPort(serverPort.ID, ip); err != nil {
				return err
			}
		}
	}

	subnet, port, err := o.findAssignSubnetAndPort(ip, nodeToAdd)
	if err != nil {
		return err
	}

	// This call is to double-check if the reservation port exists and update its DeviceID. If reservation port is
	// missing it will be recreated.
	serverID, err = getNovaServerIDFromProviderID(nodeToAdd.Spec.ProviderID) // got to use new node's ProviderID now
	if err != nil {
		return err
	}
	_, err = o.reserveNeutronIPAddress(*subnet, ip, serverID)
	if err != nil {
		return err
	}

	if err = o.allowIPAddressOnNeutronPort(port.ID, ip); err != nil && !errors.Is(err, AlreadyExistingIPError) {
		return fmt.Errorf("could not allow IP address %s on port %s, err: %q", ip.String(), port.ID, err)
	}
	return nil
}

// ReleasePrivateIP attempts to release the IP address provided from the
// VM instance corresponding to the corev1.Node provided on the cloud the
// cluster is deployed on.
// ReleasePrivateIP must be idempotent, meaning that it will release
// all matching IP allowed_address_pairs for ports which are bound to this server.
// It also means that any unbound port on any network that is attached to this server -
// having the IP address to be released and matching the correct DeviceOwner and DeviceID
// containing the serverID will be deleted, as well.
// In OpenStack, it is possible to create different subnets with the exact same CIDR.
// These different subnets can then be assigned to ports on the same server.
// Hence, a server could be connected to several ports where the same IP is part of the
// allowed_address_pairs and where the same IP is reserved in neutron.
// NOTE: If the IP is non-existant: it returns an NonExistingIPError. The caller will
// likely want to ignore such an error and continue its normal operation.
func (o *OpenStack) ReleasePrivateIP(ip net.IP, node *corev1.Node) error {
	if node == nil {
		return fmt.Errorf("invalid nil pointer provided for node when trying to release IP %s", ip.String())
	}
	// List all ports that are attached to this server.
	serverID, err := getNovaServerIDFromProviderID(node.Spec.ProviderID)
	if err != nil {
		return err
	}
	serverPorts, err := o.listNovaServerPorts(serverID)
	if err != nil {
		return err
	}

	// Loop over all ports that are attached to this nova instance.
	isFound := false
	for _, serverPort := range serverPorts {
		// 1) Check if the IP address is part of the port's allowed_address_pairs.
		//   If that's the case:
		//     a) Remove the IP address from the port's allowed_address_pairs.
		// 2) Loop over all subnets that are attached to this port and check if the
		//    IP address is inside the subnet.
		//    a) Does the IP address fit inside the given subnet? This verification can safe
		//       needless calls to the neutron API.
		//       b) If so, check if the the IP address is inside the subnet.
		//          c) If so, release the IP allocation = delete the unbound neutron port inside the subnet.
		// 3) The IP address is not part of any attached subnet and it's not part of any allowed_address_pair
		// on any of the ports that are attached to the server. In that case, return a NonExistingIPError.
		// This is part of normal operation and upper layers should ignore this error and go on with normal
		// business logic.
		// Mind that if 1) fails and returns an error, then this method will return the error and
		// the operation will be retried. Should 2) fail and return an error, then this method will
		// return the error and the operation will be retried. The next time, the first operation
		// will be skipped and only the second operation will be run. In a worst case scenario,
		// if the last operation fails continuously, we will end up with a dangling unbound neutron
		// port that must be deleted manually.

		// 1) Check if the IP address is part of the port's allowed_address_pairs.
		if isIPAddressAllowedOnNeutronPort(serverPort, ip) {
			isFound = true
			// 1) a) Remove the IP address from the port's allowed_address_pairs.
			if err = o.unallowIPAddressOnNeutronPort(serverPort.ID, ip); err != nil {
				return err
			}
		}

		// 2) Get all subnets that are attached to this port's network and search for the neutron port
		// holding the IP address.
		subnets, err := o.getNeutronSubnetsForNetwork(serverPort.NetworkID)
		if err != nil {
			klog.Warningf("Could not find subnet information for network %s, err: %q", serverPort.NetworkID, err)
			continue
		}
		for _, s := range subnets {
			// 2) a) Does the IP address fit inside the given subnet? This verification can save
			// needless calls to the neutron API.
			_, ipnet, err := net.ParseCIDR(s.CIDR)
			if err != nil {
				klog.Warningf("Could not parse subnet information %s for network %s, err: %q",
					s.CIDR, serverPort.NetworkID, err)
				continue
			}
			if !ipnet.Contains(ip) {
				continue
			}
			// 2) b) Is the IP address on the subnet?
			// The DeviceOwner and DeviceID that this is a port that identify that this is managed by this plugin.
			if unboundPort, err := o.getNeutronPortWithIPAddressAndMachineID(s, ip, serverID); err == nil {
				isFound = true
				// 2) c)  Then, release the IP allocation = delete the unbound neutron port.
				if err = o.releaseNeutronIPAddress(*unboundPort, serverID); err != nil {
					return err
				}
				// We could break here now. However, go on here with the next subnet on this port
				// to cover the very odd case that 2 subnets with the same CIDR were attached to the same
				// node port and that for some reason both subnets had a port reservation with the correct
				// DeviceOwner/DeviceID.
				// break  // omitted on purpose
			}
		}
	}
	// 3) The IP address is not part of any attached subnet and it's not part of any allowed_address_pair
	// on any of the ports that are attached to the server.
	if !isFound {
		// This is part of normal operation.
		// Callers will likely ignore this and go on with normal operation.
		return NonExistingIPError
	}

	return nil
}

// GetNodeEgressIPConfiguration retrieves the egress IP configuration for
// the node, following the convention the cloud uses. This means
// specifically for OpenStack that the interface is keyed by the port's neutron UUID.
func (o *OpenStack) GetNodeEgressIPConfiguration(node *corev1.Node, cloudPrivateIPConfigs []*v1.CloudPrivateIPConfig) ([]*NodeEgressIPConfiguration, error) {
	if node == nil {
		return nil, fmt.Errorf("invalid nil pointer provided for node when trying to get node EgressIP configuration")
	}

	serverID, err := getNovaServerIDFromProviderID(node.Spec.ProviderID)
	if err != nil {
		return nil, err
	}
	serverPorts, err := o.listNovaServerPorts(serverID)
	if err != nil {
		return nil, err
	}

	// For each port, generate one entry in a temporary slice of NodeEgressIPConfigurations (to be filtered further
	// later).
	var configurations []*NodeEgressIPConfiguration
	for _, p := range serverPorts {
		// Retrieve configuration for this port.
		config, err := o.getNeutronPortNodeEgressIPConfiguration(p, cloudPrivateIPConfigs)
		if err != nil {
			return nil, err
		}
		configurations = append(configurations, config)
	}

	// Sanity check: Check the entire slice for duplicate CIDR assignments. Do not allow the same CIDR to be attached
	// to 2 different ports, otherwise we don't know where the EgressIP should be attached to.
	cidrs := make(map[string]struct{})
	for _, config := range configurations {
		if config.IFAddr.IPv4 != "" {
			if _, ok := cidrs[config.IFAddr.IPv4]; ok {
				return nil, fmt.Errorf("IPv4 CIDR '%s' is attached more than once to node %s", config.IFAddr.IPv4, node.Name)
			}
			cidrs[config.IFAddr.IPv4] = struct{}{}
		}
		if config.IFAddr.IPv6 != "" {
			if _, ok := cidrs[config.IFAddr.IPv6]; ok {
				return nil, fmt.Errorf("IPv6 CIDR '%s' is attached more than once to node %s", config.IFAddr.IPv6, node.Name)
			}
			cidrs[config.IFAddr.IPv6] = struct{}{}
		}
	}

	// We only allow EgressIPs on the MachineNetwork (the first node internal address for each IP address family).
	// Corner case: IPv4 InternalIP is on different interface than the IPv6 InternalIP. This should never happen in
	// OpenShift. If it does, we simply return the first matching config regardless.
	ipv4InternalIP, ipv6InternalIP := getNodeInternalAddrs(node)
	for _, config := range configurations {
		if config.IFAddr.IPv4 != "" {
			_, ipv4Net, ipv4Err := net.ParseCIDR(config.IFAddr.IPv4)
			if ipv4Err != nil {
				klog.Errorf("failure parsing IPv4 CIDR %q, err: %q", config.IFAddr.IPv4, ipv4Err)
			} else if ipv4Net.Contains(ipv4InternalIP) {
				return []*NodeEgressIPConfiguration{config}, nil
			}
		}
		if config.IFAddr.IPv6 != "" {
			_, ipv6Net, ipv6Err := net.ParseCIDR(config.IFAddr.IPv6)
			if ipv6Err != nil {
				klog.Errorf("failure parsing IPv6 CIDR %q, err: %q", config.IFAddr.IPv6, ipv6Err)
			} else if ipv6Net.Contains(ipv6InternalIP) {
				return []*NodeEgressIPConfiguration{config}, nil
			}
		}
		klog.Infof("Skipping interface config. Neither the IPv4 nor the IPv6 network contain the first InternalIP "+
			"of the node. Interface config: %q, IPv4 InternalIP: %q, IPv6 InternalIP: %q",
			config, ipv4InternalIP, ipv6InternalIP)
	}

	return nil, fmt.Errorf("no suitable interface configurations found")
}

// getNeutronPortNodeEgressIPConfiguration renders the NeutronPortNodeEgressIPConfiguration for a given port.
// The interface is keyed by a neutron UUID.
// If multiple IPv4 repectively multiple IPv6 subnets are attached to the same port, throw an error.
// The IP capacity is per port. The definition of this field does unfortunately not play very well with the way how
// neutron operates as there is no such thing as a per port quota or limit. Therefore we set a ceiling of
// `openstackMaxCapacity`. The number of unique IP addresses in allowed_address_pair and fixed_ips is subtracted from
// that ceiling.
func (o *OpenStack) getNeutronPortNodeEgressIPConfiguration(p neutronports.Port, cloudPrivateIPConfigs []*v1.CloudPrivateIPConfig) (*NodeEgressIPConfiguration, error) {
	var ipv4, ipv6 string
	var err error
	var ip net.IP
	var ipnet *net.IPNet

	// Retrieve all subnets for this port.
	subnets, err := o.getNeutronSubnetsForNetwork(p.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("could not find subnet information for network %s, err: %q", p.NetworkID, err)
	}

	// Loop over all subnets. OpenStack potentially has several IPv4 or IPv6 subnets per port, but the
	// CloudPrivateIPConfig expects only a single subnet of each address family per port. Throw an error
	// in such a case.
	var cloudPrivateIPsCount int
	for _, s := range subnets {
		// Parse CIDR information into ip and ipnet.
		ip, ipnet, err = net.ParseCIDR(s.CIDR)
		if err != nil {
			return nil, fmt.Errorf("could not parse subnet information %s for network %s, err: %q",
				s.CIDR, p.NetworkID, err)
		}
		// For IPv4 and IPv6, calculate the capacity.
		if utilnet.IsIPv4(ip) {
			if ipv4 != "" {
				return nil, fmt.Errorf("found multiple IPv4 subnets attached to port %s, this is not supported", p.ID)
			}
			ipv4 = ipnet.String()
		} else {
			if ipv6 != "" {
				return nil, fmt.Errorf("found multiple IPv6 subnets attached to port %s, this is not supported", p.ID)
			}
			ipv6 = ipnet.String()
		}
		// Loop over all cloudPrivateIPConfigs and check if they are part of this ipnet.
		// If the IP is contained in the ipnet, increase cloudPrivateIPsCount.
		for _, cpic := range cloudPrivateIPConfigs {
			cip, _, err := cloudprivateipconfig.NameToIP(cpic.Name)
			if err != nil {
				return nil, err
			}
			if ipnet.Contains(cip) {
				cloudPrivateIPsCount++
			}
		}
	}

	c := openstackMaxCapacity + cloudPrivateIPsCount - len(p.AllowedAddressPairs)
	return &NodeEgressIPConfiguration{
		Interface: p.ID,
		IFAddr: ifAddr{
			IPv4: ipv4,
			IPv6: ipv6,
		},
		Capacity: capacity{
			IP: c,
		},
	}, nil
}

// reserveNeutronIPAddress creates a new unattached neutron port with the given IP on
// the given subnet. This will serve as our IPAM as it is impossible to create 2 ports
// with the same IP on the same subnet. The created port will be identified with a custom
// DeviceID and DeviceOwner.
// If create call returns error we'll check if it's 409 Conflict. If so, we'll try to fetch
// list of ports with matching IP and DeviceOwner on that subnet. In case of success, we'll
// assume this is an exisitng reservation port for that EgressIP, check if DeviceID needs to
// be updated, update it if so and return that already existing port.
// NOTE: We are not using tags. According to the neutron API, it's possible to add a tag when creating
// a port. But gophercloud does not allow us to do that and we must use a 2 step process (create port, then
// add tag).
func (o *OpenStack) reserveNeutronIPAddress(s neutronsubnets.Subnet, ip net.IP, serverID string) (*neutronports.Port, error) {
	if serverID == "" || len(serverID) > 254-len(egressIPTag) {
		return nil, fmt.Errorf("cannot assign IP address %s on subnet %s with an invalid serverID '%s'", ip.String(), s.ID, serverID)
	}

	// Create the port.
	expectedDeviceID := generateDeviceID(serverID)
	opts := neutronports.CreateOpts{
		NetworkID: s.NetworkID,
		FixedIPs: []neutronports.IP{
			{
				SubnetID:  s.ID,
				IPAddress: ip.String(),
			},
		},
		DeviceOwner: egressIPTag,
		DeviceID:    expectedDeviceID,
		Name:        fmt.Sprintf("egressip-%s", ip.String()),
	}
	p, err := neutronports.Create(context.TODO(), o.neutronClient, opts).Extract()

	if err != nil {
		// Let's check if error suggests that port with that IP already exists in that subnet.
		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			klog.Infof("Got conflict when trying to create reservation port with IP %s. Checking for an existing "+
				"reservation port", ip.String())
			// If so, let's get the port and check if it's our reservation port. It's possible we've created it earlier.
			// It's also possible user configured a taken range, we should error out in such case.
			opts := neutronports.ListOpts{
				// {SubnetID: <id>, IPAddress: <ip>} would generate a query like
				// fixed_ips=subnet_id%3D<id>,ip_address%3D<ip>. Instead we need
				// fixed_ips=subnet_id%3D<id>&fixed_ips=ip_address%3D<ip>, hence we use
				// {SubnetID: s.ID}, {IPAddress: ip.String()}
				FixedIPs:    []neutronports.FixedIPOpts{{SubnetID: s.ID}, {IPAddress: ip.String()}},
				DeviceOwner: egressIPTag,
			}
			page, err := neutronports.List(o.neutronClient, opts).AllPages(context.TODO())
			if err != nil {
				return nil, err
			}
			ports, err := neutronports.ExtractPorts(page)
			if err != nil {
				return nil, err
			}
			if len(ports) > 1 {
				// This is unexpected, Neutron should not allow multiple ports with the same IP
				// in one subnet
				return p, fmt.Errorf(
					"bogus result from Neutron, multiple ports with IP %s in subnet %s", ip.String(), s.ID)
			} else if len(ports) == 1 {
				// We've got our port, we'll return it, but first let's check if DeviceOwner is set correctly.
				p = &ports[0]
				klog.Infof("Found reservation port %s for IP %s. Reusing it", p.ID, ip.String())
				if p.DeviceID != expectedDeviceID {
					// If not, we got to update it. We intend to replace the result with updated representation of the port.
					p, err = neutronports.Update(context.TODO(), o.neutronClient, p.ID, neutronports.UpdateOpts{DeviceID: &expectedDeviceID}).Extract()
					if err != nil {
						return nil, err
					}
					klog.Infof("Port %s updated with DeviceID %s", p.ID, expectedDeviceID)
				}
				return p, nil
			}
			// The only case left is 0 results, which indicate that the port that is using that IP is not ours
			// (DeviceOwner doesn't match). So let's log a warning and return the 409 error as a legitimate indicator
			// of something else using the IP we intended to use. Most likely it's a configuration issue.
			klog.Errorf("Conflict when creating a reservation port with IP %s on subnet %s. Most likely the IP is "+
				"already in use on the subnet", ip.String(), s.ID)
		}
		return nil, err
	}

	return p, nil
}

// releaseNeutronIPAddress deletes an unattached neutron port with the given IP on
// the given subnet. It also looks at the DeviceOwner and DeviceID and makes sure that the port matches.
func (o *OpenStack) releaseNeutronIPAddress(port neutronports.Port, serverID string) error {
	if serverID == "" || len(serverID) > 254-len(egressIPTag) {
		return fmt.Errorf("cannot release neutron port %s. An invalid serverID was provided '%s'", port.ID, serverID)
	}

	if port.DeviceOwner != egressIPTag || port.DeviceID != generateDeviceID(serverID) {
		return fmt.Errorf("cannot delete port '%s' for node with serverID '%s', it belongs to another device owner (%s) and/or device (%s)",
			port.ID, serverID, port.DeviceOwner, port.DeviceID)
	}

	return neutronports.Delete(context.TODO(), o.neutronClient, port.ID).ExtractErr()
}

// getNeutronPortWithIPAddressAndMachineID gets the neutron port with the given IP on the given subnet and
// with the correct DeviceID containing the serverID.
func (o *OpenStack) getNeutronPortWithIPAddressAndMachineID(s neutronsubnets.Subnet, ip net.IP, serverID string) (*neutronports.Port, error) {
	if serverID == "" || len(serverID) > 254-len(egressIPTag) {
		return nil, fmt.Errorf("cannot retrieve neutron port with IP address %s on subnet %s with an invalid serverID '%s'", ip.String(), s.ID, serverID)
	}

	var ports []neutronports.Port

	// Loop through all ports on network NetworkID.
	// The following filter does not work, therefore move this logic to the loop below.
	/* FixedIPs: []neutronports.FixedIPOpts{
		{
			SubnetID:  s.ID,
			IPAddress: ip.String(),
		},
	}, */
	// For each port on the network, loop through the ports FixedIPs list and check if
	// SubnetID and IPAddress match with what we're looking for.
	// If so, stop searching the list of ports.
	portListOpts := neutronports.ListOpts{
		NetworkID: s.NetworkID,
	}
	pager := neutronports.List(o.neutronClient, portListOpts)
	err := pager.EachPage(context.TODO(), func(ctx context.Context, page pagination.Page) (bool, error) {
		portList, err := neutronports.ExtractPorts(page)
		if err != nil {
			// Something is wrong, stop searching and throw an error.
			return false, err
		}

		for _, p := range portList {
			if p.DeviceOwner != egressIPTag || p.DeviceID != generateDeviceID(serverID) {
				continue
			}
			for _, fip := range p.FixedIPs {
				if fip.SubnetID == s.ID && fip.IPAddress == ip.String() {
					ports = append(ports, p)
					// End the search.
					return false, nil
				}
			}
		}
		// Get the next list of ports from the pager.
		return true, nil
	})
	if err != nil {
		return nil, err
	}

	if len(ports) != 1 {
		return nil, fmt.Errorf("expected to find a single port, instead found %d ports", len(ports))
	}
	return &ports[0], nil
}

// allowIPAddressOnNeutronPort adds the specified IP address to the port's allowed_address_pairs.
func (o *OpenStack) allowIPAddressOnNeutronPort(portID string, ip net.IP) error {
	// Needed due to neutron bug  https://bugzilla.redhat.com/show_bug.cgi?id=2119199.
	klog.Infof("Getting port lock for portID %s and IP %s", portID, ip.String())
	portLock := o.getLockForPort(portID)
	portLock.Lock()
	defer portLock.Unlock()

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Always get the most recent copy of this port.
		p, err := neutronports.Get(context.TODO(), o.neutronClient, portID).Extract()
		if err != nil {
			return err
		}

		// Sanity check to see if the IP is already inside the port's allowed_address_pairs.
		if isIPAddressAllowedOnNeutronPort(*p, ip) {
			return AlreadyExistingIPError
		}

		// Update the port's allowed_address_pairs by appending to it.
		// According to the neutron API:
		// "While the ip_address is required, the mac_address will be taken from the port if not specified."
		// https://docs.openstack.org/api-ref/network/v2/index.html?expanded=update-port-detail
		allowedPairs := append(p.AllowedAddressPairs, neutronports.AddressPair{
			IPAddress: ip.String(),
		})
		// Update the port. Provide the revision number to make use of neutron's If-Match
		// header. If the port has received another update since we last retrieved it, the
		// revision number won't match and neutron will return a "RevisionNumberConstraintFailed"
		// error message.
		opts := neutronports.UpdateOpts{
			AllowedAddressPairs: &allowedPairs,
			RevisionNumber:      &p.RevisionNumber,
		}
		_, err = neutronports.Update(context.TODO(), o.neutronClient, p.ID, opts).Extract()

		// If the update yielded an error of type "RevisionNumberConstraintFailed", then create a
		// Conflict error. RetryOnConflict will react to this and will repeat the entire operation.
		if err != nil && strings.Contains(err.Error(), "RevisionNumberConstraintFailed") {
			return &apierrors.StatusError{
				ErrStatus: metav1.Status{
					Message: err.Error(),
					Reason:  metav1.StatusReasonConflict,
					Code:    http.StatusConflict,
				},
			}
		}

		// Any other error or nil, return.
		return err
	})
}

// unallowIPAddressOnNeutronPort removes the specified IP address from the port's allowed_address_pairs.
func (o *OpenStack) unallowIPAddressOnNeutronPort(portID string, ip net.IP) error {
	// Needed due to neutron bug  https://bugzilla.redhat.com/show_bug.cgi?id=2119199.
	klog.Infof("Getting port lock for portID %s and IP %s", portID, ip.String())
	portLock := o.getLockForPort(portID)
	portLock.Lock()
	defer portLock.Unlock()

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Always get the most recent copy of this port.
		p, err := neutronports.Get(context.TODO(), o.neutronClient, portID).Extract()
		if err != nil {
			return err
		}

		// Sanity check to see if the IP was already removed from the port's allowed_address_pairs.
		// If it's still present, return an error that higher layers should act upon.
		if !isIPAddressAllowedOnNeutronPort(*p, ip) {
			return fmt.Errorf("IP address '%s' is not allowed on port '%s', cannot unallow it", ip, p.ID)
		}

		// Build a slice that contains all allowed pairs other than
		// the one that we want to remove.
		var allowedPairs []neutronports.AddressPair
		for _, aap := range p.AllowedAddressPairs {
			if ip.Equal(net.ParseIP(aap.IPAddress)) {
				continue
			}
			allowedPairs = append(allowedPairs, aap)
		}
		// Update the port. Provide the revision number to make use of neutron's If-Match
		// header. If the port has received another update since we last retrieved it, the
		// revision number won't match and neutron will return a "RevisionNumberConstraintFailed"
		// error message.
		opts := neutronports.UpdateOpts{
			AllowedAddressPairs: &allowedPairs,
			RevisionNumber:      &p.RevisionNumber,
		}
		_, err = neutronports.Update(context.TODO(), o.neutronClient, p.ID, opts).Extract()

		// If the update yielded an error of type "RevisionNumberConstraintFailed", then create a
		// Conflict error. RetryOnConflict will react to this and will repeat the entire operation.
		if err != nil && strings.Contains(err.Error(), "RevisionNumberConstraintFailed") {
			return &apierrors.StatusError{
				ErrStatus: metav1.Status{
					Message: err.Error(),
					Reason:  metav1.StatusReasonConflict,
					Code:    http.StatusConflict,
				},
			}
		}

		// Any other error or nil, return.
		return err
	})
}

// getNeutronSubnetsForNetwork returns all subnets that belong to the given network with
// ID <networkID>.
func (o *OpenStack) getNeutronSubnetsForNetwork(networkID string) ([]neutronsubnets.Subnet, error) {
	var subnets []neutronsubnets.Subnet

	if _, err := uuid.Parse(networkID); err != nil {
		return nil, fmt.Errorf("networkID '%s' is not a valid UUID", networkID)
	}

	opts := neutronsubnets.ListOpts{NetworkID: networkID}
	pager := neutronsubnets.List(o.neutronClient, opts)
	err := pager.EachPage(context.TODO(), func(ctx context.Context, page pagination.Page) (bool, error) {
		subnetList, err := neutronsubnets.ExtractSubnets(page)
		if err != nil {
			return false, err
		}
		subnets = append(subnets, subnetList...)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return subnets, nil
}

// getNovaServer gets the nova server with ID == <serverID>.
func (o *OpenStack) getNovaServer(serverID string) (*novaservers.Server, error) {
	if _, err := uuid.Parse(serverID); err != nil {
		return nil, fmt.Errorf("serverID '%s' is not a valid UUID", serverID)
	}

	server, err := novaservers.Get(context.TODO(), o.novaClient, serverID).Extract()
	if err != nil {
		return nil, err
	}
	return server, nil
}

// listNovaServerPorts lists all ports that are attached to the provided nova server
// with ID == <serverID>.
func (o *OpenStack) listNovaServerPorts(serverID string) ([]neutronports.Port, error) {
	var err error
	var serverPorts []neutronports.Port

	if _, err := uuid.Parse(serverID); err != nil {
		return nil, fmt.Errorf("serverID '%s' is not a valid UUID", serverID)
	}

	portListOpts := neutronports.ListOpts{
		DeviceID: serverID,
	}

	pager := neutronports.List(o.neutronClient, portListOpts)
	err = pager.EachPage(context.TODO(), func(ctx context.Context, page pagination.Page) (bool, error) {
		portList, err := neutronports.ExtractPorts(page)
		if err != nil {
			return false, err
		}
		for _, port := range portList {
			if novaDeviceOwnerRegex.Match([]byte(port.DeviceOwner)) {
				serverPorts = append(serverPorts, port)
			}
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return serverPorts, nil
}

// isIPAddressAllowedOnNeutronPort returns true if the given IP address can be found inside the
// list of allowed_address_pairs for this port.
func isIPAddressAllowedOnNeutronPort(p neutronports.Port, ip net.IP) bool {
	for _, aap := range p.AllowedAddressPairs {
		if ip.Equal(net.ParseIP(aap.IPAddress)) {
			return true
		}

	}
	return false
}

// getNovaServerIDFromProviderID extracts the nova server ID from the given providerID.
func getNovaServerIDFromProviderID(providerID string) (string, error) {
	serverID := strings.TrimPrefix(providerID, openstackProviderPrefix)
	if serverID == providerID {
		return "", UnexpectedURIError(fmt.Sprintf("%s; the provider ID does not contain expected prefix %s",
			providerID, openstackProviderPrefix))
	}
	if _, err := uuid.Parse(serverID); err != nil {
		return "", UnexpectedURIError(fmt.Sprintf("%s; error parsing UUID %q: %q",
			providerID, serverID, err.Error()))
	}
	return serverID, nil
}

// generateDeviceID is a tiny helper to allow us to work around https://bugzilla.redhat.com/show_bug.cgi?id=2109162.
func generateDeviceID(serverID string) string {
	return fmt.Sprintf("%s_%s", egressIPTag, serverID)
}

// getLockForPort returns a sync.Mutex for port with portID.
func (o *OpenStack) getLockForPort(portID string) *sync.Mutex {
	o.portLockMapMutex.Lock()
	defer o.portLockMapMutex.Unlock()

	if o.portLockMap == nil {
		o.portLockMap = make(map[string]*sync.Mutex)
	}
	if _, ok := o.portLockMap[portID]; !ok {
		o.portLockMap[portID] = &sync.Mutex{}
	}
	return o.portLockMap[portID]
}

// getNodeInternalAddrs returns the first IPv4 and/or IPv6 InternalIP defined
// for the node. On certain cloud providers the egress IP will be added to
// the list of node IPs as an InternalIP address. Node IPs are ordered,
// meaning the egress IP will never be first in this list.
// Copied from :
// https://github.com/ovn-org/ovn-kubernetes/blob/2cceeebd4f66ee8dd9e683551b883e549b5cd7da/go-controller/pkg/ovn/egressip.go#L2580
func getNodeInternalAddrs(node *corev1.Node) (net.IP, net.IP) {
	var v4Addr, v6Addr net.IP
	for _, nodeAddr := range node.Status.Addresses {
		if nodeAddr.Type == corev1.NodeInternalIP {
			ip := net.ParseIP(nodeAddr.Address)
			if !utilnet.IsIPv6(ip) && v4Addr == nil {
				v4Addr = ip
			} else if utilnet.IsIPv6(ip) && v6Addr == nil {
				v6Addr = ip
			}
		}
	}
	return v4Addr, v6Addr
}
