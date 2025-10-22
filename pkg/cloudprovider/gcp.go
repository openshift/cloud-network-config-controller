package cloudprovider

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	google "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
)

const (
	PlatformTypeGCP = "GCP"
	// GCP hard-codes the amount of alias IPs that can be assigned to a NIC to 100 -
	// independently of IP family, so we need to retrieve the amount of alias IPs
	// already in use by default and subtract from 100. See:
	// https://cloud.google.com/vpc/docs/quota#per_instance .
	defaultGCPPrivateIPCapacity = 100
	// default universe domain
	// https://github.com/openshift/cloud-network-config-controller/blob/dc255162b1442a1b85aa0b2ab37ed63245857476/vendor/golang.org/x/oauth2/google/default.go#L25
	defaultUniverseDomain = "googleapis.com"
)

// GCP implements the API wrapper for talking
// to the GCP cloud API
type GCP struct {
	CloudProvider
	client *google.Service
}

func (g *GCP) initCredentials() (err error) {
	secret, err := g.readSecretData("service_account.json")
	if err != nil {
		return err
	}
	secretData := []byte(secret)

	// If the UniverseDomain is not set, the client will try to retrieve it from the metadata server.
	// https://github.com/openshift/cloud-network-config-controller/blob/dc255162b1442a1b85aa0b2ab37ed63245857476/vendor/golang.org/x/oauth2/google/default.go#L77
	// This won't work in OpenShift because the CNCC pod cannot access the metadata service IP address (we block
	// the access to 169.254.169.254 from cluster-networked pods).
	// Set the UniverseDomain to the default value explicitly.
	if !strings.Contains(secret, "universe_domain") {
		// Using option.WithUniverseDomain() doesn't work because the value is not passed to the client.
		// Modify the credentials json directly instead
		var jsonMap map[string]interface{}
		err := json.Unmarshal(secretData, &jsonMap)
		if err != nil {
			return fmt.Errorf("error: cannot decode google client secret, err: %v", err)
		}
		jsonMap["universe_domain"] = defaultUniverseDomain
		secretData, err = json.Marshal(&jsonMap)
		if err != nil {
			return fmt.Errorf("error: cannot encode google client secret, err: %v", err)
		}
	}

	opts := []option.ClientOption{
		option.WithCredentialsJSON(secretData),
		option.WithUserAgent(UserAgent),
	}
	if g.cfg.APIOverride != "" {
		opts = append(opts, option.WithEndpoint(g.cfg.APIOverride))
	}

	g.client, err = google.NewService(g.ctx, opts...)
	if err != nil {
		return fmt.Errorf("error: cannot initialize google client, err: %v", err)
	}
	return nil
}

// AssignPrivateIP adds the IP to the associated instance's IP aliases.
// Important: GCP IP aliases can come in all forms, i.e: if you add 10.0.32.25
// GCP can return 10.0.32.25/32 or 10.0.32.25 - we thus need to check for both
// when validating that the IP provided doesn't already exist
func (g *GCP) AssignPrivateIP(ip net.IP, node *corev1.Node) error {
	project, zone, instance, err := g.getInstance(node)
	if err != nil {
		return err
	}
	networkInterfaces, err := g.getNetworkInterfaces(instance)
	if err != nil {
		return err
	}
	// Perform the operation against the first interface listed following the
	// order GCP specifies.
	networkInterface := networkInterfaces[0]
	for _, aliasIPRange := range networkInterface.AliasIpRanges {
		if assignedIP := net.ParseIP(aliasIPRange.IpCidrRange); assignedIP.Equal(ip) {
			return AlreadyExistingIPError
		}
		if _, assignedSubnet, err := net.ParseCIDR(aliasIPRange.IpCidrRange); err == nil && assignedSubnet.Contains(ip) {
			return AlreadyExistingIPError
		}
	}
	networkInterface.AliasIpRanges = append(networkInterface.AliasIpRanges, &google.AliasIpRange{
		IpCidrRange: ip.String(),
	})
	operation, err := g.client.Instances.UpdateNetworkInterface(project, zone, instance.Name, networkInterface.Name, networkInterface).Do()
	if err != nil {
		return err
	}
	return g.waitForCompletion(project, zone, operation.Name)
}

// ReleasePrivateIP removes the IP alias from the associated instance.
// Important: GCP IP aliases can come in all forms, i.e: if you add 10.0.32.25
// GCP can return 10.0.32.25/32 or 10.0.32.25
func (g *GCP) ReleasePrivateIP(ip net.IP, node *corev1.Node) error {
	project, zone, instance, err := g.getInstance(node)
	if err != nil {
		return err
	}

	networkInterfaces, err := g.getNetworkInterfaces(instance)
	if err != nil {
		return err
	}
	// Perform the operation against the first interface listed following the
	// order GCP specifies.
	networkInterface := networkInterfaces[0]
	ipAssigned := false
	var keepAliases []*google.AliasIpRange
	for _, aliasIPRange := range networkInterface.AliasIpRanges {
		if assignedIP := net.ParseIP(aliasIPRange.IpCidrRange); assignedIP != nil && !assignedIP.Equal(ip) {
			keepAliases = append(keepAliases, aliasIPRange)
			continue
		} else if assignedIP != nil && assignedIP.Equal(ip) {
			ipAssigned = true
			continue
		}
		if assignedIP, _, err := net.ParseCIDR(aliasIPRange.IpCidrRange); err == nil && !assignedIP.Equal(ip) {
			keepAliases = append(keepAliases, aliasIPRange)
		} else if err == nil && assignedIP.Equal(ip) {
			ipAssigned = true
		}
	}
	if !ipAssigned {
		return NonExistingIPError
	}
	networkInterface.AliasIpRanges = keepAliases
	// make sure that AliasIpRanges is always sent in the request, even if it is empty
	networkInterface.ForceSendFields = append(networkInterface.ForceSendFields, "AliasIpRanges")
	operation, err := g.client.Instances.UpdateNetworkInterface(project, zone, instance.Name, networkInterface.Name, networkInterface).Do()
	if err != nil {
		return err
	}
	return g.waitForCompletion(project, zone, operation.Name)
}

func (g *GCP) GetNodeEgressIPConfiguration(node *corev1.Node, cpicIPs sets.Set[string]) ([]*NodeEgressIPConfiguration, error) {
	_, _, instance, err := g.getInstance(node)
	if err != nil {
		return nil, fmt.Errorf("error retrieving instance associated with node, err: %v", err)
	}
	networkInterfaces, err := g.getNetworkInterfaces(instance)
	if err != nil {
		return nil, err
	}
	// Perform the operation against the first interface listed following the
	// order GCP specifies.
	for _, networkInterface := range networkInterfaces {
		config := &NodeEgressIPConfiguration{
			Interface: networkInterface.Name,
		}

		v4Subnet, v6Subnet, err := g.getSubnet(networkInterface)
		if err != nil {
			return nil, fmt.Errorf("error retrieving the network interface subnets, err: %v", err)
		}
		config.IFAddr = ifAddr{}
		if v4Subnet != nil {
			config.IFAddr.IPv4 = v4Subnet.String()
		}
		if v6Subnet != nil {
			config.IFAddr.IPv6 = v6Subnet.String()
		}
		config.Capacity = capacity{
			// IPv4 and IPv6 fields not used by GCP (uses IP-family-agnostic capacity)
			IP: ptr.To(g.getCapacity(networkInterface, cpicIPs)),
		}
		return []*NodeEgressIPConfiguration{config}, nil //nolint:staticcheck
	}
	return nil, nil
}

// The GCP zone operations API call. All GCP infrastructure modifications are
// assigned a unique operation ID and are queued in a global/zone operations
// queue. In the case of assignments of private IP addresses to instances, the
// operation is added to the zone operations queue. Hence we need to keep the
// opName and the zone the instance lives in.
func (g *GCP) waitForCompletion(project, zone, opName string) error {
	op, err := g.client.ZoneOperations.Wait(project, zone, opName).Do()
	if err != nil {
		return err
	}

	if op.Error != nil {
		data, err := op.Error.MarshalJSON()
		if err != nil {
			return fmt.Errorf("failed marshaling error %v", op.Error)
		}
		return fmt.Errorf("%s", string(data))
	}
	return nil
}

func (g *GCP) getSubnet(networkInterface *google.NetworkInterface) (*net.IPNet, *net.IPNet, error) {
	var v4Subnet, v6Subnet *net.IPNet
	project, region, subnet, err := g.parseSubnet(networkInterface.Subnetwork)

	if err != nil {
		return nil, nil, err
	}

	subnetResult, err := g.client.Subnetworks.Get(project, region, subnet).Do()
	if err != nil {
		return nil, nil, err
	}
	if subnetResult.IpCidrRange != "" {
		_, v4Subnet, _ = net.ParseCIDR(subnetResult.IpCidrRange)
	}
	if subnetResult.Ipv6CidrRange != "" {
		_, v6Subnet, _ = net.ParseCIDR(subnetResult.Ipv6CidrRange)
	}
	return v4Subnet, v6Subnet, nil
}

// Note: there is also a global "alias IP per VPC quota", but OpenShift clusters on
// GCP seem to have that value defined to 15,000. So we can skip that.
func (g *GCP) getCapacity(networkInterface *google.NetworkInterface, cpicIPs sets.Set[string]) int {
	currentIPUsage := 0
	for _, aliasIPRange := range networkInterface.AliasIpRanges {
		var aliasIP net.IP
		if assignedIP := net.ParseIP(aliasIPRange.IpCidrRange); assignedIP != nil {
			aliasIP = assignedIP
		} else if _, assignedSubnet, err := net.ParseCIDR(aliasIPRange.IpCidrRange); err == nil {
			aliasIP = assignedSubnet.IP
		}

		if aliasIP != nil && !cpicIPs.Has(aliasIP.String()) {
			currentIPUsage++
		}
	}

	return defaultGCPPrivateIPCapacity - currentIPUsage
}

// getInstance retrieves the GCP instance referred by the Node object.
// returns the project and zone name as well.
func (g *GCP) getInstance(node *corev1.Node) (string, string, *google.Instance, error) {
	project, zone, instance, err := splitGCPNode(node)
	if err != nil {
		return "", "", nil, err
	}

	i, err := g.client.Instances.Get(project, zone, instance).Do()
	if err != nil {
		return "", "", nil, err
	}
	return project, zone, i, nil
}

func (g *GCP) getNetworkInterfaces(instance *google.Instance) ([]*google.NetworkInterface, error) {
	if len(instance.NetworkInterfaces) == 0 {
		return nil, NoNetworkInterfaceError
	}
	if instance.NetworkInterfaces[0] == nil {
		return nil, NoNetworkInterfaceError
	}
	return instance.NetworkInterfaces, nil
}

//	 This is what the node's providerID looks like on GCP
//		spec:
//	  providerID: gce://openshift-gce-devel-ci/us-east1-b/ci-ln-pvr3lyb-f76d1-6w8mm-master-0
//	 i.e: projectID/zone/instanceName
//
// split out and return these components
func splitGCPNode(node *corev1.Node) (project, zone, instance string, err error) {
	u, err := url.Parse(node.Spec.ProviderID)
	if err != nil {
		err = fmt.Errorf("failed to parse node %s provider id %s: %w", node.Name, node.Spec.ProviderID, err)
		return
	}
	parts := strings.SplitN(u.Path, "/", 3)
	if len(parts) != 3 {
		err = fmt.Errorf("failed to parse node %s provider id %s: expected two path components", node.Name, node.Spec.ProviderID)
		return
	}

	project = u.Host
	zone = parts[1]
	instance = parts[2]
	return
}

// GCP Subnet URLs are defined as:
// - https://www.googleapis.com/compute/v1/projects/project/regions/region/subnetworks/subnetwork
// OR
// - regions/region/subnetworks/subnetwork
func (g *GCP) parseSubnet(subnetURL string) (string, string, string, error) {
	subnetURLParts := strings.Split(subnetURL, "/")
	if len(subnetURLParts) != 11 {
		return "", "", "", UnexpectedURIError(subnetURL)
	}
	return subnetURLParts[len(subnetURLParts)-5], subnetURLParts[len(subnetURLParts)-3],
		subnetURLParts[len(subnetURLParts)-1], nil
}
