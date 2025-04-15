package cloudprovider

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"k8s.io/utils/ptr"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/go-autorest/autorest/azure"
	azureapi "github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/msi-dataplane/pkg/dataplane"
	v1 "github.com/openshift/api/cloudnetwork/v1"
	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

const (
	PlatformTypeAzure = "Azure"
	// Azure defines a private IP assignment limit of 256 addresses per NIC and
	// 65,536 per virtual network see:
	// https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits?toc=/azure/virtual-network/toc.json#networking-limits
	defaultAzurePrivateIPCapacity = 256
	// defaultAzureOperationTimeout is the timeout for all Azure operations
	defaultAzureOperationTimeout = 10 * time.Second
)

// Azure implements the API wrapper for talking
// to the Azure cloud API
type Azure struct {
	CloudProvider
	platformStatus               *configv1.AzurePlatformStatus
	resourceGroup                string
	env                          azure.Environment
	vmClient                     *armcompute.VirtualMachinesClient
	virtualNetworkClient         *armnetwork.VirtualNetworksClient
	networkClient                *armnetwork.InterfacesClient
	backendAddressPoolClient     *armnetwork.LoadBalancerBackendAddressPoolsClient
	nodeMapLock                  sync.Mutex
	nodeLockMap                  map[string]*sync.Mutex
	azureWorkloadIdentityEnabled bool
}

type azureCredentialsConfig struct {
	clientID       string
	tenantID       string
	subscriptionID string
	resourceGroup  string
	clientSecret   string
	tokenFile      string
}

// readAzureCredentialsConfig reads the azure credentials' configuration.
// Some of the returned fields can be empty, and it is up to the caller to ensure that all the required values are set.
func (a *Azure) readAzureCredentialsConfig() (*azureCredentialsConfig, error) {
	var cfg azureCredentialsConfig
	var err error

	cfg.clientID, err = a.readSecretData("azure_client_id")
	if err != nil {
		klog.Infof("azure_client_id not found in the secret: %v, falling back to AZURE_CLIENT_ID env", err)
		cfg.clientID = os.Getenv("AZURE_CLIENT_ID")
	}

	cfg.tenantID, err = a.readSecretData("azure_tenant_id")
	if err != nil {
		klog.Infof("azure_tenant_id not found in the secret: %v, falling back to AZURE_TENANT_ID env", err)
		cfg.tenantID = os.Getenv("AZURE_TENANT_ID")
	}

	cfg.clientSecret, err = a.readSecretData("azure_client_secret")
	if err != nil {
		klog.Infof("azure_client_secret not found in the secret: %v, falling back to AZURE_CLIENT_SECRET env", err)
		cfg.clientSecret = os.Getenv("AZURE_CLIENT_SECRET")
	}

	cfg.tokenFile, err = a.readSecretData("azure_federated_token_file")
	if err != nil {
		klog.Infof("azure_federated_token_file not found in the secret: %v, falling back to AZURE_FEDERATED_TOKEN_FILE env", err)
		cfg.tokenFile = os.Getenv("AZURE_FEDERATED_TOKEN_FILE")

		if strings.TrimSpace(cfg.tokenFile) == "" {
			cfg.tokenFile = "/var/run/secrets/openshift/serviceaccount/token"
		}
	}

	cfg.subscriptionID, err = a.readSecretData("azure_subscription_id")
	if err != nil {
		return nil, fmt.Errorf("azure_subscription_id not found in the secret: %v", err)
	}

	cfg.resourceGroup, err = a.readSecretData("azure_resourcegroup")
	if err != nil {
		if a.platformStatus != nil && len(strings.TrimSpace(a.platformStatus.ResourceGroupName)) > 0 {
			klog.Infof("Attempting to use resource group from cluster infrastructure because azure_resourcegroup is missing")
			cfg.resourceGroup = strings.TrimSpace(a.platformStatus.ResourceGroupName)
		} else {
			return nil, fmt.Errorf("azure_resourcegroup not found in the platform status and the secret: %v", err)
		}
	}

	return &cfg, nil
}
func (a *Azure) initCredentials() error {
	cfg, err := a.readAzureCredentialsConfig()
	if err != nil {
		return err
	}

	a.resourceGroup = cfg.resourceGroup

	// Pick the Azure "Environment", which is just a named set of API endpoints.
	if a.cfg.APIOverride != "" {
		a.env, err = azure.EnvironmentFromURL(a.cfg.APIOverride)
	} else {
		name := a.cfg.AzureEnvironment
		if name == "" {
			name = "AzurePublicCloud"
		}
		a.env, err = azure.EnvironmentFromName(name)
	}
	if err != nil {
		return fmt.Errorf("failed to initialize Azure environment: %w", err)
	}

	cred, cloudConfig, err := a.getAzureCredentials(a.env, cfg)
	if err != nil {
		return err
	}

	options := &arm.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Cloud: cloudConfig,
		},
	}

	a.vmClient, err = armcompute.NewVirtualMachinesClient(cfg.subscriptionID, cred, options)
	if err != nil {
		return fmt.Errorf("failed to initialize new VirtualMachinesClient: %w", err)
	}

	a.networkClient, err = armnetwork.NewInterfacesClient(cfg.subscriptionID, cred, options)
	if err != nil {
		return fmt.Errorf("failed to initialize new InterfacesClient: %w", err)
	}

	a.virtualNetworkClient, err = armnetwork.NewVirtualNetworksClient(cfg.subscriptionID, cred, options)
	if err != nil {
		return fmt.Errorf("failed to initialize new VirtualNetworksClient: %w", err)
	}

	a.backendAddressPoolClient, err = armnetwork.NewLoadBalancerBackendAddressPoolsClient(cfg.subscriptionID, cred, options)
	if err != nil {
		return fmt.Errorf("failed to initialize new LoadBalancerBackendAddressPoolsClient: %w", err)
	}

	return nil
}

func (a *Azure) AssignPrivateIP(ip net.IP, node *corev1.Node) error {
	ipc := ip.String()
	klog.Infof("Acquiring node lock for assigning ip address, node: %s, ip: %s", node.Name, ipc)
	nodeLock := a.getNodeLock(node.Name)
	nodeLock.Lock()
	defer nodeLock.Unlock()
	instance, err := a.getInstance(node)
	if err != nil {
		return err
	}
	networkInterfaces, err := a.getNetworkInterfaces(instance)
	if err != nil {
		return err
	}
	if networkInterfaces[0].Properties == nil {
		return fmt.Errorf("nil network interface properties")
	}
	applicationSecurityGroups := networkInterfaces[0].Properties.IPConfigurations[0].Properties.ApplicationSecurityGroups

	// Perform the operation against the first interface listed, which will be
	// the primary interface (if it's defined as such) or the first one returned
	// following the order Azure specifies.
	networkInterface := networkInterfaces[0]
	// Assign the IP
	ipConfigurations := networkInterface.Properties.IPConfigurations
	name := fmt.Sprintf("%s_%s", node.Name, ipc)
	untrue := false

	// In some Azure setups (Azure private, public ARO, private ARO) outbound connectivity is achieved through
	// outbound rules tied to the backend address pool of the primary IP of the VM NIC. An Azure constraint
	// forbids the creation of a secondary IP tied to such address pool and would result in
	// OutboundRuleCannotBeUsedWithBackendAddressPoolThatIsReferencedBySecondaryIpConfigs.
	// Work around it by not specifying the backend address pool when an outbound rule is set, even though
	// that means preventing outbound connectivity to the egress IP, which will be able to reach the
	// infrastructure subnet nonetheless. In public Azure clusters, outbound connectivity is achieved through
	// UserDefinedRouting, which doesn't impose such constraints on secondary IPs.
	loadBalancerBackendAddressPoolsArgument := networkInterface.Properties.IPConfigurations[0].Properties.LoadBalancerBackendAddressPools
	var attachedOutboundRule *armnetwork.SubResource
OuterLoop:
	for _, ipconfig := range networkInterface.Properties.IPConfigurations {
		if ipconfig.Properties.LoadBalancerBackendAddressPools != nil {
			for _, pool := range ipconfig.Properties.LoadBalancerBackendAddressPools {
				if pool.ID == nil {
					continue
				}
				// for some reason, the struct for the pool above is not entirely filled out:
				//     BackendAddressPoolPropertiesFormat:(*network.BackendAddressPoolPropertiesFormat)(nil)
				// Do a separate get for this pool in order to check whether there are any outbound rules
				// attached to it
				realPool, err := a.getBackendAddressPool(ptr.Deref(pool.ID, ""))
				if err != nil {
					return fmt.Errorf("error looking up backend address pool %s with ID %s: %v", ptr.Deref(pool.Name, ""), ptr.Deref(pool.ID, ""), err)
				}
				if realPool.Properties.LoadBalancerBackendAddresses != nil && len(realPool.Properties.LoadBalancerBackendAddresses) > 0 {
					if realPool.Properties.OutboundRule != nil {
						loadBalancerBackendAddressPoolsArgument = nil
						attachedOutboundRule = realPool.Properties.OutboundRule
						break OuterLoop
					}
					if realPool.Properties.OutboundRules != nil && len(realPool.Properties.OutboundRules) > 0 {
						loadBalancerBackendAddressPoolsArgument = nil
						attachedOutboundRule = (realPool.Properties.OutboundRules)[0]
						break OuterLoop
					}
				}
			}
		}
	}
	if loadBalancerBackendAddressPoolsArgument == nil {
		outboundRuleStr := ""
		if attachedOutboundRule != nil && attachedOutboundRule.ID != nil {
			// https://issues.redhat.com/browse/OCPBUGS-33617 showed that there can be a rule without an ID...
			outboundRuleStr = fmt.Sprintf(": %s", ptr.Deref(attachedOutboundRule.ID, ""))
		}
		klog.Warningf("Egress IP %s will have no outbound connectivity except for the infrastructure subnet: "+
			"omitting backend address pool when adding secondary IP: it has an outbound rule already%s",
			ipc, outboundRuleStr)
	}
	newIPConfiguration := &armnetwork.InterfaceIPConfiguration{
		Name: &name,
		Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
			PrivateIPAddress:                &ipc,
			PrivateIPAllocationMethod:       ptr.To(armnetwork.IPAllocationMethodStatic),
			Subnet:                          networkInterface.Properties.IPConfigurations[0].Properties.Subnet,
			Primary:                         &untrue,
			LoadBalancerBackendAddressPools: loadBalancerBackendAddressPoolsArgument,
			ApplicationSecurityGroups:       applicationSecurityGroups,
		},
	}
	for _, ipCfg := range ipConfigurations {
		if ptr.Deref(ipCfg.Properties.PrivateIPAddress, "") == ipc {
			json, err := ipCfg.MarshalJSON()
			if err != nil {
				klog.Errorf("Failed to marshall the ip configuration: %v", err)
			}
			klog.Warningf("IP: %s is already assigned to node: %s with the ip configuration: %s", ipc, node.Name, json)
			return AlreadyExistingIPError
		}
	}
	ipConfigurations = append(ipConfigurations, newIPConfiguration)
	networkInterface.Properties.IPConfigurations = ipConfigurations
	// Send the request
	poller, err := a.createOrUpdate(networkInterface)
	if err != nil {
		return err
	}
	return a.waitForCompletion(poller)
}

func (a *Azure) ReleasePrivateIP(ip net.IP, node *corev1.Node) error {
	klog.Infof("Acquiring node lock for releasing ip address, node: %s, ip: %s", node.Name, ip.String())
	nodeLock := a.getNodeLock(node.Name)
	nodeLock.Lock()
	defer nodeLock.Unlock()
	instance, err := a.getInstance(node)
	if err != nil {
		return err
	}
	networkInterfaces, err := a.getNetworkInterfaces(instance)
	if err != nil {
		return err
	}
	// Perform the operation against the first interface listed, which will be
	// the primary interface (if it's defined as such) or the first one returned
	// following the order Azure specifies.
	networkInterface := networkInterfaces[0]
	// Release the IP
	keepIPConfiguration := []*armnetwork.InterfaceIPConfiguration{}
	ipAssigned := false
	if networkInterface.Properties == nil {
		return fmt.Errorf("nil network interface properties")
	}
	for _, ipConfiguration := range networkInterface.Properties.IPConfigurations {
		if assignedIP := net.ParseIP(ptr.Deref(ipConfiguration.Properties.PrivateIPAddress, "")); assignedIP != nil && !assignedIP.Equal(ip) {
			keepIPConfiguration = append(keepIPConfiguration, ipConfiguration)
		} else if assignedIP != nil && assignedIP.Equal(ip) {
			ipAssigned = true
		}
	}
	// Short-circuit if the IP never existed to begin with
	if !ipAssigned {
		return NonExistingIPError
	}
	networkInterface.Properties.IPConfigurations = keepIPConfiguration
	// Send the request
	poller, err := a.createOrUpdate(networkInterface)
	if err != nil {
		return err
	}
	return a.waitForCompletion(poller)
}

func (a *Azure) GetNodeEgressIPConfiguration(node *corev1.Node, cloudPrivateIPConfigs []*v1.CloudPrivateIPConfig) ([]*NodeEgressIPConfiguration, error) {
	instance, err := a.getInstance(node)
	if err != nil {
		return nil, err
	}
	networkInterfaces, err := a.getNetworkInterfaces(instance)
	if err != nil {
		return nil, err
	}
	// Perform the operation against the first interface listed, which will be
	// the primary interface (if it's defined as such) or the first one returned
	// following the order Azure specifies.
	networkInterface := networkInterfaces[0]
	// Prepare the config
	config := &NodeEgressIPConfiguration{
		Interface: strings.TrimPrefix(getNameFromResourceID(ptr.Deref(networkInterface.ID, "")), "/"),
	}
	v4Subnet, v6Subnet, err := a.getSubnet(networkInterface)
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
		IP: a.getCapacity(networkInterface, len(cloudPrivateIPConfigs)),
	}
	return []*NodeEgressIPConfiguration{config}, nil
}

func (a *Azure) createOrUpdate(networkInterface armnetwork.Interface) (*runtime.Poller[armnetwork.InterfacesClientCreateOrUpdateResponse], error) {
	ctx, cancel := context.WithTimeout(a.ctx, defaultAzureOperationTimeout)
	defer cancel()
	poller, err := a.networkClient.BeginCreateOrUpdate(ctx, a.resourceGroup, ptr.Deref(networkInterface.Name, ""), networkInterface, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create or update network interface: %v, err: %v", ptr.Deref(networkInterface.Name, ""), err)
	}

	return poller, nil
}

func (a *Azure) waitForCompletion(poller *runtime.Poller[armnetwork.InterfacesClientCreateOrUpdateResponse]) error {
	// No specified timeout for this operation, because a valid value doesn't
	// seem possible to estimate. Note: Azure has some defaults defined here:
	// https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime@v1.17.0#Poller.PollUntilDone
	if _, err := poller.PollUntilDone(context.TODO(), nil); err != nil {
		return err
	}
	return nil
}

func (a *Azure) getSubnet(networkInterface armnetwork.Interface) (*net.IPNet, *net.IPNet, error) {
	addressPrefixes, err := a.getAddressPrefixes(networkInterface)
	if err != nil {
		return nil, nil, fmt.Errorf("error retrieving associated address prefix for network interface, err: %v", err)
	}
	var v4Subnet, v6Subnet *net.IPNet
	for _, addressPrefix := range addressPrefixes {
		if addressPrefix == nil {
			return nil, nil, fmt.Errorf("error retrieving associated address prefix")
		}
		_, subnet, err := net.ParseCIDR(*addressPrefix)
		if err != nil {
			return nil, nil, fmt.Errorf("error: unable to parse found AddressPrefix: %s for network interface, err: %v", ptr.Deref(addressPrefix, ""), err)
		}
		if utilnet.IsIPv6CIDR(subnet) {
			if v6Subnet == nil {
				v6Subnet = subnet
			}
		} else {
			if v4Subnet == nil {
				v4Subnet = subnet
			}
		}
	}
	return v4Subnet, v6Subnet, nil
}

// We need to retrieve the amounts assigned to the node by default and subtract
// that from the default 256 value. Note: there is also a "Private IP addresses
// per virtual network" quota, but that's 65.536, so we can skip that.
func (a *Azure) getCapacity(networkInterface armnetwork.Interface, cloudPrivateIPsCount int) int {
	currentIPv4Usage, currentIPv6Usage := 0, 0
	for _, ipConfiguration := range networkInterface.Properties.IPConfigurations {
		if assignedIP := net.ParseIP(ptr.Deref(ipConfiguration.Properties.PrivateIPAddress, "")); assignedIP != nil {
			if utilnet.IsIPv4(assignedIP) {
				currentIPv4Usage++
			} else {
				currentIPv6Usage++
			}
		}
	}
	return defaultAzurePrivateIPCapacity + cloudPrivateIPsCount - currentIPv4Usage - currentIPv6Usage
}

// This is what the node's providerID looks like on Azure
// spec:
//
//	providerID: azure:///subscriptions/ee2e2172-e246-4d4b-a72a-f62fbf924238/resourceGroups/ovn-qgwkn-rg/providers/Microsoft.Compute/virtualMachines/ovn-qgwkn-worker-canadacentral1-bskbf
//
// getInstance also validates that the instance has a (or several) NICs
func (a *Azure) getInstance(node *corev1.Node) (*armcompute.VirtualMachine, error) {
	providerData := strings.Split(node.Spec.ProviderID, "/")
	if len(providerData) != 11 {
		return nil, UnexpectedURIError(node.Spec.ProviderID)
	}
	ctx, cancel := context.WithTimeout(a.ctx, defaultAzureOperationTimeout)
	defer cancel()
	instance, err := a.vmClient.Get(ctx, a.resourceGroup, providerData[len(providerData)-1], nil)
	if err != nil {
		return nil, err
	}
	return &instance.VirtualMachine, nil
}

// getNetworkInterfaces returns a slice of network.Interface with the
// primary one first, if it exists, else in the order assigned by Azure.
func (a *Azure) getNetworkInterfaces(instance *armcompute.VirtualMachine) ([]armnetwork.Interface, error) {
	if instance.Properties == nil || instance.Properties.NetworkProfile == nil {
		return nil, NoNetworkInterfaceError
	}
	if instance.Properties.NetworkProfile.NetworkInterfaces == nil || len(instance.Properties.NetworkProfile.NetworkInterfaces) == 0 {
		return nil, NoNetworkInterfaceError
	}
	networkInterfaces := []armnetwork.Interface{}
	// Try to get the ID corresponding to the "primary" NIC and put that first
	// in the slice. Do it like this because it's assumed to not be guaranteed
	// to be first in the slice returned by the Azure API?
	for _, netif := range instance.Properties.NetworkProfile.NetworkInterfaces {
		if netif.Properties != nil && netif.Properties.Primary != nil && ptr.Deref(netif.Properties.Primary, false) {
			intf, err := a.getNetworkInterface(ptr.Deref(netif.ID, ""))
			if err != nil {
				return nil, err
			}
			networkInterfaces = append(networkInterfaces, intf)
			break
		}
	}
	// Get the rest and append that.
	for _, netif := range instance.Properties.NetworkProfile.NetworkInterfaces {
		if netif.Properties != nil && !ptr.Deref(netif.Properties.Primary, false) {
			intf, err := a.getNetworkInterface(ptr.Deref(netif.ID, ""))
			if err != nil {
				return nil, err
			}
			networkInterfaces = append(networkInterfaces, intf)
		}
	}
	if len(networkInterfaces) == 0 {
		// Due to security restrictions access, the NIC's "primary" field is not enumerable.
		// If we have NICs, then select the first in the list.
		if len(instance.Properties.NetworkProfile.NetworkInterfaces) > 0 {
			intf, err := a.getNetworkInterface(ptr.Deref(instance.Properties.NetworkProfile.NetworkInterfaces[0].ID, ""))
			if err != nil {
				return nil, err
			}
			networkInterfaces = append(networkInterfaces, intf)
			return networkInterfaces, nil
		}
		return nil, NoNetworkInterfaceError
	}
	return networkInterfaces, nil
}

func splitObjectID(azureResourceID string) (resourceGroupName, loadBalancerName, backendAddressPoolName string) {
	// example of an azureResourceID:
	// "/subscriptions/53b8f551-f0fc-4bea-8cba-6d1fefd54c8a/resourceGroups/huirwang-debug1-2qh9t-rg/providers/Microsoft.Network/loadBalancers/huirwang-debug1-2qh9t/backendAddressPools/huirwang-debug1-2qh9t"

	// Split the Azure resource ID into parts using "/"
	parts := strings.Split(azureResourceID, "/")

	// Iterate through the parts to find the relevant subIDs
	for i, part := range parts {
		switch part {
		case "resourceGroups":
			if i+1 < len(parts) {
				resourceGroupName = parts[i+1]
			}
		case "loadBalancers":
			if i+1 < len(parts) {
				loadBalancerName = parts[i+1]
			}
		case "backendAddressPools":
			if i+1 < len(parts) {
				backendAddressPoolName = parts[i+1]
			}
		}
	}
	return
}

func (a *Azure) getBackendAddressPool(poolID string) (*armnetwork.BackendAddressPool, error) {
	ctx, cancel := context.WithTimeout(a.ctx, defaultAzureOperationTimeout)
	defer cancel()
	resourceGroupName, loadBalancerName, backendAddressPoolName := splitObjectID(poolID)
	response, err := a.backendAddressPoolClient.Get(ctx, resourceGroupName, loadBalancerName, backendAddressPoolName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve backend address pool for backendAddressPoolClient=%s, loadBalancerName=%s, backendAddressPoolName=%s: %w",
			resourceGroupName, loadBalancerName, backendAddressPoolName, err)
	}
	return &response.BackendAddressPool, nil

}

func (a *Azure) getNetworkInterface(id string) (armnetwork.Interface, error) {
	ctx, cancel := context.WithTimeout(a.ctx, defaultAzureOperationTimeout)
	defer cancel()
	response, err := a.networkClient.Get(ctx, a.resourceGroup, getNameFromResourceID(id), nil)
	if err != nil {
		return armnetwork.Interface{}, fmt.Errorf("failed to retrieve network interface for id %s: %w", id, err)
	}
	return response.Interface, nil
}

// This is what the subnet ID looks like on Azure:
//
//	ID: "/subscriptions/d38f1e38-4bed-438e-b227-833f997adf6a/resourceGroups/ci-ln-wzc83kk-002ac-qcghn-rg/providers/Microsoft.Network/virtualNetworks/ci-ln-wzc83kk-002ac-qcghn-vnet/subnets/ci-ln-wzc83kk-002ac-qcghn-worker-subnet"
func (a *Azure) getNetworkResourceGroupAndSubnetAndNetnames(subnetID string) (string, string, string, error) {
	providerData := strings.Split(subnetID, "/")
	if len(providerData) != 11 {
		return "", "", "", UnexpectedURIError(subnetID)
	}
	return providerData[4], providerData[len(providerData)-3], providerData[len(providerData)-1], nil
}

func (a *Azure) getAddressPrefixes(networkInterface armnetwork.Interface) ([]*string, error) {
	var virtualNetworkResourceGroup string
	var virtualNetworkName string
	var subnetName string
	var err error
	for _, ipConfiguration := range networkInterface.Properties.IPConfigurations {
		if ptr.Deref(ipConfiguration.Properties.Primary, false) {
			virtualNetworkResourceGroup, virtualNetworkName, subnetName, err = a.getNetworkResourceGroupAndSubnetAndNetnames(ptr.Deref(ipConfiguration.Properties.Subnet.ID, ""))
			if err != nil {
				return nil, err
			}
			break
		}
	}
	ctx, cancel := context.WithTimeout(a.ctx, defaultAzureOperationTimeout)
	defer cancel()
	virtualNetwork, err := a.virtualNetworkClient.Get(ctx, virtualNetworkResourceGroup, virtualNetworkName, nil)
	if err != nil {
		return nil, fmt.Errorf("error retrieving subnet IP configuration, err: %v", err)
	}
	// Check the list of subnets first. If a subnet with the subnet name is found, then use that
	// instead of virtualNetwork.AddressSpace.AddressPrefixes which only contains the main subnet's
	// address prefix.
	// FIXME: This might not work for IPv6.
	if virtualNetwork.Properties != nil && virtualNetwork.Properties.Subnets != nil {
		for _, vns := range virtualNetwork.Properties.Subnets {
			if vns.Name != nil && vns.Properties.AddressPrefix != nil &&
				ptr.Deref(vns.Name, "") == subnetName {
				return []*string{vns.Properties.AddressPrefix}, nil
			}
		}
	}

	if virtualNetwork.Properties.AddressSpace == nil {
		return nil, fmt.Errorf("nil subnet address space")
	}
	if virtualNetwork.Properties.AddressSpace.AddressPrefixes == nil || len(virtualNetwork.Properties.AddressSpace.AddressPrefixes) == 0 {
		return nil, fmt.Errorf("no subnet address prefixes defined")
	}
	return virtualNetwork.Properties.AddressSpace.AddressPrefixes, nil
}

func (a *Azure) getAzureCredentials(env azureapi.Environment, cfg *azureCredentialsConfig) (azcore.TokenCredential, cloud.Configuration, error) {
	var (
		cred azcore.TokenCredential
		err  error
	)

	cloudConfig := ParseCloudEnvironment(env)

	userAssignedIdentityCredentialsFilePath := os.Getenv("ARO_HCP_CLIENT_CREDENTIALS_PATH")
	if userAssignedIdentityCredentialsFilePath != "" {
		// UserAssignedIdentityCredentials for managed Azure HCP
		klog.Infof("Using user assigned identity credentials authentication")
		clientOptions := azcore.ClientOptions{
			Cloud: cloudConfig,
		}
		cred, err = dataplane.NewUserAssignedIdentityCredential(context.Background(), userAssignedIdentityCredentialsFilePath, dataplane.WithClientOpts(clientOptions))
		if err != nil {
			return nil, cloud.Configuration{}, err
		}
	} else if strings.TrimSpace(cfg.clientSecret) == "" {
		if a.azureWorkloadIdentityEnabled && strings.TrimSpace(cfg.tokenFile) != "" {
			klog.Infof("Using workload identity authentication")
			if cfg.clientID == "" || cfg.tenantID == "" {
				return nil, cloud.Configuration{}, fmt.Errorf("clientID and tenantID are required in workload identity authentication")
			}
			options := azidentity.WorkloadIdentityCredentialOptions{
				ClientOptions: azcore.ClientOptions{
					Cloud: cloudConfig,
				},
				ClientID:      cfg.clientID,
				TenantID:      cfg.tenantID,
				TokenFilePath: cfg.tokenFile,
			}
			cred, err = azidentity.NewWorkloadIdentityCredential(&options)
			if err != nil {
				return nil, cloud.Configuration{}, err
			}
		}
	} else {
		klog.Infof("Using client secret authentication")
		if cfg.clientID == "" || cfg.tenantID == "" {
			return nil, cloud.Configuration{}, fmt.Errorf("clientID and tenantID are required in client secret authentication")
		}
		options := azidentity.ClientSecretCredentialOptions{
			ClientOptions: azcore.ClientOptions{
				Cloud: cloudConfig,
			},
		}
		cred, err = azidentity.NewClientSecretCredential(cfg.tenantID, cfg.clientID, cfg.clientSecret, &options)
		if err != nil {
			return nil, cloud.Configuration{}, err
		}
	}

	return cred, cloudConfig, nil
}

// getNodeLock retrieves node lock from nodeLockMap, If lock doesn't exist, then update map
// with a new lock entry for the given node name.
func (a *Azure) getNodeLock(nodeName string) *sync.Mutex {
	a.nodeMapLock.Lock()
	defer a.nodeMapLock.Unlock()
	if _, ok := a.nodeLockMap[nodeName]; !ok {
		a.nodeLockMap[nodeName] = &sync.Mutex{}
	}
	return a.nodeLockMap[nodeName]
}

func getNameFromResourceID(id string) string {
	return id[strings.LastIndex(id, "/"):]
}

func ParseCloudEnvironment(env azureapi.Environment) cloud.Configuration {
	var cloudConfig cloud.Configuration
	switch env {
	case azure.ChinaCloud:
		cloudConfig = cloud.AzureChina
	case azure.USGovernmentCloud:
		cloudConfig = cloud.AzureGovernment
	case azure.PublicCloud:
		cloudConfig = cloud.AzurePublic
	default: // AzureStackCloud
		cloudConfig = cloud.Configuration{
			ActiveDirectoryAuthorityHost: env.ActiveDirectoryEndpoint,
			Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
				cloud.ResourceManager: {
					Audience: env.TokenAudience,
					Endpoint: env.ResourceManagerEndpoint,
				},
			},
		}
	}
	return cloudConfig
}
