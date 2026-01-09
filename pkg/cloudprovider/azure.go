package cloudprovider

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	azureapi "github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/msi-dataplane/pkg/dataplane"
	cloudnetworkv1 "github.com/openshift/api/cloudnetwork/v1"
	configv1 "github.com/openshift/api/config/v1"
	cloudnetworklisters "github.com/openshift/client-go/cloudnetwork/listers/cloudnetwork/v1"
	"github.com/openshift/cloud-network-config-controller/pkg/cloudprivateipconfig"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
	"k8s.io/utils/ptr"
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
	env                          azureapi.Environment
	vmClient                     *armcompute.VirtualMachinesClient
	virtualNetworkClient         *armnetwork.VirtualNetworksClient
	networkClient                *armnetwork.InterfacesClient
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
		a.env, err = azureapi.EnvironmentFromURL(a.cfg.APIOverride)
	} else {
		name := a.cfg.AzureEnvironment
		if name == "" {
			name = "AzurePublicCloud"
		}
		a.env, err = azureapi.EnvironmentFromName(name)
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
		return fmt.Errorf("error while retrieving instance details from Azure: %w", err)
	}
	networkInterfaces, err := a.getNetworkInterfaces(instance)
	if err != nil {
		return fmt.Errorf("error while retrieving interface details from Azure: %w", err)
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

	newIPConfiguration := &armnetwork.InterfaceIPConfiguration{
		Name: &name,
		Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
			PrivateIPAddress:          &ipc,
			PrivateIPAllocationMethod: ptr.To(armnetwork.IPAllocationMethodStatic),
			Subnet:                    networkInterface.Properties.IPConfigurations[0].Properties.Subnet,
			Primary:                   &untrue,
			ApplicationSecurityGroups: applicationSecurityGroups,
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
	klog.Warningf("Egress IP %s will have no outbound connectivity except for the infrastructure subnet: "+
		"omitting backend address pool when adding secondary IP", ipc)
	poller, err := a.createOrUpdate(networkInterface)
	if err != nil {
		return fmt.Errorf("error while updating network interface: %w", err)
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
		return fmt.Errorf("error while retrieving instance details from Azure: %w", err)
	}
	networkInterfaces, err := a.getNetworkInterfaces(instance)
	if err != nil {
		return fmt.Errorf("error while retrieving interface details from Azure: %w", err)
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
		return fmt.Errorf("error while updating network interface: %w", err)
	}
	return a.waitForCompletion(poller)
}

func (a *Azure) GetNodeEgressIPConfiguration(node *corev1.Node, cpicIPs sets.Set[string]) ([]*NodeEgressIPConfiguration, error) {
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
		// IPv4 and IPv6 fields not used by Azure (uses IP-family-agnostic capacity)
		IP: ptr.To(a.getCapacity(networkInterface, cpicIPs)),
	}
	return []*NodeEgressIPConfiguration{config}, nil
}

// The consensus is to not add egress IP to public load balancer
// backend pool regardless of the presence of an OutBoundRule.
// During upgrade this function removes any egress IP added to
// public load balancer backend pool previously.
func (a *Azure) SyncLBBackend(cloudPrivateIPConfigLister cloudnetworklisters.CloudPrivateIPConfigLister, nodeLister corelisters.NodeLister) error {
	cloudPrivateIPConfigs, err := cloudPrivateIPConfigLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("error listing cloud private ip config, err: %v", err)
	}
	for _, cloudPrivateIPConfig := range cloudPrivateIPConfigs {
		if !isCloudPrivateIPConfigAssigned(cloudPrivateIPConfig) {
			continue
		}
		ip, _, err := cloudprivateipconfig.NameToIP(cloudPrivateIPConfig.Name)
		if err != nil {
			return fmt.Errorf("error parsing CloudPrivateIPConfig %s: %v", cloudPrivateIPConfig.Name, err)
		}
		ipc := ip.String()
		node, err := nodeLister.Get(cloudPrivateIPConfig.Spec.Node)
		if err != nil && apierrors.IsNotFound(err) {
			klog.Warningf("source node: %s no longer exists for CloudPrivateIPConfig: %q",
				cloudPrivateIPConfig.Spec.Node, cloudPrivateIPConfig.Name)
			continue
		} else if err != nil {
			return fmt.Errorf("error getting node %s for CloudPrivateIPConfig %q: %w",
				cloudPrivateIPConfig.Spec.Node, cloudPrivateIPConfig.Name, err)
		}

		instance, err := a.getInstance(node)
		if err != nil {
			return fmt.Errorf("error while retrieving instance details from Azure: %w", err)
		}
		networkInterfaces, err := a.getNetworkInterfaces(instance)
		if err != nil {
			return fmt.Errorf("error while retrieving interface details from Azure: %w", err)
		}
		if networkInterfaces[0].Properties == nil {
			return fmt.Errorf("nil network interface properties")
		}
		// Perform the operation against the first interface listed, which will be
		// the primary interface (if it's defined as such) or the first one returned
		// following the order Azure specifies.
		networkInterface := networkInterfaces[0]
		var loadBalancerBackendPoolModified bool
		// omit Egress IP from LB backend pool
		ipConfigurations := networkInterface.Properties.IPConfigurations
		for _, ipCfg := range ipConfigurations {
			if ptr.Deref(ipCfg.Properties.PrivateIPAddress, "") == ipc &&
				ipCfg.Properties.LoadBalancerBackendAddressPools != nil {
				klog.Infof("Removing Egress IP %s from Azure public load balancer backend pool", ipc)
				ipCfg.Properties.LoadBalancerBackendAddressPools = nil
				loadBalancerBackendPoolModified = true
			}
		}
		if loadBalancerBackendPoolModified {
			networkInterface.Properties.IPConfigurations = ipConfigurations
			poller, err := a.createOrUpdate(networkInterface)
			if err != nil {
				return fmt.Errorf("error while updating network interface: %w", err)
			}
			if err = a.waitForCompletion(poller); err != nil {
				return fmt.Errorf("error while updating network interface: %w", err)
			}
		}
	}
	return nil
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
func (a *Azure) getCapacity(networkInterface armnetwork.Interface, cpicIPs sets.Set[string]) int {
	currentIPUsage := 0
	for _, ipConfiguration := range networkInterface.Properties.IPConfigurations {
		if assignedIP := net.ParseIP(ptr.Deref(ipConfiguration.Properties.PrivateIPAddress, "")); assignedIP != nil {
			if !cpicIPs.Has(assignedIP.String()) {
				currentIPUsage++
			}
		}
	}

	return defaultAzurePrivateIPCapacity - currentIPUsage
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
	if len(instance.Properties.NetworkProfile.NetworkInterfaces) == 0 {
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
			if vns.Name != nil && ptr.Deref(vns.Name, "") == subnetName {
				if vns.Properties.AddressPrefix != nil {
					return []*string{vns.Properties.AddressPrefix}, nil
				}
				// In some cases, addressPrefixes is set with single element.
				// so use it when addressPrefix is not available.
				if len(vns.Properties.AddressPrefixes) > 0 {
					return vns.Properties.AddressPrefixes, nil
				}
			}
		}
	}

	if virtualNetwork.Properties.AddressSpace == nil {
		return nil, fmt.Errorf("nil subnet address space")
	}
	if len(virtualNetwork.Properties.AddressSpace.AddressPrefixes) == 0 {
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

func (a *Azure) CleanupNode(nodeName string) {
	a.nodeMapLock.Lock()
	defer a.nodeMapLock.Unlock()
	delete(a.nodeLockMap, nodeName)
}

func getNameFromResourceID(id string) string {
	return id[strings.LastIndex(id, "/"):]
}

func ParseCloudEnvironment(env azureapi.Environment) cloud.Configuration {
	var cloudConfig cloud.Configuration
	switch env {
	case azureapi.ChinaCloud:
		cloudConfig = cloud.AzureChina
	case azureapi.USGovernmentCloud:
		cloudConfig = cloud.AzureGovernment
	case azureapi.PublicCloud:
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

func isCloudPrivateIPConfigAssigned(cpic *cloudnetworkv1.CloudPrivateIPConfig) bool {
	for _, condition := range cpic.Status.Conditions {
		if condition.Type == string(cloudnetworkv1.Assigned) && condition.Status == v1.ConditionTrue {
			return true
		}
	}
	return false
}
