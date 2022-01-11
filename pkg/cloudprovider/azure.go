package cloudprovider

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	compute "github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2020-06-30/compute"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	azureapi "github.com/Azure/go-autorest/autorest/azure"
	corev1 "k8s.io/api/core/v1"
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
	resourceGroup        string
	env                  azure.Environment
	vmClient             compute.VirtualMachinesClient
	virtualNetworkClient network.VirtualNetworksClient
	networkClient        network.InterfacesClient
}

func (a *Azure) initCredentials() error {
	clientID, err := a.readSecretData("azure_client_id")
	if err != nil {
		return err
	}
	tenantID, err := a.readSecretData("azure_tenant_id")
	if err != nil {
		return err
	}
	clientSecret, err := a.readSecretData("azure_client_secret")
	if err != nil {
		return err
	}
	subscriptionID, err := a.readSecretData("azure_subscription_id")
	if err != nil {
		return err
	}
	a.resourceGroup, err = a.readSecretData("azure_resourcegroup")
	if err != nil {
		return err
	}
	authorizer, err := a.getAuthorizer(clientID, clientSecret, tenantID)
	if err != nil {
		return err
	}

	// Pick the Azure "Environment", which is just a named set of API endpoints.
	if a.cfg.APIOverride != "" {
		a.env, err = azure.EnvironmentFromURL(a.cfg.APIOverride)
	} else {
		a.env, err = azure.EnvironmentFromName(a.cfg.AzureEnvironment)
	}
	if err != nil {
		return fmt.Errorf("failed to initialize Azure environment: %w", err)
	}

	a.vmClient = compute.NewVirtualMachinesClientWithBaseURI(a.env.ResourceManagerEndpoint, subscriptionID)
	a.vmClient.Authorizer = authorizer
	_ = a.vmClient.AddToUserAgent(UserAgent)

	a.networkClient = network.NewInterfacesClientWithBaseURI(a.env.ResourceManagerEndpoint, subscriptionID)
	a.networkClient.Authorizer = authorizer
	_ = a.networkClient.AddToUserAgent(UserAgent)

	a.virtualNetworkClient = network.NewVirtualNetworksClientWithBaseURI(a.env.ResourceManagerEndpoint, subscriptionID)
	a.virtualNetworkClient.Authorizer = authorizer
	_ = a.virtualNetworkClient.AddToUserAgent(UserAgent)
	return nil
}

func (a *Azure) AssignPrivateIP(ip net.IP, node *corev1.Node) error {
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
	// Assign the IP
	ipConfigurations := *networkInterface.IPConfigurations
	name := fmt.Sprintf("%s_%s", node.Name, ip.String())
	ipc := ip.String()
	untrue := false
	newIPConfiguration := network.InterfaceIPConfiguration{
		Name: &name,
		InterfaceIPConfigurationPropertiesFormat: &network.InterfaceIPConfigurationPropertiesFormat{
			PrivateIPAddress:                &ipc,
			PrivateIPAllocationMethod:       network.Static,
			Subnet:                          (*networkInterface.IPConfigurations)[0].Subnet,
			Primary:                         &untrue,
			LoadBalancerBackendAddressPools: (*networkInterface.IPConfigurations)[0].LoadBalancerBackendAddressPools,
		},
	}
	ipConfigurations = append(ipConfigurations, newIPConfiguration)
	networkInterface.IPConfigurations = &ipConfigurations
	// Send the request
	result, err := a.createOrUpdate(networkInterface)
	if err != nil {
		return err
	}
	return a.waitForCompletion(result)
}

func (a *Azure) ReleasePrivateIP(ip net.IP, node *corev1.Node) error {
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
	keepIPConfiguration := []network.InterfaceIPConfiguration{}
	ipAssigned := false
	for _, ipConfiguration := range *networkInterface.IPConfigurations {
		if assignedIP := net.ParseIP(*ipConfiguration.PrivateIPAddress); assignedIP != nil && !assignedIP.Equal(ip) {
			keepIPConfiguration = append(keepIPConfiguration, ipConfiguration)
		} else if assignedIP != nil && assignedIP.Equal(ip) {
			ipAssigned = true
		}
	}
	// Short-circuit if the IP never existed to begin with
	if !ipAssigned {
		return NonExistingIPError
	}
	networkInterface.IPConfigurations = &keepIPConfiguration
	// Send the request
	result, err := a.createOrUpdate(networkInterface)
	if err != nil {
		return err
	}
	return a.waitForCompletion(result)
}

func (a *Azure) GetNodeEgressIPConfiguration(node *corev1.Node) ([]*NodeEgressIPConfiguration, error) {
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
		Interface: strings.TrimPrefix(getNameFromResourceID(*networkInterface.ID), "/"),
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
		IP: a.getCapacity(networkInterface),
	}
	return []*NodeEgressIPConfiguration{config}, nil
}

func (a *Azure) createOrUpdate(networkInterface network.Interface) (network.InterfacesCreateOrUpdateFuture, error) {
	ctx, cancel := context.WithTimeout(a.ctx, defaultAzureOperationTimeout)
	defer cancel()
	return a.networkClient.CreateOrUpdate(ctx, a.resourceGroup, *networkInterface.Name, networkInterface)
}

func (a *Azure) waitForCompletion(result network.InterfacesCreateOrUpdateFuture) error {
	// No specified timeout for this operation, because a valid value doesn't
	// seem possible to estimate. Note: Azure has some defaults defined here:
	// https://github.com/Azure/go-autorest/blob/master/autorest/client.go#L32-L44
	return result.WaitForCompletionRef(context.TODO(), a.networkClient.Client)
}

func (a *Azure) getSubnet(networkInterface network.Interface) (*net.IPNet, *net.IPNet, error) {
	addressPrefixes, err := a.getAddressPrefixes(networkInterface)
	if err != nil {
		return nil, nil, fmt.Errorf("error retrieving associated address prefix for network interface, err: %v", err)
	}
	var v4Subnet, v6Subnet *net.IPNet
	for _, addressPrefix := range addressPrefixes {
		_, subnet, err := net.ParseCIDR(addressPrefix)
		if err != nil {
			return nil, nil, fmt.Errorf("error: unable to parse found AddressPrefix: %s for network interface, err: %v", addressPrefix, err)
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
func (a *Azure) getCapacity(networkInterface network.Interface) int {
	currentIPv4Usage, currentIPv6Usage := 0, 0
	for _, ipConfiguration := range *networkInterface.IPConfigurations {
		if assignedIP := net.ParseIP(*ipConfiguration.PrivateIPAddress); assignedIP != nil {
			if utilnet.IsIPv4(assignedIP) {
				currentIPv4Usage++
			} else {
				currentIPv6Usage++
			}
		}
	}
	return defaultAzurePrivateIPCapacity - currentIPv4Usage - currentIPv6Usage
}

// This is what the node's providerID looks like on Azure
// spec:
//   providerID: azure:///subscriptions/ee2e2172-e246-4d4b-a72a-f62fbf924238/resourceGroups/ovn-qgwkn-rg/providers/Microsoft.Compute/virtualMachines/ovn-qgwkn-worker-canadacentral1-bskbf
// getInstance also validates that the instance has a (or several) NICs
func (a *Azure) getInstance(node *corev1.Node) (*compute.VirtualMachine, error) {
	providerData := strings.Split(node.Spec.ProviderID, "/")
	if len(providerData) != 11 {
		return nil, UnexpectedURIError(node.Spec.ProviderID)
	}
	ctx, cancel := context.WithTimeout(a.ctx, defaultAzureOperationTimeout)
	defer cancel()
	instance, err := a.vmClient.Get(ctx, a.resourceGroup, providerData[len(providerData)-1], "")
	if err != nil {
		return nil, err
	}
	return &instance, nil
}

// getNetworkInterfaces returns a slice of network.Interface with the
// primary one first, if it exists, else in the order assigned by Azure.
func (a *Azure) getNetworkInterfaces(instance *compute.VirtualMachine) ([]network.Interface, error) {
	if instance.NetworkProfile == nil {
		return nil, NoNetworkInterfaceError
	}
	if instance.NetworkProfile.NetworkInterfaces == nil || len(*instance.NetworkProfile.NetworkInterfaces) == 0 {
		return nil, NoNetworkInterfaceError
	}
	networkInterfaces := []network.Interface{}
	// Try to get the ID corresponding to the "primary" NIC and put that first
	// in the slice. Do it like this because it's assumed to not be guaranteed
	// to be first in the slice returned by the Azure API?
	for _, netif := range *instance.NetworkProfile.NetworkInterfaces {
		if netif.Primary != nil && *netif.Primary {
			intf, err := a.getNetworkInterface(*netif.ID)
			if err != nil {
				return nil, err
			}
			networkInterfaces = append(networkInterfaces, intf)
			break
		}
	}
	// Get the rest and append that.
	for _, netif := range *instance.NetworkProfile.NetworkInterfaces {
		if (netif.Primary != nil && !*netif.Primary) || netif.Primary == nil {
			intf, err := a.getNetworkInterface(*netif.ID)
			if err != nil {
				return nil, err
			}
			networkInterfaces = append(networkInterfaces, intf)
		}
	}
	return networkInterfaces, nil
}

func (a *Azure) getNetworkInterface(id string) (network.Interface, error) {
	ctx, cancel := context.WithTimeout(a.ctx, defaultAzureOperationTimeout)
	defer cancel()
	return a.networkClient.Get(ctx, a.resourceGroup, getNameFromResourceID(id), "")
}

// This is what the subnet ID looks like on Azure:
// 	ID: "/subscriptions/d38f1e38-4bed-438e-b227-833f997adf6a/resourceGroups/ci-ln-wzc83kk-002ac-qcghn-rg/providers/Microsoft.Network/virtualNetworks/ci-ln-wzc83kk-002ac-qcghn-vnet/subnets/ci-ln-wzc83kk-002ac-qcghn-worker-subnet"
func (a *Azure) getVirtualNetworkNameFromSubnetID(subnetID string) (string, error) {
	providerData := strings.Split(subnetID, "/")
	if len(providerData) != 11 {
		return "", UnexpectedURIError(subnetID)
	}
	return providerData[len(providerData)-3], nil
}

func (a *Azure) getAddressPrefixes(networkInterface network.Interface) ([]string, error) {
	var virtualNetworkName string
	var err error
	for _, ipConfiguration := range *networkInterface.IPConfigurations {
		if *ipConfiguration.Primary {
			virtualNetworkName, err = a.getVirtualNetworkNameFromSubnetID(*ipConfiguration.Subnet.ID)
			if err != nil {
				return nil, err
			}
			break
		}
	}
	ctx, cancel := context.WithTimeout(a.ctx, defaultAzureOperationTimeout)
	defer cancel()
	virtualNetwork, err := a.virtualNetworkClient.Get(ctx, a.resourceGroup, virtualNetworkName, "")
	if err != nil {
		return nil, fmt.Errorf("error retrieving subnet IP configuration, err: %v", err)
	}
	if virtualNetwork.AddressSpace == nil {
		return nil, fmt.Errorf("nil subnet address space")
	}
	if virtualNetwork.AddressSpace.AddressPrefixes == nil || len(*virtualNetwork.AddressSpace.AddressPrefixes) == 0 {
		return nil, fmt.Errorf("no subnet address prefixes defined")
	}
	return *virtualNetwork.AddressSpace.AddressPrefixes, nil
}

func (a *Azure) getAuthorizer(clientID string, clientSecret string, tenantID string) (autorest.Authorizer, error) {
	oauthConfig, err := adal.NewOAuthConfig(azureapi.PublicCloud.ActiveDirectoryEndpoint, tenantID)
	if err != nil {
		return nil, err
	}
	spToken, err := adal.NewServicePrincipalToken(*oauthConfig, clientID, clientSecret, azureapi.PublicCloud.ResourceManagerEndpoint)
	if err != nil {
		return nil, err
	}
	return autorest.NewBearerAuthorizer(spToken), nil
}

func getNameFromResourceID(id string) string {
	return id[strings.LastIndex(id, "/"):]
}
