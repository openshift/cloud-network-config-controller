package cloudprovider

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	awsapi "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	v1 "github.com/openshift/api/cloudnetwork/v1"
	"github.com/openshift/cloud-network-config-controller/pkg/cloudprivateipconfig"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

const (
	PlatformTypeAWS = "AWS"
)

// AWS implements the API wrapper for talking to the AWS cloud API
type AWS struct {
	CloudProvider
	client *ec2.EC2
}

func (a *AWS) initCredentials() error {
	f, err := sharedCredentialsFileFromDirectory(a.cfg.CredentialDir)
	if err != nil {
		return err
	}
	sessionOpts := session.Options{
		SharedConfigState: session.SharedConfigEnable,
		SharedConfigFiles: []string{f},
		Config:            awsapi.Config{Region: &a.cfg.Region},
	}
	if a.cfg.APIOverride != "" {
		customResolver := func(service, region string, optFns ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error) {
			if service == endpoints.Ec2ServiceID {
				return endpoints.ResolvedEndpoint{
					URL:           a.cfg.APIOverride,
					SigningRegion: a.cfg.Region,
				}, nil
			}
			return endpoints.DefaultResolver().EndpointFor(service, region, optFns...)
		}
		sessionOpts.Config.EndpointResolver = endpoints.ResolverFunc(customResolver)
	}
	if a.cfg.AWSCAOverride != "" {
		var err error
		sessionOpts.CustomCABundle, err = os.Open(a.cfg.AWSCAOverride)
		if err != nil {
			return fmt.Errorf("could not open AWS CA bundle %s: %w", a.cfg.AWSCAOverride, err)
		}
	}

	mySession, err := session.NewSessionWithOptions(sessionOpts)
	if err != nil {
		return fmt.Errorf("could not initialize AWS session: %w", err)
	}

	a.client = ec2.New(mySession)
	return nil
}

// AssignPrivateIP assigns the IP address to the node by re-providing all
// existing ones + the new one. It does this on a per-IP-family basis (since the
// AWS API is separated per family). If the IP is already existing: it returns an
// AlreadyExistingIPError.
func (a *AWS) AssignPrivateIP(ip net.IP, node *corev1.Node) error {
	instance, err := a.getInstance(node)
	if err != nil {
		return err
	}
	networkInterfaces, err := a.getNetworkInterfaces(instance)
	if err != nil {
		return err
	}
	// Perform the operation against the first interface listed following the
	// order AWS specifies.
	networkInterface := networkInterfaces[0]
	addIP := ip.String()
	if utilnet.IsIPv6(ip) {
		for _, assignedIPv6 := range networkInterface.Ipv6Addresses {
			if assignedIP := net.ParseIP(*assignedIPv6.Ipv6Address); assignedIP != nil && assignedIP.Equal(ip) {
				return AlreadyExistingIPError
			}
		}
		input := ec2.AssignIpv6AddressesInput{
			NetworkInterfaceId: networkInterface.NetworkInterfaceId,
			Ipv6Addresses:      []*string{&addIP},
		}
		_, err = a.client.AssignIpv6Addresses(&input)
		if err != nil {
			klog.Errorf("error: %s, tried to assign IP '%s' to interface: %s.", err, addIP, *networkInterface)
			return err
		}
		return a.waitForCompletion(node, []string{addIP}, false)
	} else {
		for _, assignedIPv4 := range networkInterface.PrivateIpAddresses {
			if assignedIP := net.ParseIP(*assignedIPv4.PrivateIpAddress); assignedIP != nil && assignedIP.Equal(ip) {
				return AlreadyExistingIPError
			}
		}
		inputV4 := ec2.AssignPrivateIpAddressesInput{
			NetworkInterfaceId: networkInterface.NetworkInterfaceId,
			PrivateIpAddresses: []*string{&addIP},
		}
		_, err = a.client.AssignPrivateIpAddresses(&inputV4)
		if err != nil {
			klog.Errorf("error: %s, tried to assign IP '%s' to interface: %s.", err, addIP, *networkInterface)
			return err
		}
		return a.waitForCompletion(node, []string{addIP}, false)
	}
}

// ReleasePrivateIP un-assigns the IP address from the node. It does this on a
// per-IP-family basis (since the AWS API is separated per family).  If the IP
// is non-existant: it returns an NonExistingIPError.
func (a *AWS) ReleasePrivateIP(ip net.IP, node *corev1.Node) error {
	instance, err := a.getInstance(node)
	if err != nil {
		return err
	}
	networkInterfaces, err := a.getNetworkInterfaces(instance)
	if err != nil {
		return err
	}
	// Perform the operation against the first interface listed following the
	// order AWS specifies.
	networkInterface := networkInterfaces[0]
	deleteIPs := []*string{}
	if utilnet.IsIPv6(ip) {
		for _, assignedIPv6 := range networkInterface.Ipv6Addresses {
			if assignedIP := net.ParseIP(*assignedIPv6.Ipv6Address); assignedIP != nil && assignedIP.Equal(ip) {
				deleteIPs = append(deleteIPs, assignedIPv6.Ipv6Address)
			}
		}
		if len(deleteIPs) == 0 {
			return NonExistingIPError
		}
		input := ec2.UnassignIpv6AddressesInput{
			NetworkInterfaceId: networkInterface.NetworkInterfaceId,
			Ipv6Addresses:      deleteIPs,
		}
		_, err = a.client.UnassignIpv6Addresses(&input)
		if err != nil {
			return err
		}
		return a.waitForCompletion(node, awsapi.StringValueSlice(deleteIPs), true)
	} else {
		for _, assignedIPv4 := range networkInterface.PrivateIpAddresses {
			if assignedIP := net.ParseIP(*assignedIPv4.PrivateIpAddress); assignedIP != nil && assignedIP.Equal(ip) {
				deleteIPs = append(deleteIPs, assignedIPv4.PrivateIpAddress)
			}
		}
		if len(deleteIPs) == 0 {
			return NonExistingIPError
		}
		inputV4 := ec2.UnassignPrivateIpAddressesInput{
			NetworkInterfaceId: networkInterface.NetworkInterfaceId,
			PrivateIpAddresses: deleteIPs,
		}
		_, err = a.client.UnassignPrivateIpAddresses(&inputV4)
		if err != nil {
			return err
		}
		return a.waitForCompletion(node, awsapi.StringValueSlice(deleteIPs), true)
	}
}

func (a *AWS) GetNodeEgressIPConfiguration(node *corev1.Node, cloudPrivateIPConfigs []*v1.CloudPrivateIPConfig) ([]*NodeEgressIPConfiguration, error) {
	instance, err := a.getInstance(node)
	if err != nil {
		return nil, err
	}
	instanceV4Capacity, instanceV6Capacity, err := a.getInstanceCapacity(instance)
	if err != nil {
		return nil, fmt.Errorf("error retrieving the instance capacities, err: %v", err)
	}
	networkInterfaces, err := a.getNetworkInterfaces(instance)
	if err != nil {
		return nil, err
	}
	networkInterface := networkInterfaces[0]
	config := &NodeEgressIPConfiguration{
		Interface: *networkInterface.NetworkInterfaceId,
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
	capV4, capV6, err := a.getCapacity(instanceV4Capacity, instanceV6Capacity, networkInterface, cloudPrivateIPConfigs)
	if err != nil {
		return nil, err
	}
	config.Capacity = capacity{
		IPv4: capV4,
		IPv6: capV6,
	}
	return []*NodeEgressIPConfiguration{config}, nil
}

// Unfortunately the AWS API (WaitUntilInstanceRunning) only handles equality
// assertion: so on delete we can't specify and assert that the IP which is
// being removed is completely removed, we are forced to do the inverse, i.e:
// assert that all IPs except the IP being removed are there (which should
// anyways be the case). Hence, use our own poller which verifies on ADD that
// all IPs that we add are assigned to the node, and on DEL that all IPs being
// removed have been completely removed from the node.
func (a *AWS) waitForCompletion(node *corev1.Node, ips []string, deleteOp bool) error {
	return wait.PollImmediate(time.Second*2, time.Minute, func() (done bool, err error) {
		instance, err := a.getInstance(node)
		if err != nil {
			return false, err
		}
		sampleIP := ips[0]
		assignedIPs := []string{}
		if utilnet.IsIPv6String(sampleIP) {
			for _, assignedIPv6 := range instance.NetworkInterfaces[0].Ipv6Addresses {
				if assignedIP := net.ParseIP(*assignedIPv6.Ipv6Address); assignedIP != nil {
					assignedIPs = append(assignedIPs, assignedIP.String())
				}
			}
		} else {
			for _, assignedIPv4 := range instance.NetworkInterfaces[0].PrivateIpAddresses {
				if assignedIP := net.ParseIP(*assignedIPv4.PrivateIpAddress); assignedIP != nil {
					assignedIPs = append(assignedIPs, assignedIP.String())
				}
			}
		}
		if deleteOp {
			return !sets.NewString(assignedIPs...).HasAny(ips...), nil
		} else {
			return sets.NewString(assignedIPs...).HasAll(ips...), nil
		}
	})
}

func (a *AWS) getSubnet(networkInterface *ec2.InstanceNetworkInterface) (*net.IPNet, *net.IPNet, error) {
	describeOutput, err := a.client.DescribeSubnets(&ec2.DescribeSubnetsInput{
		SubnetIds: []*string{networkInterface.SubnetId},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error: cannot list ec2 subnets, err: %v", err)
	}
	if len(describeOutput.Subnets) > 1 {
		return nil, nil, fmt.Errorf("error: multiple subnets found for the subnet ID: %s", *networkInterface.SubnetId)
	}

	var v4Subnet, v6Subnet *net.IPNet
	subnet := describeOutput.Subnets[0]
	if subnet.CidrBlock != nil && *subnet.CidrBlock != "" {
		_, subnet, err := net.ParseCIDR(*subnet.CidrBlock)
		if err != nil {
			return nil, nil, fmt.Errorf("error: unable to parse IPv4 subnet, err: %v", err)
		}
		v4Subnet = subnet
	}

	// I don't know what it means to have several IPv6 CIDR blocks defined for
	// one subnet, specially given that you can only have one IPv4 CIDR block
	// defined...¯\_(ツ)_/¯
	// Let's just pick the first.
	if len(subnet.Ipv6CidrBlockAssociationSet) > 0 && subnet.Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock != nil && *subnet.Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock != "" {
		_, subnet, err := net.ParseCIDR(*subnet.Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock)
		if err != nil {
			return nil, nil, fmt.Errorf("error: unable to parse IPv6 subnet, err: %v", err)
		}
		v6Subnet = subnet
	}

	return v4Subnet, v6Subnet, nil
}

// AWS uses a variable capacity per instance type, see:
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#AvailableIpPerENI
// Hence we need to retrieve that and then subtract the amount already assigned
// by default.
func (a *AWS) getCapacity(instanceV4Capacity, instanceV6Capacity int, networkInterface *ec2.InstanceNetworkInterface, cloudPrivateIPConfigs []*v1.CloudPrivateIPConfig) (int, int, error) {
	currentIPv4Usage, currentIPv6Usage := 0, 0
	for _, assignedIPv6 := range networkInterface.Ipv6Addresses {
		if assignedIP := net.ParseIP(*assignedIPv6.Ipv6Address); assignedIP != nil {
			currentIPv6Usage++
		}
	}
	for _, assignedIPv4 := range networkInterface.PrivateIpAddresses {
		if assignedIP := net.ParseIP(*assignedIPv4.PrivateIpAddress); assignedIP != nil {
			currentIPv4Usage++
		}
	}
	for _, cloudPrivateIPConfig := range cloudPrivateIPConfigs {
		_, ipFamily, err := cloudprivateipconfig.NameToIP(cloudPrivateIPConfig.Name)
		if err != nil {
			return 0, 0, err
		}
		if ipFamily == cloudprivateipconfig.IPv4 {
			instanceV4Capacity++
		} else if ipFamily == cloudprivateipconfig.IPv6 {
			instanceV6Capacity++
		}
	}
	return instanceV4Capacity - currentIPv4Usage, instanceV6Capacity - currentIPv6Usage, nil
}

func (a *AWS) getNetworkInterfaces(instance *ec2.Instance) ([]*ec2.InstanceNetworkInterface, error) {
	if len(instance.NetworkInterfaces) == 0 {
		return nil, NoNetworkInterfaceError
	}
	if instance.NetworkInterfaces[0] == nil {
		return nil, NoNetworkInterfaceError
	}
	return instance.NetworkInterfaces, nil
}

func (a *AWS) getInstanceCapacity(instance *ec2.Instance) (int, int, error) {
	input := &ec2.DescribeInstanceTypesInput{
		InstanceTypes: []*string{instance.InstanceType},
	}
	output, err := a.client.DescribeInstanceTypes(input)
	if err != nil {
		return -1, -1, err
	}
	if len(output.InstanceTypes) != 1 {
		return -1, -1, fmt.Errorf("multiple or no instance types found")
	}
	var instanceIPv4Capacity, instanceIPv6Capacity int
	for _, instanceType := range output.InstanceTypes {
		if networkInfo := instanceType.NetworkInfo; networkInfo != nil {
			instanceIPv4Capacity = int(awsapi.Int64Value(networkInfo.Ipv4AddressesPerInterface))
			instanceIPv6Capacity = int(awsapi.Int64Value(networkInfo.Ipv6AddressesPerInterface))
		}
	}
	return instanceIPv4Capacity, instanceIPv6Capacity, nil
}

// getInstance returns the EC2 Instance for the given node.
func (a *AWS) getInstance(node *corev1.Node) (*ec2.Instance, error) {
	instanceId, err := getInstanceIdFromProviderId(node.Spec.ProviderID)
	if err != nil {
		return nil, err
	}
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{awsapi.String(instanceId)},
	}
	result, err := a.client.DescribeInstances(input)
	if err != nil {
		return nil, fmt.Errorf("error: cannot list ec2 instance for node: %s, err: %v", node.Name, err)
	}
	instances := []*ec2.Instance{}
	for _, reservation := range result.Reservations {
		instances = append(instances, reservation.Instances...)
	}
	if len(instances) != 1 {
		return nil, fmt.Errorf("error: found conflicting instance replicas for node: %s, instances: %v", node.Name, instances)
	}
	return instances[0], nil
}

// getInstanceIdFromProviderId extracts the instance id from a given provider id.
// The provider ID should normally be passed in with aws:///<zone>/<instanceID>
// But it might also be passed in as aws://<zone>/<instanceID> and the zone might
// be omitted.
// This is what the node's providerID can look like on AWS (examples):
//
//	spec:
//	  providerID: aws:///us-west-2a/i-008447f243eead273
//	  providerID: aws://us-west-2a/i-008447f243eead273
//	  providerID: aws:///i-008447f243eead273
//
// see https://github.com/kubernetes/cloud-provider-aws/blob/5f394ba297bf280ceb3edfc38922630b4bd83f46/pkg/providers/v2/instances.go#L254
func getInstanceIdFromProviderId(providerId string) (string, error) {
	// after trimming 'aws://', the remainder will be in one of the following formats:
	// * <availability-zone>/<instance-id>
	// * /<availability-zone>/<instance-id>
	// * <instance-id>
	splitProviderId := strings.Split(strings.TrimPrefix(providerId, "aws://"), "/")
	if len(splitProviderId) > 3 {
		return "", UnexpectedURIError(providerId)
	}
	instanceId := splitProviderId[len(splitProviderId)-1]
	if instanceId == "" {
		return "", UnexpectedURIError(providerId)
	}

	return instanceId, nil
}

// sharedCredentialsFileFromDirectory returns a location (path) to the shared credentials file that was created
// using the data in the provided directory.
// This is heavily inspired and partially copied verbatim from:
// https://github.com/openshift/cluster-ingress-operator/blob/1600a0e349ef075fcb52ab65b33445e256358ab8/pkg/util/aws/shared_credentials_file.go#L26
// If file ${dir}/credentials exists then sharedCredentialsFileFromDirectory simply returns that string.
// Otherwise if such a file does not exist, sharedCredentialsFileFromDirectory will attempt to build a credentials
// file from ${dir}/aws_access_key_id and ${dir}/aws_secret_access_key.
func sharedCredentialsFileFromDirectory(dir string) (string, error) {
	fCredentials := filepath.Join(dir, "credentials")
	fAccessKeyID := filepath.Join(dir, "aws_access_key_id")
	fSecretAccessKey := filepath.Join(dir, "aws_secret_access_key")

	if _, err := os.Stat(fCredentials); err == nil {
		return fCredentials, nil
	}

	klog.Infof("Could not find file %s, trying to build temp file from %s and %s",
		fCredentials, fAccessKeyID, fSecretAccessKey)

	accessKeyID, err := os.ReadFile(fAccessKeyID)
	if err != nil {
		return "", errors.Wrapf(err, "failed to read file %s", fAccessKeyID)
	}
	secretAccessKey, err := os.ReadFile(fSecretAccessKey)
	if err != nil {
		return "", errors.Wrapf(err, "failed to read file %s", fSecretAccessKey)
	}
	data := newConfigForStaticCreds(string(accessKeyID), string(secretAccessKey))

	f, err := os.CreateTemp("", "aws-shared-credentials")
	if err != nil {
		return "", errors.Wrap(err, "failed to create file for shared credentials")
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return "", errors.Wrapf(err, "failed to write credentials to %s", f.Name())
	}
	return f.Name(), nil
}

// newConfigForStaticCreds is copied verbatim from:
// https://github.com/openshift/cluster-ingress-operator/blob/1600a0e349ef075fcb52ab65b33445e256358ab8/pkg/util/aws/shared_credentials_file.go#L52
func newConfigForStaticCreds(accessKey string, accessSecret string) []byte {
	buf := &bytes.Buffer{}
	fmt.Fprint(buf, "[default]\n")
	fmt.Fprintf(buf, "aws_access_key_id = %s\n", accessKey)
	fmt.Fprintf(buf, "aws_secret_access_key = %s\n", accessSecret)
	return buf.Bytes()
}
