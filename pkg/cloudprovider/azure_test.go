package cloudprovider

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/onsi/gomega"
	"k8s.io/utils/ptr"
)

func Test_updateNICIPConfigurations(t *testing.T) {
	testIP := "127.0.0.2"

	primaryASGs := []*armnetwork.ApplicationSecurityGroup{
		{ID: ptr.To("primary-asg-id")},
	}
	primarySubnet := armnetwork.Subnet{
		ID: ptr.To("primary-subnet-id"),
	}
	primaryLoadBalancerAddressPools := []*armnetwork.BackendAddressPool{
		{ID: ptr.To("primary-lb-addresspool-id")},
	}

	// primaryIPConfiguration is the primary IPConfiguration of the NIC
	primaryIPConfiguration := armnetwork.InterfaceIPConfiguration{
		ID:   ptr.To("primary-id"),
		Name: ptr.To("primary-name"),
		Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
			ApplicationSecurityGroups:       primaryASGs,
			LoadBalancerBackendAddressPools: primaryLoadBalancerAddressPools,
			Primary:                         ptr.To(true),
			PrivateIPAddress:                ptr.To("127.0.0.1"),
			PrivateIPAllocationMethod:       ptr.To(armnetwork.IPAllocationMethodDynamic),
			Subnet:                          &primarySubnet,
		},
		Type: ptr.To("primary-type"),
		Etag: ptr.To("primary-etag"),
	}

	// testIPGenerated is the IPConfiguration generated for the testIP. It does not contain fields which are only returned by the server.
	testIPGenerated := armnetwork.InterfaceIPConfiguration{
		Name: ptr.To("test-node_127.0.0.2"),
		Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
			PrivateIPAddress:          &testIP,
			ApplicationSecurityGroups: primaryASGs,
			Primary:                   ptr.To(false),
			PrivateIPAllocationMethod: ptr.To(armnetwork.IPAllocationMethodStatic),
			Subnet:                    &primarySubnet,
		},
	}

	// testIPMatch is an additional IPConfiguration with the test IP which matches the desired state
	testIPMatch := armnetwork.InterfaceIPConfiguration{
		ID:   ptr.To("testipmatch-id"),
		Name: ptr.To("test-node_127.0.0.2"),
		Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
			PrivateIPAddress:          &testIP,
			ApplicationSecurityGroups: primaryASGs,
			Primary:                   ptr.To(false),
			PrivateIPAllocationMethod: ptr.To(armnetwork.IPAllocationMethodStatic),
			Subnet:                    &primarySubnet,
		},
		Type: ptr.To("testipmatch-type"),
		Etag: ptr.To("testipmatch-etag"),
	}
	// testIPNoMatch is an additional IPConfiguration with the test IP which does not match the desired state
	testIPNoMatch := armnetwork.InterfaceIPConfiguration{
		ID:   ptr.To("testipnomatch-id"),
		Name: ptr.To("test-node_127.0.0.2"),
		Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
			PrivateIPAddress:                &testIP,
			ApplicationSecurityGroups:       primaryASGs,
			LoadBalancerBackendAddressPools: primaryLoadBalancerAddressPools,
			Primary:                         ptr.To(false),
			PrivateIPAllocationMethod:       ptr.To(armnetwork.IPAllocationMethodStatic),
			Subnet:                          &primarySubnet,
		},
		Type: ptr.To("testipnomatch-type"),
		Etag: ptr.To("testipnomatch-etag"),
	}

	// altIP is an additional IPConfiguration which does not have the test IP
	altIP := armnetwork.InterfaceIPConfiguration{
		ID:   ptr.To("altip-id"),
		Name: ptr.To("altip-name"),
		Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
			PrivateIPAddress:          ptr.To("127.0.0.2"),
			Primary:                   ptr.To(false),
			PrivateIPAllocationMethod: ptr.To(armnetwork.IPAllocationMethodStatic),
			Subnet:                    &primarySubnet,
		},
		Type: ptr.To("altip-type"),
		Etag: ptr.To("altip-etag"),
	}

	type args struct {
		ipConfigurations []*armnetwork.InterfaceIPConfiguration
	}
	tests := []struct {
		name          string
		args          args
		wantIPConfigs []*armnetwork.InterfaceIPConfiguration
		wantErr       bool
	}{
		{
			name: "should add egress ip when there are none",
			args: args{
				ipConfigurations: []*armnetwork.InterfaceIPConfiguration{
					&primaryIPConfiguration,
				},
			},
			wantIPConfigs: []*armnetwork.InterfaceIPConfiguration{
				&primaryIPConfiguration,
				&testIPGenerated,
			},
			wantErr: false,
		},
		{
			name: "should not add egress ip when defined and up to date",
			args: args{
				ipConfigurations: []*armnetwork.InterfaceIPConfiguration{
					&primaryIPConfiguration,
					&testIPMatch,
				},
			},
			wantErr: true,
		},
		{
			name: "should update egress ip when defined but not up to date",
			args: args{
				ipConfigurations: []*armnetwork.InterfaceIPConfiguration{
					&primaryIPConfiguration,
					&testIPNoMatch,
				},
			},
			wantIPConfigs: []*armnetwork.InterfaceIPConfiguration{
				&primaryIPConfiguration,
				&testIPGenerated,
			},
			wantErr: false,
		},
		{
			name: "should update egress ip in place when defined but not up to date",
			args: args{
				ipConfigurations: []*armnetwork.InterfaceIPConfiguration{
					&primaryIPConfiguration,
					&testIPNoMatch,
					&altIP,
				},
			},
			wantIPConfigs: []*armnetwork.InterfaceIPConfiguration{
				&primaryIPConfiguration,
				&testIPGenerated,
				&altIP,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			nicProperties := &armnetwork.InterfacePropertiesFormat{
				IPConfigurations: tt.args.ipConfigurations,
			}

			err := updateNICIPConfigurations(testIP, "test-node", nicProperties)
			if (err != nil) != tt.wantErr {
				t.Errorf("updateNICIPConfigurations() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil {
				g.Expect(nicProperties.IPConfigurations).To(gomega.Equal(tt.wantIPConfigs), "IPConfigurations")
			}
		})
	}
}

func Test_ipconfigMatches(t *testing.T) {
	// baseIPConfiguration returns an IPConfiguration with basic input fields set to test values
	baseIPConfiguration := func() *armnetwork.InterfaceIPConfiguration {
		return &armnetwork.InterfaceIPConfiguration{
			Name: ptr.To("test-name"),
			Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
				ApplicationSecurityGroups: []*armnetwork.ApplicationSecurityGroup{
					{ID: ptr.To("asg-id")},
				},
				Primary:                   ptr.To(false),
				PrivateIPAddress:          ptr.To("127.0.0.1"),
				PrivateIPAllocationMethod: ptr.To(armnetwork.IPAllocationMethodStatic),
				Subnet: &armnetwork.Subnet{
					ID: ptr.To("test-subnet-id"),
				},
			},
		}
	}

	// populatedBaseIPConfiguration returns an IPConfiguration with the same
	// fields set as baseIPConfiguration, but with additional values set which
	// would have been populated when returned in an API response
	populatedBaseIPConfiguration := func() *armnetwork.InterfaceIPConfiguration {
		ipConfiguration := baseIPConfiguration()

		ipConfiguration.ID = ptr.To("test-id")
		ipConfiguration.Etag = ptr.To("test-etag")
		ipConfiguration.Properties.ProvisioningState = ptr.To(armnetwork.ProvisioningStateSucceeded)
		ipConfiguration.Properties.ApplicationSecurityGroups[0].Etag = ptr.To("asg-etag")
		ipConfiguration.Properties.ApplicationSecurityGroups[0].Properties = &armnetwork.ApplicationSecurityGroupPropertiesFormat{
			ProvisioningState: ptr.To(armnetwork.ProvisioningStateSucceeded),
			ResourceGUID:      ptr.To("asg-guid"),
		}
		ipConfiguration.Properties.Subnet.Name = ptr.To("subnet-name")
		ipConfiguration.Properties.Subnet.Etag = ptr.To("subnet-etag")
		ipConfiguration.Properties.Subnet.Properties = &armnetwork.SubnetPropertiesFormat{
			ProvisioningState: ptr.To(armnetwork.ProvisioningStateSucceeded),
		}

		return ipConfiguration
	}

	type args struct {
		current func() *armnetwork.InterfaceIPConfiguration
		desired func() *armnetwork.InterfaceIPConfiguration
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "identical base fields",
			args: args{
				current: populatedBaseIPConfiguration,
				desired: baseIPConfiguration,
			},
			want: true,
		},
		{
			name: "private IP allocation method differs should not match",
			args: args{
				current: func() *armnetwork.InterfaceIPConfiguration {
					ipConfig := populatedBaseIPConfiguration()
					ipConfig.Properties.PrivateIPAllocationMethod = ptr.To(armnetwork.IPAllocationMethodDynamic)
					return ipConfig
				},
				desired: baseIPConfiguration,
			},
			want: false,
		},
		{
			name: "primary differs should not match",
			args: args{
				current: func() *armnetwork.InterfaceIPConfiguration {
					ipConfig := populatedBaseIPConfiguration()
					ipConfig.Properties.Primary = ptr.To(true)
					return ipConfig
				},
				desired: baseIPConfiguration,
			},
			want: false,
		},
		{
			name: "subnet differs should not match",
			args: args{
				current: func() *armnetwork.InterfaceIPConfiguration {
					ipConfig := populatedBaseIPConfiguration()
					ipConfig.Properties.Subnet.ID = ptr.To("subnet-id-alt")
					return ipConfig
				},
				desired: baseIPConfiguration,
			},
			want: false,
		},
		{
			name: "egress IP has LoadBalancerBackendAddressPools should not match",
			args: args{
				current: func() *armnetwork.InterfaceIPConfiguration {
					ipConfig := populatedBaseIPConfiguration()
					ipConfig.Properties.LoadBalancerBackendAddressPools = []*armnetwork.BackendAddressPool{
						{
							ID:         ptr.To("lb-pool-id"),
							Name:       ptr.To("lb-pool-name"),
							Properties: &armnetwork.BackendAddressPoolPropertiesFormat{},
							Etag:       ptr.To("lb-pool-etag"),
						},
					}
					return ipConfig
				},
				desired: baseIPConfiguration,
			},
			want: false,
		},
		{
			name: "extra application security group should not match",
			args: args{
				current: func() *armnetwork.InterfaceIPConfiguration {
					ipConfig := populatedBaseIPConfiguration()
					ipConfig.Properties.ApplicationSecurityGroups = append(ipConfig.Properties.ApplicationSecurityGroups, &armnetwork.ApplicationSecurityGroup{
						ID: ptr.To("asg-id-alt"),
					})
					return ipConfig
				},
				desired: baseIPConfiguration,
			},
			want: false,
		},
		{
			name: "missing application security group should not match",
			args: args{
				current: func() *armnetwork.InterfaceIPConfiguration {
					ipConfig := populatedBaseIPConfiguration()
					ipConfig.Properties.ApplicationSecurityGroups = nil
					return ipConfig
				},
				desired: baseIPConfiguration,
			},
			want: false,
		},
		{
			name: "multiple application security groups differ by one should not match",
			args: args{
				current: func() *armnetwork.InterfaceIPConfiguration {
					ipConfig := populatedBaseIPConfiguration()
					ipConfig.Properties.ApplicationSecurityGroups = append(ipConfig.Properties.ApplicationSecurityGroups, &armnetwork.ApplicationSecurityGroup{
						ID: ptr.To("asg-id-alt"),
					})
					return ipConfig
				},
				desired: func() *armnetwork.InterfaceIPConfiguration {
					ipConfig := populatedBaseIPConfiguration()
					ipConfig.Properties.ApplicationSecurityGroups = append(ipConfig.Properties.ApplicationSecurityGroups, &armnetwork.ApplicationSecurityGroup{
						ID: ptr.To("asg-id-alt2"),
					})
					return ipConfig
				},
			},
			want: false,
		},
		{
			name: "same application security groups in different order should match",
			args: args{
				current: func() *armnetwork.InterfaceIPConfiguration {
					ipConfig := populatedBaseIPConfiguration()
					ipConfig.Properties.ApplicationSecurityGroups = append(ipConfig.Properties.ApplicationSecurityGroups, &armnetwork.ApplicationSecurityGroup{
						ID: ptr.To("asg-id-alt"),
					})
					return ipConfig
				},
				desired: func() *armnetwork.InterfaceIPConfiguration {
					ipConfig := populatedBaseIPConfiguration()
					ipConfig.Properties.ApplicationSecurityGroups = append([]*armnetwork.ApplicationSecurityGroup{{ID: ptr.To("asg-id-alt")}}, ipConfig.Properties.ApplicationSecurityGroups...)
					return ipConfig
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipconfigMatches(tt.args.current(), tt.args.desired()); got != tt.want {
				t.Errorf("ipconfigMatches() = %v, want %v", got, tt.want)
			}
		})
	}
}
