package cloudprovider

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	novaservers "github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	neutronnetworks "github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	neutronports "github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	neutronsubnets "github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	th "github.com/gophercloud/gophercloud/testhelper"
	testclient "github.com/gophercloud/gophercloud/testhelper/client"
	v1 "github.com/openshift/api/cloudnetwork/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	novaDeviceOwner = "compute:nova"
)

var serverMap = map[string]novaservers.Server{
	"9e5476bd-a4ec-4653-93d6-72c93aa682ba": {
		ID:   "9e5476bd-a4ec-4653-93d6-72c93aa682ba",
		Name: "server1",
	},
	"b5d5889f-76f9-46b1-8af9-bfdf81e96616": {
		ID:   "b5d5889f-76f9-46b1-8af9-bfdf81e96616",
		Name: "server2",
	},
	"95dda9a5-7bd9-494f-8b84-81c1629915bc": {
		ID:   "95dda9a5-7bd9-494f-8b84-81c1629915bc",
		Name: "server3",
	},
}

var portMap = map[string]neutronports.Port{
	"9ab428d4-58f8-42d7-9672-90c3f5641f83": {
		ID:        "9ab428d4-58f8-42d7-9672-90c3f5641f83",
		NetworkID: "57d1274f-4717-43f1-88ec-0944546a14ef",
		Name:      "server1-port1",
		FixedIPs: []neutronports.IP{
			{
				SubnetID:  "49895d6d-6972-4198-8afa-ada96e1daaef",
				IPAddress: "192.0.2.10",
			},
			{
				SubnetID:  "de0cda14-6ac6-4439-bc94-da0a27938b7b",
				IPAddress: "2000::10",
			},
		},
		AllowedAddressPairs: []neutronports.AddressPair{
			{
				IPAddress: "192.0.2.1",
			},
			{
				IPAddress: "192.0.2.2",
			},
		},
		DeviceID:    "9e5476bd-a4ec-4653-93d6-72c93aa682ba",
		DeviceOwner: novaDeviceOwner,
	},
	"eec4c521-4288-4d54-939a-1ea32cc35c37": {
		ID:        "eec4c521-4288-4d54-939a-1ea32cc35c37",
		NetworkID: "57d1274f-4717-43f1-88ec-0944546a14ef",
		Name:      "server1-port2",
		FixedIPs: []neutronports.IP{
			{
				SubnetID:  "49895d6d-6972-4198-8afa-ada96e1daaef",
				IPAddress: "192.0.2.20",
			},
			{
				SubnetID:  "de0cda14-6ac6-4439-bc94-da0a27938b7b",
				IPAddress: "2000::20",
			},
		},
		DeviceID:    "9e5476bd-a4ec-4653-93d6-72c93aa682ba",
		DeviceOwner: novaDeviceOwner,
	},
	"319bb795-b08e-4b8f-b9d2-b3a7c8c1ab45": {
		ID:        "319bb795-b08e-4b8f-b9d2-b3a7c8c1ab45",
		NetworkID: "57d1274f-4717-43f1-88ec-0944546a14ef",
		Name:      "server2-port1",
		FixedIPs: []neutronports.IP{
			{
				SubnetID:  "49895d6d-6972-4198-8afa-ada96e1daaef",
				IPAddress: "192.0.2.11",
			},
			{
				SubnetID:  "de0cda14-6ac6-4439-bc94-da0a27938b7b",
				IPAddress: "2000::11",
			},
		},
		DeviceID:    "b5d5889f-76f9-46b1-8af9-bfdf81e96616",
		DeviceOwner: novaDeviceOwner,
	},
	"ed5351a4-08b5-4ac6-b9c9-bbbe557df381": {
		ID:        "ed5351a4-08b5-4ac6-b9c9-bbbe557df381",
		NetworkID: "e3ddc5f8-0306-4039-872e-8c8fe40b42fc",
		Name:      "server2-port2",
		FixedIPs: []neutronports.IP{
			{
				SubnetID:  "81363362-e826-4be5-93e6-c4ff6ad8b715",
				IPAddress: "192.0.3.11",
			},
			{
				SubnetID:  "47cd458e-c3f4-42c7-aa9e-0303a24205b6",
				IPAddress: "2001::11",
			},
		},
		DeviceID:    "b5d5889f-76f9-46b1-8af9-bfdf81e96616",
		DeviceOwner: novaDeviceOwner,
	},
	"aafecceb-d986-42b6-8ea7-449c7cacb7d9": {
		ID:          "aafecceb-d986-42b6-8ea7-449c7cacb7d9",
		DeviceOwner: egressIPTag,
		DeviceID:    generateDeviceID("node2"),
		AllowedAddressPairs: []neutronports.AddressPair{
			{
				IPAddress:  "192.168.123.10",
				MACAddress: "",
			},
		},
	},
	"638a74cd-d894-45b1-8865-4945c4911145": {
		ID:          "638a74cd-d894-45b1-8865-4945c4911145",
		NetworkID:   "57d1274f-4717-43f1-88ec-0944546a14ef",
		Name:        "unbound-port",
		DeviceOwner: egressIPTag,
		DeviceID:    generateDeviceID("node1"),
		FixedIPs: []neutronports.IP{
			{
				SubnetID:  "49895d6d-6972-4198-8afa-ada96e1daaef",
				IPAddress: "192.0.2.12",
			},
			{
				SubnetID:  "de0cda14-6ac6-4439-bc94-da0a27938b7b",
				IPAddress: "2000::12",
			},
		},
	},
	"fa65cd2e-5a85-4b8f-9138-40509eb062ca": {
		ID:           "fa65cd2e-5a85-4b8f-9138-40509eb062ca",
		NetworkID:    "cae78aec-16db-483a-9927-c427d4cff77f",
		Name:         "port-multiple-ipv4-cidrs",
		Description:  "",
		AdminStateUp: false,
		Status:       "",
		MACAddress:   "",
		FixedIPs: []neutronports.IP{
			{
				SubnetID:  "379db076-b0a3-4ecd-84f6-3701137aeaea",
				IPAddress: "192.168.124.10",
			},
			{
				SubnetID:  "3b05bf67-4868-4d7c-9a3d-39d1e1008d71",
				IPAddress: "192.168.125.11",
			},
		},
	},
	"84da9456-8a1d-4d3f-9e15-821e29b5e7c8": {
		ID:        "84da9456-8a1d-4d3f-9e15-821e29b5e7c8",
		NetworkID: "57d1274f-4717-43f1-88ec-0944546a14ef",
		Name:      "multi-az-port",
		FixedIPs: []neutronports.IP{
			{
				SubnetID:  "49895d6d-6972-4198-8afa-ada96e1daaef",
				IPAddress: "192.0.2.10",
			},
			{
				SubnetID:  "de0cda14-6ac6-4439-bc94-da0a27938b7b",
				IPAddress: "2000::10",
			},
		},
		AllowedAddressPairs: []neutronports.AddressPair{
			{
				IPAddress: "192.0.2.1",
			},
			{
				IPAddress: "192.0.2.2",
			},
		},
		DeviceID:    "50b412c1-d659-424e-8e29-5a5e5a6b5c45",
		DeviceOwner: "compute:AZhci-2",
	},
}

var networkMap = map[string]neutronnetworks.Network{
	"57d1274f-4717-43f1-88ec-0944546a14ef": {
		ID:   "57d1274f-4717-43f1-88ec-0944546a14ef",
		Name: "network1",
	},
	"e3ddc5f8-0306-4039-872e-8c8fe40b42fc": {
		ID:   "e3ddc5f8-0306-4039-872e-8c8fe40b42fc",
		Name: "network2",
	},
	"cae78aec-16db-483a-9927-c427d4cff77f": {
		ID:   "cae78aec-16db-483a-9927-c427d4cff77f",
		Name: "network-multiple-ipv4-cidrs",
	},
}

var subnetMap = map[string]neutronsubnets.Subnet{
	"49895d6d-6972-4198-8afa-ada96e1daaef": {
		ID:              "49895d6d-6972-4198-8afa-ada96e1daaef",
		NetworkID:       "57d1274f-4717-43f1-88ec-0944546a14ef",
		Name:            "network1-v4",
		Description:     "",
		IPVersion:       4,
		CIDR:            "192.0.2.0/24",
		GatewayIP:       "",
		DNSNameservers:  []string{},
		AllocationPools: []neutronsubnets.AllocationPool{},
		HostRoutes:      []neutronsubnets.HostRoute{},
		EnableDHCP:      false,
		TenantID:        "",
		ProjectID:       "",
		IPv6AddressMode: "",
		IPv6RAMode:      "",
		SubnetPoolID:    "",
		Tags:            []string{},
	},
	"de0cda14-6ac6-4439-bc94-da0a27938b7b": {
		ID:              "de0cda14-6ac6-4439-bc94-da0a27938b7b",
		NetworkID:       "57d1274f-4717-43f1-88ec-0944546a14ef",
		Name:            "network1-v6",
		Description:     "",
		IPVersion:       6,
		CIDR:            "2000::/64",
		GatewayIP:       "",
		DNSNameservers:  []string{},
		AllocationPools: []neutronsubnets.AllocationPool{},
		HostRoutes:      []neutronsubnets.HostRoute{},
		EnableDHCP:      false,
		TenantID:        "",
		ProjectID:       "",
		IPv6AddressMode: "",
		IPv6RAMode:      "",
		SubnetPoolID:    "",
		Tags:            []string{},
	},
	"81363362-e826-4be5-93e6-c4ff6ad8b715": {
		ID:              "81363362-e826-4be5-93e6-c4ff6ad8b715",
		NetworkID:       "e3ddc5f8-0306-4039-872e-8c8fe40b42fc",
		Name:            "network2-v4",
		Description:     "",
		IPVersion:       4,
		CIDR:            "192.0.3.0/24",
		GatewayIP:       "",
		DNSNameservers:  []string{},
		AllocationPools: []neutronsubnets.AllocationPool{},
		HostRoutes:      []neutronsubnets.HostRoute{},
		EnableDHCP:      false,
		TenantID:        "",
		ProjectID:       "",
		IPv6AddressMode: "",
		IPv6RAMode:      "",
		SubnetPoolID:    "",
		Tags:            []string{},
	},
	"47cd458e-c3f4-42c7-aa9e-0303a24205b6": {
		ID:              "47cd458e-c3f4-42c7-aa9e-0303a24205b6",
		NetworkID:       "e3ddc5f8-0306-4039-872e-8c8fe40b42fc",
		Name:            "network2-v6",
		Description:     "",
		IPVersion:       6,
		CIDR:            "2001::/64",
		GatewayIP:       "",
		DNSNameservers:  []string{},
		AllocationPools: []neutronsubnets.AllocationPool{},
		HostRoutes:      []neutronsubnets.HostRoute{},
		EnableDHCP:      false,
		TenantID:        "",
		ProjectID:       "",
		IPv6AddressMode: "",
		IPv6RAMode:      "",
		SubnetPoolID:    "",
		Tags:            []string{},
	},
	"379db076-b0a3-4ecd-84f6-3701137aeaea": {
		ID:              "379db076-b0a3-4ecd-84f6-3701137aeaea",
		NetworkID:       "cae78aec-16db-483a-9927-c427d4cff77f",
		Name:            "",
		Description:     "",
		IPVersion:       4,
		CIDR:            "192.168.124.0/24",
		GatewayIP:       "",
		DNSNameservers:  []string{},
		AllocationPools: []neutronsubnets.AllocationPool{},
		HostRoutes:      []neutronsubnets.HostRoute{},
		EnableDHCP:      false,
		TenantID:        "",
		ProjectID:       "",
		IPv6AddressMode: "",
		IPv6RAMode:      "",
		SubnetPoolID:    "",
		Tags:            []string{},
	},
	"3b05bf67-4868-4d7c-9a3d-39d1e1008d71": {
		ID:              "3b05bf67-4868-4d7c-9a3d-39d1e1008d71",
		NetworkID:       "cae78aec-16db-483a-9927-c427d4cff77f",
		Name:            "",
		Description:     "",
		IPVersion:       4,
		CIDR:            "192.168.125.0/24",
		GatewayIP:       "",
		DNSNameservers:  []string{},
		AllocationPools: []neutronsubnets.AllocationPool{},
		HostRoutes:      []neutronsubnets.HostRoute{},
		EnableDHCP:      false,
		TenantID:        "",
		ProjectID:       "",
		IPv6AddressMode: "",
		IPv6RAMode:      "",
		SubnetPoolID:    "",
		Tags:            []string{},
	},
}

// HandleServerGet sets up the test servers to respond to a server Get request.
func HandleServerGet(t *testing.T) {
	for id := range serverMap {
		th.Mux.HandleFunc("/servers/"+id, func(w http.ResponseWriter, r *http.Request) {
			th.TestMethod(t, r, "GET")
			th.TestHeader(t, r, "X-Auth-Token", testclient.TokenID)
			th.TestHeader(t, r, "Accept", "application/json")

			serverID := strings.Split(r.URL.Path, "/")[2]
			server, ok := serverMap[serverID]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			var out []byte
			out, err := json.Marshal(map[string]novaservers.Server{
				"server": server,
			})
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(w, string(out))
		})
	}
}

func HandleSubnetList(t *testing.T) {
	th.Mux.HandleFunc("/subnets", func(w http.ResponseWriter, r *http.Request) {
		th.TestMethod(t, r, "GET")
		th.TestHeader(t, r, "X-Auth-Token", testclient.TokenID)

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		networkID := r.URL.Query().Get("network_id")

		var subnetList []neutronsubnets.Subnet
		for _, s := range subnetMap {
			if networkID == "" || networkID == s.NetworkID {
				subnetList = append(subnetList, s)
			}
		}

		var out []byte
		out, err := json.Marshal(map[string][]subnets.Subnet{
			"subnets": subnetList,
		})
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(w, string(out))
	})
}

func HandlePortListAndCreation(t *testing.T) {
	th.Mux.HandleFunc("/ports", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "POST" {
			t.Errorf("Request method = %v, expected GET|POST", r.Method)
		}
		th.TestHeader(t, r, "X-Auth-Token", testclient.TokenID)

		// GET case.
		if r.Method == "GET" {
			portListHandler(t, w, r)
			return
		}

		// POST case.
		th.TestHeader(t, r, "Content-Type", "application/json")
		th.TestHeader(t, r, "Accept", "application/json")
		portCreationHandler(t, w, r)
	})
}

func portListHandler(t *testing.T, w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	deviceID := r.URL.Query().Get("device_id")
	deviceOwner := r.URL.Query().Get("device_owner")
	networkID := r.URL.Query().Get("network_id")
	IPs := r.URL.Query()["fixed_ips"]
	IP := ""
	for _, val := range IPs {
		if strings.HasPrefix(val, "ip_address=") {
			IP = strings.TrimPrefix(val, "ip_address=")
			break
		}
	}

	var portList []neutronports.Port
	for _, p := range portMap {
		if deviceID != "" && deviceID != p.DeviceID {
			continue
		}
		if deviceOwner != "" && deviceOwner != p.DeviceOwner {
			continue
		}
		if networkID != "" && networkID != p.NetworkID {
			continue
		}
		if IP != "" {
			matched := false
			for _, fixedIP := range p.FixedIPs {
				if fixedIP.IPAddress == IP {
					matched = true
				}
			}
			if !matched {
				continue
			}
		}
		portList = append(portList, p)
	}

	var out []byte
	out, err := json.Marshal(map[string][]neutronports.Port{
		"ports": portList,
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(w, string(out))
}

func portCreationHandler(t *testing.T, w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("Unexpected error when reading from body of POST request to /ports, err %q", err)
	}

	// This will only allow the creation of a single port. In order to test bulk creation, add a second
	// branch that parses var q map[string][]neutronports.Port with key "ports" instead of "port".
	var p map[string]neutronports.Port
	err = json.Unmarshal(body, &p)
	if err != nil {
		t.Fatalf("Unexpected error during unmarshal operation, err: %q", err)
	}
	if _, ok := p["port"]; !ok {
		t.Fatalf("Invalid request for port creation, expected to see key 'port'")
	}

	newPort := p["port"]
	networkFound := false
	// Check first if the network exists
	for _, n := range networkMap {
		if n.ID == newPort.NetworkID {
			networkFound = true
			break
		}
	}
	if !networkFound {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// Now, check if the subnet exists
	subnetFound := false
outer:
	for _, fip := range newPort.FixedIPs {
		for _, s := range subnetMap {
			if s.ID == fip.SubnetID {
				subnetFound = true
				break outer
			}
		}
	}
	if !subnetFound {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	for _, v := range portMap {
		if newPort.NetworkID == v.NetworkID {
			for _, fip := range newPort.FixedIPs {
				for _, ffip := range v.FixedIPs {
					if fip.SubnetID == ffip.SubnetID && fip.IPAddress == ffip.IPAddress {
						w.WriteHeader(http.StatusConflict)
						return
					}
				}
			}
		}
	}

	// Generate and assign a new UUID to the newly created port.
	// UUIDs are extremely unlikely to overlap, so looping through this a
	// max of 10 times should be enough.
	portAdded := false
	for i := 0; i < 10; i++ {
		newPort.ID = uuid.New().String()
		if _, ok := portMap[newPort.ID]; ok {
			continue
		}
		portMap[newPort.ID] = newPort
		portAdded = true
		break
	}
	if !portAdded {
		t.Fatalf("Could not add port to current portMap, err: %q", err)
	}
	// Register this new port with the port update and tag update handlers.
	HandlePortGetUpdateDelete(t, newPort.ID)

	// Remarshal the object so that  we can print it
	b, err := json.Marshal(map[string]neutronports.Port{"port": newPort})
	if err != nil {
		t.Fatalf("Unexpected error during marshal operation, err: %q", err)
	}
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, string(b))
}

func HandlePortGetUpdateDelete(t *testing.T, portID string) {
	//	var updateCounter int
	var updateCounter int
	f := func(id string) {
		th.Mux.HandleFunc("/ports/"+id, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" && r.Method != "PUT" && r.Method != "DELETE" {
				t.Errorf("Request method = %v, expected GET|PUT", r.Method)
			}
			th.TestHeader(t, r, "X-Auth-Token", testclient.TokenID)

			// Retrieve existing port (GET + UPDATE + DELETE common)
			portID := strings.Split(r.URL.Path, "/")[2]
			port, ok := portMap[portID]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			// DELETE
			if r.Method == "DELETE" {
				delete(portMap, portID)
				w.WriteHeader(http.StatusAccepted)
				fmt.Fprintf(w, "")
				return
			}

			// GET + UPDATE common
			th.TestHeader(t, r, "Accept", "application/json")

			// GET
			if r.Method == "GET" {
				var out []byte
				out, err := json.Marshal(map[string]neutronports.Port{
					"port": port,
				})
				if err != nil {
					t.Fatal(err)
				}
				fmt.Fprintf(w, string(out))
				return
			}

			// PUT
			th.TestHeader(t, r, "Content-Type", "application/json")
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("Unexpected error when reading from body of POST request to /ports, err %q", err)
			}

			// Make sure that the If-Match header is set.
			if len(r.Header.Values("If-Match")) == 0 {
				t.Fatalf("If-Match header not set for PUT request for port with ID %s", portID)
			}
			// Simulate revision number conflicts - every second port update request will fail.
			updateCounter++
			if updateCounter%2 == 1 {
				w.WriteHeader(http.StatusPreconditionFailed)
				fmt.Fprintf(w, "RevisionNumberConstraintFailed")
				return
			}

			// Unmarshal into existing port to update it.
			// Then, update the AllowedAddressPairs. This is the only field
			// that this mock can handle currently.
			var updateRequest map[string]neutronports.Port
			err = json.Unmarshal(body, &updateRequest)
			if err != nil {
				t.Fatalf("Unexpected error during unmarshal operation, err: %q", err)
			}
			if _, ok := updateRequest["port"]; !ok {
				t.Fatalf("Invalid request for port creation, expected to see key 'port'")
			}
			port.AllowedAddressPairs = updateRequest["port"].AllowedAddressPairs

			portMap[port.ID] = port
			b, err := json.Marshal(port)
			if err != nil {
				t.Fatalf("Unexpected error during marshal operation, err: %q", err)
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, string(b))
		})
	}

	// If not portID is specified, do this for all ports in the map.
	if portID == "" {
		for id := range portMap {
			f(id)
		}
		return
	}
	// If a portID is specified, do this for the given portID.
	f(portID)
}

func TestOpenStackPlugin(t *testing.T) {
	th.SetupHTTP()
	defer th.TeardownHTTP()

	HandleSubnetList(t)
	HandlePortGetUpdateDelete(t, "")
	HandlePortListAndCreation(t)
	HandleServerGet(t)

	o := OpenStack{
		CloudProvider: CloudProvider{},
		novaClient:    testclient.ServiceClient(),
		neutronClient: testclient.ServiceClient(),
	}

	// Get EgressIP information of a node where everything is in order.
	n2 := &corev1.Node{}
	n2.Name = "node2"
	n2.Spec.ProviderID = "openstack:///b5d5889f-76f9-46b1-8af9-bfdf81e96616"
	n2.Status.Addresses = []corev1.NodeAddress{
		{
			Type:    corev1.NodeInternalIP,
			Address: "192.0.2.10",
		},
		{
			Type:    corev1.NodeInternalIP,
			Address: "2000::10",
		},
	}
	nodeEgressIPConfiguration, err := o.GetNodeEgressIPConfiguration(n2, nil)
	if err != nil {
		t.Fatalf("TestOpenStackPlugin: Could not generate NodeEgressIPConfiguration, err: %q", err)
	}
	expectedNodeEgressIPConfig := []NodeEgressIPConfiguration{
		{
			Interface: "319bb795-b08e-4b8f-b9d2-b3a7c8c1ab45",
			IFAddr: ifAddr{
				IPv4: "192.0.2.0/24",
				IPv6: "2000::/64",
			},
			Capacity: capacity{
				IP: openstackMaxCapacity,
			},
		},
	}
	if len(expectedNodeEgressIPConfig) != len(nodeEgressIPConfiguration) {
		// Resolve pointers so that this becomes human readable.
		got := ""
		for _, v := range nodeEgressIPConfiguration {
			got = fmt.Sprintf("%s %v", got, *v)
		}
		t.Fatalf("TestOpenStackPlugin: nodeEgressIPConfiguration does not match. Got '%v', expected '%v'", got, expectedNodeEgressIPConfig)
	}
	for _, config := range nodeEgressIPConfiguration {
		matched := false
		for _, expectedConfig := range expectedNodeEgressIPConfig {
			if reflect.DeepEqual(config, &expectedConfig) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("TestOpenStackPlugin: nodeEgressIPConfiguration does not match. Config '%v' not found, expected '%v'", config, expectedNodeEgressIPConfig)
		}
	}

	// Now, try making several invalid assignments.
	err = o.AssignPrivateIP(net.ParseIP("192.168.1.20"), n2)
	errString := "could not assign IP address 192.168.1.20 to node node2"
	if err == nil || err.Error() != errString {
		t.Fatalf("TestOpenStackPlugin: Unexpected error, got '%q' but expected '%s'", err, errString)
	}

	// IP address 192.0.2.20 is already held by another device (server1-port2).
	err = o.AssignPrivateIP(net.ParseIP("192.0.2.20"), n2)
	errString = "but got 409 instead"
	if err == nil || !strings.Contains(err.Error(), errString) {
		t.Fatalf("TestOpenStackPlugin: Unexpected error, got '%q' but expected error to contain '%s'", err, errString)
	}

	// Make a successful assignment.
	err = o.AssignPrivateIP(net.ParseIP("192.0.2.50"), n2)
	if err != nil {
		t.Fatalf("TestOpenStackPlugin: Unexpected error, got '%q' but expected <nil>", err)
	}

	// Unrelease an unbound IP address.
	err = o.ReleasePrivateIP(net.ParseIP("192.168.1.20"), n2)
	errString = "the requested IP for removal is not assigned"
	if err == nil || err.Error() != errString {
		t.Fatalf("TestOpenStackPlugin: Unexpected error, got '%q' but expected '%s'", err, errString)
	}

	// Make a successful release request.
	err = o.ReleasePrivateIP(net.ParseIP("192.0.2.50"), n2)
	if err != nil {
		t.Fatalf("TestOpenStackPlugin: Unexpected error, got '%q' but expected <nil>", err)
	}

	// Try releasing the same IP again.
	err = o.ReleasePrivateIP(net.ParseIP("192.0.2.50"), n2)
	errString = "the requested IP for removal is not assigned"
	if err == nil || err.Error() != errString {
		t.Fatalf("TestOpenStackPlugin: Unexpected error, got '%q' but expected '%s'", err, errString)
	}
}

func TestGetNodeEgressIPConfiguration(t *testing.T) {
	th.SetupHTTP()
	defer th.TeardownHTTP()

	HandleSubnetList(t)
	HandlePortGetUpdateDelete(t, "")
	HandlePortListAndCreation(t)
	HandleServerGet(t)

	o := OpenStack{
		CloudProvider: CloudProvider{},
		novaClient:    testclient.ServiceClient(),
		neutronClient: testclient.ServiceClient(),
	}

	tcs := map[string]struct {
		node                       *corev1.Node
		expectedNodeEgressIPConfig []NodeEgressIPConfiguration
		errString                  string
	}{
		"Invalid node": {
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
				},
				Spec: corev1.NodeSpec{
					ProviderID: "openstack:///9e5476bd-a4ec-4653-93d6-72c93aa682ba",
				},
			},
			errString: "is attached more than once to node",
		},
		"Valid node 0": {
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node2",
				},
				Spec: corev1.NodeSpec{
					ProviderID: "openstack:///b5d5889f-76f9-46b1-8af9-bfdf81e96616",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "192.0.2.10",
						},
						{
							Type:    corev1.NodeInternalIP,
							Address: "2000::10",
						},
					},
				},
			},
			expectedNodeEgressIPConfig: []NodeEgressIPConfiguration{
				{
					Interface: "319bb795-b08e-4b8f-b9d2-b3a7c8c1ab45",
					IFAddr: ifAddr{
						IPv4: "192.0.2.0/24",
						IPv6: "2000::/64",
					},
					Capacity: capacity{
						IP: openstackMaxCapacity,
					},
				},
			},
		},
		"Valid node 1": {
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node2",
				},
				Spec: corev1.NodeSpec{
					ProviderID: "openstack:///b5d5889f-76f9-46b1-8af9-bfdf81e96616",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "192.0.3.10",
						},
						{
							Type:    corev1.NodeInternalIP,
							Address: "2001::10",
						},
					},
				},
			},
			expectedNodeEgressIPConfig: []NodeEgressIPConfiguration{
				{
					Interface: "ed5351a4-08b5-4ac6-b9c9-bbbe557df381",
					IFAddr: ifAddr{
						IPv4: "192.0.3.0/24",
						IPv6: "2001::/64",
					},
					Capacity: capacity{
						IP: openstackMaxCapacity,
					},
				},
			},
		},
		"Valid node 2": {
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node2",
				},
				Spec: corev1.NodeSpec{
					ProviderID: "openstack:///b5d5889f-76f9-46b1-8af9-bfdf81e96616",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "192.0.2.10",
						},
						{
							Type:    corev1.NodeInternalIP,
							Address: "2000::10",
						},
						{
							Type:    corev1.NodeInternalIP,
							Address: "192.0.3.10",
						},
						{
							Type:    corev1.NodeInternalIP,
							Address: "2001::10",
						},
					},
				},
			},
			expectedNodeEgressIPConfig: []NodeEgressIPConfiguration{
				{
					Interface: "319bb795-b08e-4b8f-b9d2-b3a7c8c1ab45",
					IFAddr: ifAddr{
						IPv4: "192.0.2.0/24",
						IPv6: "2000::/64",
					},
					Capacity: capacity{
						IP: openstackMaxCapacity,
					},
				},
			},
		},
		"Valid node 3 - undefined behavior": {
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node2",
				},
				Spec: corev1.NodeSpec{
					ProviderID: "openstack:///b5d5889f-76f9-46b1-8af9-bfdf81e96616",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "192.0.2.10",
						},
						{
							Type:    corev1.NodeInternalIP,
							Address: "2001::10",
						},
						{
							Type:    corev1.NodeInternalIP,
							Address: "2000::10",
						},
						{
							Type:    corev1.NodeInternalIP,
							Address: "192.0.3.10",
						},
					},
				},
			},
			expectedNodeEgressIPConfig: []NodeEgressIPConfiguration{
				{
					Interface: "319bb795-b08e-4b8f-b9d2-b3a7c8c1ab45",
					IFAddr: ifAddr{
						IPv4: "192.0.2.0/24",
						IPv6: "2000::/64",
					},
					Capacity: capacity{
						IP: openstackMaxCapacity,
					},
				},
			},
		},
	}
	for testName, tc := range tcs {
		nodeEgressIPConfiguration, err := o.GetNodeEgressIPConfiguration(tc.node, nil)
		if tc.errString != "" {
			if err == nil {
				t.Fatalf("TestGetNodeEgressIPConfiguration(%s): Expected to get an error message that contains %q "+
					"but instead got no error", testName, tc.errString)
			} else if !strings.Contains(err.Error(), tc.errString) {
				t.Fatalf("TestGetNodeEgressIPConfiguration(%s): Expected to get an error message that contains %q "+
					"but instead got no error", testName, tc.errString)
			}
			continue
		}

		if err != nil {
			t.Fatalf("TestGetNodeEgressIPConfiguration(%s): Expected to get no error but instead got: %q",
				testName, err)
		}
		if len(tc.expectedNodeEgressIPConfig) != len(nodeEgressIPConfiguration) {
			// Resolve pointers so that this becomes human readable.
			got := ""
			for _, v := range nodeEgressIPConfiguration {
				got = fmt.Sprintf("%s %v", got, *v)
			}
			t.Fatalf("TestGetNodeEgressIPConfiguration(%s): nodeEgressIPConfiguration does not match. Got %q, expected %q",
				testName, got, tc.expectedNodeEgressIPConfig)
		}
		for _, config := range nodeEgressIPConfiguration {
			matched := false
			for _, expectedConfig := range tc.expectedNodeEgressIPConfig {
				if reflect.DeepEqual(config, &expectedConfig) {
					matched = true
					break
				}
			}
			if !matched {
				t.Fatalf("TestGetNodeEgressIPConfiguration(%s): nodeEgressIPConfiguration does not match. "+
					"Config '%v' not found, expected '%v'",
					testName, config, tc.expectedNodeEgressIPConfig)
			}
		}
	}
}

func TestGetNeutronPortNodeEgressIPConfiguration(t *testing.T) {
	th.SetupHTTP()
	defer th.TeardownHTTP()
	HandleSubnetList(t)
	HandlePortListAndCreation(t)

	o := OpenStack{
		CloudProvider: CloudProvider{},
		novaClient:    testclient.ServiceClient(),
		neutronClient: testclient.ServiceClient(),
	}

	tcs := []struct {
		port                  neutronports.Port
		nodeEgressIPConfig    NodeEgressIPConfiguration
		cloudPrivateIPConfigs []*v1.CloudPrivateIPConfig
		errString             string
	}{
		{
			port: portMap["9ab428d4-58f8-42d7-9672-90c3f5641f83"],
			nodeEgressIPConfig: NodeEgressIPConfiguration{
				Interface: "9ab428d4-58f8-42d7-9672-90c3f5641f83",
				IFAddr: ifAddr{
					IPv4: "192.0.2.0/24",
					IPv6: "2000::/64",
				},
				Capacity: capacity{
					IP: openstackMaxCapacity - 2, // 2 allowed_address_pairs configured on the port.
				},
			},
		},
		{
			port: portMap["9ab428d4-58f8-42d7-9672-90c3f5641f83"],
			nodeEgressIPConfig: NodeEgressIPConfiguration{
				Interface: "9ab428d4-58f8-42d7-9672-90c3f5641f83",
				IFAddr: ifAddr{
					IPv4: "192.0.2.0/24",
					IPv6: "2000::/64",
				},
				Capacity: capacity{
					IP: openstackMaxCapacity + 3 - 2, // excluding 2 allowed_address_pairs configured on the port.
				},
			},
			// Configure cloudPrivateIPConfigs with 3 ips are within neutron subnet, 1 ip outside neutron subnet.
			cloudPrivateIPConfigs: []*v1.CloudPrivateIPConfig{{ObjectMeta: metav1.ObjectMeta{
				Name: "192.0.2.10"}}, {ObjectMeta: metav1.ObjectMeta{Name: "2000..1"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "2000..2"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "10.10.10.1"}}},
		},
		{
			port:      portMap["aafecceb-d986-42b6-8ea7-449c7cacb7d9"],
			errString: "could not find subnet information for network , err: \"networkID '' is not a valid UUID\"",
		},
		{
			port:      portMap["fa65cd2e-5a85-4b8f-9138-40509eb062ca"],
			errString: "found multiple IPv4 subnets attached to port",
		},
	}

	for i, tc := range tcs {
		nodeEgressIPConfig, err := o.getNeutronPortNodeEgressIPConfiguration(tc.port, tc.cloudPrivateIPConfigs)
		if err != nil {
			if !strings.Contains(err.Error(), tc.errString) {
				t.Fatalf("TestGetNeutronPortNodeEgressIPConfiguration(%d): Received unexpected error, err: %q, expected: %q", i, err, tc.errString)
			}
			continue
		}
		if !reflect.DeepEqual(*nodeEgressIPConfig, tc.nodeEgressIPConfig) {
			t.Fatalf("TestGetNeutronPortNodeEgressIPConfiguration(%d): Received unexpected nodeEgressIPConfig. Expected: %v, got %v",
				i, tc.nodeEgressIPConfig, nodeEgressIPConfig)
		}
	}
}

// TestAllowUnAllowIPAddressOnNeutronPort tests both allowIPAddressOnNeutronPort and
// unAllowIPAddressOnNeutronPort.
func TestAllowUnAllowIPAddressOnNeutronPort(t *testing.T) {
	th.SetupHTTP()
	defer th.TeardownHTTP()
	HandlePortGetUpdateDelete(t, "")

	o := OpenStack{
		CloudProvider: CloudProvider{},
		novaClient:    testclient.ServiceClient(),
		neutronClient: testclient.ServiceClient(),
	}

	tcs := []struct {
		portID     string
		ip         net.IP
		unallow    bool
		allowedIPs []string
		errString  string
	}{
		{
			portID:     "9ab428d4-58f8-42d7-9672-90c3f5641f83",
			ip:         net.ParseIP("192.0.2.20"),
			allowedIPs: []string{"192.0.2.1", "192.0.2.2", "192.0.2.20"},
		},
		{
			portID:     "9ab428d4-58f8-42d7-9672-90c3f5641f83",
			ip:         net.ParseIP("192.0.2.21"),
			allowedIPs: []string{"192.0.2.1", "192.0.2.2", "192.0.2.20", "192.0.2.21"},
		},
		{
			portID:     "9ab428d4-58f8-42d7-9672-90c3f5641f83",
			ip:         net.ParseIP("192.0.2.20"),
			unallow:    true,
			allowedIPs: []string{"192.0.2.1", "192.0.2.2", "192.0.2.21"},
		},
		{
			portID:     "9ab428d4-58f8-42d7-9672-90c3f5641f83",
			ip:         net.ParseIP("192.0.2.21"),
			allowedIPs: []string{"192.0.2.1", "192.0.2.2", "192.0.2.21"},
			errString:  "the requested IP for assignment is already assigned",
		},
		{
			portID:     "9ab428d4-58f8-42d7-9672-90c3f5641f83",
			ip:         net.ParseIP("192.0.2.20"),
			unallow:    true,
			allowedIPs: []string{"192.0.2.1", "192.0.2.2", "192.0.2.21"},
			errString:  "is not allowed on port",
		},
		{
			portID:    "9ab428d4-58f8-42d7-9672-90c3f5641f84", // non-existing port
			ip:        net.ParseIP("192.0.2.20"),
			errString: "Resource not found",
		},
		{
			// Clean up so that a follow up test can start from a clean slate.
			portID:     "9ab428d4-58f8-42d7-9672-90c3f5641f83",
			ip:         net.ParseIP("192.0.2.21"),
			unallow:    true,
			allowedIPs: []string{"192.0.2.1", "192.0.2.2"},
		},
	}

	for i, tc := range tcs {
		f := o.allowIPAddressOnNeutronPort
		if tc.unallow {
			f = o.unallowIPAddressOnNeutronPort
		}
		if err := f(tc.portID, tc.ip); err != nil {
			if tc.errString == "" || !strings.Contains(err.Error(), tc.errString) {
				t.Fatalf("TestAllowUnAllowIPAddressOnNeutronPort(%d): Received unexpected error. Should contain '%s', but got err: %q", i, tc.errString, err)
			}
			continue
		}
		if tc.errString != "" {
			t.Fatalf("TestAllowUnAllowIPAddressOnNeutronPort(%d): Received no error but expected to see '%s'", i, tc.errString)
		}
		wantSet := sets.NewString(tc.allowedIPs...)
		haveSet := sets.NewString()
		if p, ok := portMap[tc.portID]; ok {
			for _, aip := range p.AllowedAddressPairs {
				haveSet.Insert(aip.IPAddress)
			}
		}
		if !haveSet.Equal(wantSet) {
			t.Fatalf("TestAllowUnAllowIPAddressOnNeutronPort(%d): Could not update allowed_address_pair. Want: %v, Have: %v", i, wantSet, haveSet)
		}
	}
}

func TestReserveAndReleaseNeutronIPAddress(t *testing.T) {
	th.SetupHTTP()
	defer th.TeardownHTTP()
	HandlePortListAndCreation(t)

	o := OpenStack{
		CloudProvider: CloudProvider{},
		novaClient:    testclient.ServiceClient(),
		neutronClient: testclient.ServiceClient(),
	}

	tcs := []struct {
		subnet    neutronsubnets.Subnet
		ip        net.IP
		nodeName  string
		reserve   bool
		release   bool
		portID    string
		errString string
	}{
		// Create and delete the port.
		{
			subnet:   subnetMap["49895d6d-6972-4198-8afa-ada96e1daaef"],
			ip:       net.ParseIP("192.0.2.9"),
			reserve:  true,
			release:  true,
			nodeName: "node1",
		},
		// Recreate and delete the same port again (different UUID).
		{
			subnet:   subnetMap["49895d6d-6972-4198-8afa-ada96e1daaef"],
			ip:       net.ParseIP("192.0.2.9"),
			reserve:  true,
			release:  true,
			nodeName: "node1",
		},
		// Create an IPv6 port.
		{
			subnet:   subnetMap["de0cda14-6ac6-4439-bc94-da0a27938b7b"],
			ip:       net.ParseIP("2000::5"),
			reserve:  true,
			nodeName: "node1",
		},
		// Create another IPv6 port ...
		{
			subnet:   subnetMap["de0cda14-6ac6-4439-bc94-da0a27938b7b"],
			ip:       net.ParseIP("2000::9"),
			reserve:  true,
			nodeName: "node1",
		},
		// ... and try to create a duplicate of it.
		{
			subnet:   subnetMap["de0cda14-6ac6-4439-bc94-da0a27938b7b"],
			ip:       net.ParseIP("2000::9"), // reserving the same IP address 2x should find the existing port
			reserve:  true,
			nodeName: "node1",
		},
		// Release the first IPv6 port.
		{
			subnet:   subnetMap["de0cda14-6ac6-4439-bc94-da0a27938b7b"],
			ip:       net.ParseIP("2000::5"),
			release:  true,
			nodeName: "node1",
		},
		// Release the second IPv6 port.
		{
			subnet:   subnetMap["de0cda14-6ac6-4439-bc94-da0a27938b7b"],
			ip:       net.ParseIP("2000::9"),
			release:  true,
			nodeName: "node1",
		},
		// Create a port on an invalid subnet.
		{
			subnet: subnets.Subnet{
				ID:        "de0cda14-6ac6-4439-bc94-da0a27938b7a", // non existing subnet
				NetworkID: "57d1274f-4717-43f1-88ec-0944546a14ef",
			},
			ip:        net.ParseIP("2000::50"),
			reserve:   true,
			nodeName:  "node1",
			errString: "Resource not found",
		},
		// Create a port on an invalid network.
		{
			subnet: subnets.Subnet{
				ID:        "de0cda14-6ac6-4439-bc94-da0a27938b7b",
				NetworkID: "57d1274f-4717-43f1-88ec-0944546a14ee", // non existing network
			},
			ip:        net.ParseIP("2000::51"),
			reserve:   true,
			nodeName:  "node1",
			errString: "Resource not found",
		},
		// Try releasing a bound port.
		{
			release:   true,
			portID:    "aafecceb-d986-42b6-8ea7-449c7cacb7d9",
			nodeName:  "node1",
			errString: "belongs to another device",
		},
		// Try releasing an unbound port that belongs to another node.
		{
			release:   true,
			portID:    "638a74cd-d894-45b1-8865-4945c4911145",
			nodeName:  "node2",
			errString: "it belongs to another device owner",
		},
	}

	for i, tc := range tcs {
		var port *neutronports.Port
		var err error

		if tc.reserve {
			if port, err = o.reserveNeutronIPAddress(tc.subnet, tc.ip, tc.nodeName); err != nil {
				if tc.errString == "" || !strings.Contains(err.Error(), tc.errString) {
					t.Fatalf("TestReserveAndReleaseNeutronIPAddress(%d)|reserve: Received unexpected error, err: %q", i, err)
				}
				continue
			}
			if tc.errString != "" {
				t.Fatalf("TestReserveAndReleaseNeutronIPAddress(%d)|reserve: Received no error but expected to see '%s'", i, tc.errString)
			}
		}

		if tc.release {
			// If the port was reserved, then use the pointer to that port.
			if !tc.reserve {
				if tc.portID != "" {
					// Otherwise, if a portID was provided, use the port that has that ID.
					p, ok := portMap[tc.portID]
					if !ok {
						t.Fatalf("TestReserveAndReleaseNeutronIPAddress(%d)|release: Cannot find a port for portID '%s'", i, tc.portID)
					}
					port = &p
				} else {
					// Otherwise, use the subnet, ip and nodeName information to retrieve the port.
					p, err := o.getNeutronPortWithIPAddressAndMachineID(tc.subnet, tc.ip, tc.nodeName)
					if err != nil {
						t.Fatalf("TestReserveAndReleaseNeutronIPAddress(%d)|release: Cannot find a port that matches subnet, ip and nodeName, err: %q", i, err)
					}
					port = p
				}
			}
			if err := o.releaseNeutronIPAddress(*port, tc.nodeName); err != nil {
				if tc.errString == "" || !strings.Contains(err.Error(), tc.errString) {
					t.Fatalf("TestReserveAndReleaseNeutronIPAddress(%d)|release: Received unexpected error, expected error to contain '%s' but got err: %q",
						i, tc.errString, err)
				}
				continue
			}
			if tc.errString != "" {
				t.Fatalf("TestReserveAndReleaseNeutronIPAddress(%d)|release: Received no error but expected to see '%s'", i, tc.errString)
			}
		}
	}
}

func TestIsIPAddressAllowedOnNeutronPort(t *testing.T) {
	tcs := []struct {
		port      neutronports.Port
		ip        net.IP
		isAllowed bool
	}{
		{
			port:      portMap["aafecceb-d986-42b6-8ea7-449c7cacb7d9"],
			ip:        net.ParseIP("192.168.123.10"),
			isAllowed: true,
		},
		{
			port:      portMap["aafecceb-d986-42b6-8ea7-449c7cacb7d9"],
			ip:        net.ParseIP("192.168.123.11"),
			isAllowed: false,
		},
	}

	for _, tc := range tcs {
		isAllowed := isIPAddressAllowedOnNeutronPort(tc.port, tc.ip)
		if isAllowed != tc.isAllowed {
			t.Fatalf("%s is allowed %t on port %s. Expecting %t in TestIsIPAddressAllowedOnNeutronPort", tc.ip, isAllowed, tc.port.ID, tc.isAllowed)
		}
	}
}

func TestGetNeutronSubnetsForNetwork(t *testing.T) {
	th.SetupHTTP()
	defer th.TeardownHTTP()
	HandleSubnetList(t)

	o := OpenStack{
		CloudProvider: CloudProvider{},
		novaClient:    testclient.ServiceClient(),
		neutronClient: testclient.ServiceClient(),
	}

	tcs := []struct {
		networkID string
		subnetIDs []string
		errString string
	}{
		{
			networkID: "57d1274f-4717-43f1-88ec-0944546a14ef",
			subnetIDs: []string{"49895d6d-6972-4198-8afa-ada96e1daaef", "de0cda14-6ac6-4439-bc94-da0a27938b7b"},
		},
		{
			networkID: "92bb71e9-248a-4b9a-98c8-5a99e06568c1",
			subnetIDs: []string{},
		},
	}

	for _, tc := range tcs {
		listedSubnets, err := o.getNeutronSubnetsForNetwork(tc.networkID)
		if err != nil {
			if tc.errString != err.Error() {
				t.Fatalf("Received unexpected error in TestGetNeutronSubnetsForNetwork, err: %q", err)
			}
			continue
		}

		expectedSet := sets.NewString(tc.subnetIDs...)
		listedSet := sets.NewString()
		for _, s := range listedSubnets {
			listedSet.Insert(s.ID)
		}
		if !listedSet.Equal(expectedSet) {
			t.Fatalf("Provided subnet list does not match received subnet list; provided subnet list: %v, received subnet list: %v", expectedSet, listedSet)
		}
	}
}

func TestGetNeutronPortWithIPAddressAndNodeName(t *testing.T) {
	th.SetupHTTP()
	defer th.TeardownHTTP()
	HandlePortListAndCreation(t)

	o := OpenStack{
		CloudProvider: CloudProvider{},
		novaClient:    testclient.ServiceClient(),
		neutronClient: testclient.ServiceClient(),
	}

	tcs := []struct {
		subnet    neutronsubnets.Subnet
		ip        net.IP
		nodeName  string
		portID    string
		errString string
	}{
		{
			subnet:   subnetMap["49895d6d-6972-4198-8afa-ada96e1daaef"],
			ip:       net.ParseIP("192.0.2.12"),
			nodeName: "node1",
			portID:   "638a74cd-d894-45b1-8865-4945c4911145",
		},
		{
			subnet:   subnetMap["de0cda14-6ac6-4439-bc94-da0a27938b7b"],
			ip:       net.ParseIP("2000::12"),
			nodeName: "node1",
			portID:   "638a74cd-d894-45b1-8865-4945c4911145",
		},
		{
			subnet:    subnetMap["de0cda14-6ac6-4439-bc94-da0a27938b7b"], // port not on subnet
			nodeName:  "node1",
			ip:        net.ParseIP("2000::1"),
			errString: "expected to find a single port, instead found 0 ports",
		},
		{
			subnet:    subnetMap["de0cda14-6ac6-4439-bc94-da0a27938b7a"], // wrong subnet ID
			nodeName:  "node1",
			ip:        net.ParseIP("2000::10"),
			errString: "expected to find a single port, instead found 0 ports",
		},
		{
			subnet:    subnetMap["49895d6d-6972-4198-8afa-ada96e1daaef"],
			ip:        net.ParseIP("192.0.2.10"),
			nodeName:  "node2", // wrong node name
			portID:    "9ab428d4-58f8-42d7-9672-90c3f5641f83",
			errString: "expected to find a single port, instead found 0 ports",
		},
	}

	for i, tc := range tcs {
		retrievedPort, err := o.getNeutronPortWithIPAddressAndMachineID(tc.subnet, tc.ip, tc.nodeName)
		if err != nil {
			if tc.errString != err.Error() {
				t.Fatalf("TestGetNeutronPortWithIPAddressAndNodeName(%d): Received unexpected error, expected to get '%s', instead got err: %q", i, tc.errString, err)
			}
			continue
		}

		if retrievedPort.ID != tc.portID {
			t.Fatalf("TestGetNeutronPortWithIPAddressAndNodeName(%d): Provided port ID does not match retrieved port ID; provided port ID: %s, retrieved port ID: %s", i, tc.portID, retrievedPort.ID)
		}
	}
}

func TestListNovaServerPorts(t *testing.T) {
	th.SetupHTTP()
	defer th.TeardownHTTP()
	HandlePortListAndCreation(t)

	o := OpenStack{
		CloudProvider: CloudProvider{},
		novaClient:    testclient.ServiceClient(),
		neutronClient: testclient.ServiceClient(),
	}

	tcs := []struct {
		instanceID string
		portIDs    []string
		errString  string
	}{
		// Test normal port.
		{
			instanceID: "9e5476bd-a4ec-4653-93d6-72c93aa682ba",
			portIDs:    []string{"9ab428d4-58f8-42d7-9672-90c3f5641f83", "eec4c521-4288-4d54-939a-1ea32cc35c37"},
		},
		// Test multi-AZ.
		{
			instanceID: "50b412c1-d659-424e-8e29-5a5e5a6b5c45",
			portIDs:    []string{"84da9456-8a1d-4d3f-9e15-821e29b5e7c8"},
		},
		// Test non-existing device ID.
		{
			instanceID: "9e5476bd-a4ec-4653-93d6-72c93aa682bc",
			portIDs:    []string{},
		},
	}

	for _, tc := range tcs {
		listedPorts, err := o.listNovaServerPorts(tc.instanceID)
		if err != nil {
			if tc.errString != err.Error() {
				t.Fatalf("Received unexpected error in TestListNovaServerPorts, err: %q", err)
			}
			continue
		}

		expectedSet := sets.NewString(tc.portIDs...)
		listedSet := sets.NewString()
		for _, p := range listedPorts {
			listedSet.Insert(p.ID)
		}
		if !listedSet.Equal(expectedSet) {
			t.Fatalf("Provided port list does not match received port list; provided port list: %v, received port list: %v", expectedSet, listedSet)
		}
	}
}

func TestGetNovaServer(t *testing.T) {
	th.SetupHTTP()
	defer th.TeardownHTTP()
	HandleServerGet(t)

	o := OpenStack{
		CloudProvider: CloudProvider{},
		novaClient:    testclient.ServiceClient(),
		neutronClient: testclient.ServiceClient(),
	}

	tcs := []struct {
		id        string
		errString string
	}{
		{
			id: "9e5476bd-a4ec-4653-93d6-72c93aa682ba",
		},
		{
			id:        "9e5476bd-a4ec-4653-93d6-72c93aa682bb",
			errString: "Resource not found",
		},
	}

	for i, tc := range tcs {
		server, err := o.getNovaServer(tc.id)
		if err != nil {
			if !strings.Contains(err.Error(), tc.errString) {
				t.Fatalf("TestGetNovaServer(%d): Received unexpected error in TestGetNovaServer, expected ton contain '%s' but got err: %q", i, tc.errString, err)
			}
			continue
		}
		if tc.id != server.ID {
			t.Fatalf("TestGetNovaServer(%d): Received unexpected server Expected %s, got %v", i, tc.id, server)
		}
	}
}

func TestGetNovaServerIDFromProviderID(t *testing.T) {
	tcs := []struct {
		input     string
		output    string
		errString string
	}{
		{
			input:  "openstack:///91dcacbf-fa2a-40c8-a194-c3a51ab57062",
			output: "91dcacbf-fa2a-40c8-a194-c3a51ab57062",
		},
		{
			input: "openstack://91dcacbf-fa2a-40c8-a194-c3a51ab57062",
			errString: "the URI is not expected: openstack://91dcacbf-fa2a-40c8-a194-c3a51ab57062; " +
				"the provider ID does not contain expected prefix openstack:///",
		},
		{
			input: "openstack:///91dcacbf-fa2a-40c8-a194-c3a51ab5706",
			errString: "the URI is not expected: openstack:///91dcacbf-fa2a-40c8-a194-c3a51ab5706; " +
				"error parsing UUID \"91dcacbf-fa2a-40c8-a194-c3a51ab5706\": \"invalid UUID length: 35\"",
		},
	}

	var out string
	var err error
	for _, tc := range tcs {
		out, err = getNovaServerIDFromProviderID(tc.input)
		if tc.errString != "" {
			if err != nil {
				if err.Error() != tc.errString {
					t.Fatalf("Expected error with error message '%s' but got %q",
						tc.errString, err)
				}
			} else {
				t.Fatalf("Expected an error, but got nil instead and output %s", out)
			}
		} else {
			if err != nil {
				t.Fatalf("Expected no error, but got an error instead: %q", err)

			} else {
				if out != tc.output {
					t.Fatalf("Expected output %s but got output %s instead", tc.output, out)
				}
			}
		}
	}
}
