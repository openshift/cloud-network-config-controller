package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +genclient:noStatus
// +resource:path=cloudprivateipconfig
// +kubebuilder:resource:scope=Cluster
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:printcolumn:name="Node Request",type=string,JSONPath=".spec.items[*].node"
// +kubebuilder:printcolumn:name="IP Request",type=string,JSONPath=".spec.items[*].ip"
// +kubebuilder:printcolumn:name="Node Assignment",type=string,JSONPath=".status.items[*].node"
// +kubebuilder:printcolumn:name="IP Assignment",type=string,JSONPath=".status.items[*].ip"
// CloudPrivateIPConfig is a CRD allowing the user to assign private
// IP addresses to the primary NIC associated with cloud VMs. This is done by
// specifying the Kubernetes nodes and IPs requested for those nodes.
type CloudPrivateIPConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired private IP request(s).
	// +kubebuilder:validation:Required
	// +required
	Spec CloudPrivateIPConfigSpec `json:"spec"`
	// Observed status of CloudPrivateIPConfig. Read-only.
	// +optional
	Status CloudPrivateIPConfigStatus `json:"status,omitempty"`
}

type CloudPrivateIPConfigSpec struct {
	// The requested list of private IPs and their corresponding node assignment.
	// +kubebuilder:validation:MinItems=1
	Items []CloudPrivateIPConfigItem `json:"items"`
}

type CloudPrivateIPConfigStatus struct {
	// The assigned list of private IPs and their corresponding node assignment.
	// Any failed IP assignment will have the item omitted from the .status.items.
	// I.e: if all went well: the `.spec.items` length should equal the
	// `.status.items` length.
	Items []CloudPrivateIPConfigItem `json:"items"`
}

type CloudPrivateIPConfigItem struct {
	// Node name, as specified by the Kubernetes field: `node.metadata.name`
	Node string `json:"node"`
	// IP address - IPv4 or IPv6
	IP string `json:"ip"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=cloudprivateipconfig
// CloudPrivateIPConfigList is the list of CloudPrivateIPConfigList.
type CloudPrivateIPConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// List of CloudPrivateIPConfig.
	Items []CloudPrivateIPConfig `json:"items"`
}
