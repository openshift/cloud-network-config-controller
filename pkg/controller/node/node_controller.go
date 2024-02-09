package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	cloudproviderapi "k8s.io/cloud-provider/api"
	"k8s.io/klog/v2"

	cloudnetworkv1 "github.com/openshift/api/cloudnetwork/v1"
	cloudnetworkinformers "github.com/openshift/client-go/cloudnetwork/informers/externalversions/cloudnetwork/v1"
	cloudnetworklisters "github.com/openshift/client-go/cloudnetwork/listers/cloudnetwork/v1"
	cloudprovider "github.com/openshift/cloud-network-config-controller/pkg/cloudprovider"
	controller "github.com/openshift/cloud-network-config-controller/pkg/controller"
)

var (
	// nodeControllerAgentType is the Node controller's dedicated resource type
	nodeControllerAgentType = reflect.TypeOf(&corev1.Node{})
	// nodeControllerAgentName is the controller name for the Node controller
	nodeControllerAgentName = "node"
	// nodeEgressIPConfigAnnotationKey is the annotation key used for indicating the node's egress IP configuration
	nodeEgressIPConfigAnnotationKey = "cloud.network.openshift.io/egress-ipconfig"
)

// NodeController is the controller implementation for Node resources
// This controller is used to annotate nodes for the purposes of the
// cloud network config controller
type NodeController struct {
	controller.CloudNetworkConfigController
	kubeClient                 kubernetes.Interface
	nodesLister                corelisters.NodeLister
	cloudPrivateIPConfigLister cloudnetworklisters.CloudPrivateIPConfigLister
	// cloudProviderClient is a client interface allowing the controller
	// access to the cloud API
	cloudProviderClient cloudprovider.CloudProviderIntf
	// ctx is the passed-down global context. It's used and passed
	// down to all API client calls as to make sure all in-flight calls get
	// cancelled if the main context is
	ctx context.Context
}

// NewNodeController returns a new Node controller
func NewNodeController(
	controllerContext context.Context,
	kubeClientset kubernetes.Interface,
	cloudProviderClient cloudprovider.CloudProviderIntf,
	nodeInformer coreinformers.NodeInformer,
	cloudPrivateIPConfigInformer cloudnetworkinformers.CloudPrivateIPConfigInformer) (*controller.CloudNetworkConfigController, error) {

	nodeController := &NodeController{
		nodesLister:                nodeInformer.Lister(),
		kubeClient:                 kubeClientset,
		cloudProviderClient:        cloudProviderClient,
		cloudPrivateIPConfigLister: cloudPrivateIPConfigInformer.Lister(),
		ctx:                        controllerContext,
	}

	controller := controller.NewCloudNetworkConfigController(
		[]cache.InformerSynced{nodeInformer.Informer().HasSynced},
		nodeController,
		nodeControllerAgentName,
		nodeControllerAgentType,
	)

	_, err := nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.Enqueue,
		UpdateFunc: func(oldN, newN interface{}) {
			// Enqueue when an update to the node's taints occurred - for external cloud providers, we must
			// catch changes to taint node.cloudprovider.kubernetes.io/uninitialized.
			// See https://kubernetes.io/docs/tasks/administer-cluster/running-cloud-controller/
			oldNode, _ := oldN.(*corev1.Node)
			newNode, _ := newN.(*corev1.Node)
			if !reflect.DeepEqual(oldNode.Spec.Taints, newNode.Spec.Taints) {
				controller.Enqueue(newN)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	return controller, nil
}

// syncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the Node resource
// with the current status of the resource.
func (n *NodeController) SyncHandler(key string) error {
	node, err := n.nodesLister.Get(key)
	if err != nil {
		// // A lister can only return ErrNotFound, which means: the Node
		// resource no longer exist, in which case we stop processing.
		klog.Infof("corev1.Node: '%s' in work queue no longer exists", key)
		return nil
	}

	// Skip synchronization if this node is still uninitialized by the Cloud Controller Manager,
	// meaning that it still has taint cloudproviderapi.TaintExternalCloudProvider.
	if taintKeyExists(node.Spec.Taints, cloudproviderapi.TaintExternalCloudProvider) {
		klog.V(5).Infof("Taint '%s' found on node, skipping until the node is ready",
			cloudproviderapi.TaintExternalCloudProvider)
		return nil
	}
	cloudPrivateIPConfigs, err := n.cloudPrivateIPConfigLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("error listing cloud private ip config, err: %v", err)
	}
	// Filter out cloudPrivateIPConfigs assigned to node (key) and write the entry
	// into same slice starting from index 0, finally chop off unwanted entries
	// when passing it into GetNodeEgressIPConfiguration.
	index := 0
	for _, cloudPrivateIPConfig := range cloudPrivateIPConfigs {
		if isAssignedCloudPrivateIPConfigOnNode(cloudPrivateIPConfig, key) {
			cloudPrivateIPConfigs[index] = cloudPrivateIPConfig
			index++
		}
	}
	nodeEgressIPConfigs, err := n.cloudProviderClient.GetNodeEgressIPConfiguration(node, cloudPrivateIPConfigs[:index])
	if err != nil {
		return fmt.Errorf("error retrieving the private IP configuration for node: %s, err: %v", node.Name, err)
	}
	return n.SetNodeEgressIPConfigAnnotation(node, nodeEgressIPConfigs)
}

// SetCloudPrivateIPConfigAnnotationOnNode annotates the corev1.Node with the cloud subnet information and capacity
func (n *NodeController) SetNodeEgressIPConfigAnnotation(node *corev1.Node, nodeEgressIPConfigs []*cloudprovider.NodeEgressIPConfiguration) error {
	annotation, err := n.generateAnnotation(nodeEgressIPConfigs)
	if err != nil {
		return err
	}
	klog.Infof("Setting annotation: '%s: %s' on node: %s", nodeEgressIPConfigAnnotationKey, annotation, node.Name)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ctx, cancel := context.WithTimeout(n.ctx, controller.ClientTimeout)
		defer cancel()

		// See: updateCloudPrivateIPConfigStatus
		nodeLatest, err := n.kubeClient.CoreV1().Nodes().Get(ctx, node.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		existingAnnotations := nodeLatest.Annotations
		existingAnnotations[nodeEgressIPConfigAnnotationKey] = annotation
		nodeLatest.SetAnnotations(existingAnnotations)
		_, err = n.kubeClient.CoreV1().Nodes().Update(ctx, nodeLatest, metav1.UpdateOptions{})
		return err
	})
}

func (n *NodeController) generateAnnotation(nodeEgressIPConfigs []*cloudprovider.NodeEgressIPConfiguration) (string, error) {
	serialized, err := json.Marshal(nodeEgressIPConfigs)
	if err != nil {
		return "", fmt.Errorf("error serializing cloud subnet annotation, err: %v", err)
	}
	return string(serialized), nil
}

// TaintKeyExists checks if the given taint key exists in list of taints. Returns true if exists false otherwise.
// Copied from k8s.io/kubernetes/pkg/util/taints/taints.go to avoid dependency hell.
func taintKeyExists(taints []v1.Taint, taintKeyToMatch string) bool {
	for _, taint := range taints {
		if taint.Key == taintKeyToMatch {
			return true
		}
	}
	return false
}

func isAssignedCloudPrivateIPConfigOnNode(cloudPrivateIPConfig *cloudnetworkv1.CloudPrivateIPConfig, nodeName string) bool {
	if cloudPrivateIPConfig.Status.Node != nodeName {
		return false
	}
	for _, condition := range cloudPrivateIPConfig.Status.Conditions {
		if condition.Type == string(cloudnetworkv1.Assigned) && condition.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}
