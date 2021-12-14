package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

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
	kubeClient  kubernetes.Interface
	nodesLister corelisters.NodeLister
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
	nodeInformer coreinformers.NodeInformer) *controller.CloudNetworkConfigController {

	nodeController := &NodeController{
		nodesLister:         nodeInformer.Lister(),
		kubeClient:          kubeClientset,
		cloudProviderClient: cloudProviderClient,
		ctx:                 controllerContext,
	}

	controller := controller.NewCloudNetworkConfigController(
		[]cache.InformerSynced{nodeInformer.Informer().HasSynced},
		nodeController,
		nodeControllerAgentName,
		nodeControllerAgentType,
	)

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.Enqueue,
	})
	return controller
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
	// If the node already has the annotation (ex: if we restart it is expected
	// that the nodes would) we skip it. Subnets won't change and we are only
	// interested in conveying the default assignment capacity that the node had
	// when it started existing. It's up to the network plugin to track how much
	// capacity it has left depending on the assignments it performs.
	if _, ok := node.Annotations[nodeEgressIPConfigAnnotationKey]; ok {
		return nil
	}
	nodeEgressIPConfigs, err := n.cloudProviderClient.GetNodeEgressIPConfiguration(node)
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
