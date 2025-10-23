package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	cloudnetworkv1 "github.com/openshift/api/cloudnetwork/v1"
	cloudnetworkclientset "github.com/openshift/client-go/cloudnetwork/clientset/versioned"
	cloudnetworkinformers "github.com/openshift/client-go/cloudnetwork/informers/externalversions/cloudnetwork/v1"
	cloudnetworklisters "github.com/openshift/client-go/cloudnetwork/listers/cloudnetwork/v1"
	"github.com/openshift/cloud-network-config-controller/pkg/cloudprivateipconfig"
	cloudprovider "github.com/openshift/cloud-network-config-controller/pkg/cloudprovider"
	controller "github.com/openshift/cloud-network-config-controller/pkg/controller"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var (
	// cloudPrivateIPConfigControllerAgentType is the CloudPrivateIPConfig controller's dedicated resource type
	cloudPrivateIPConfigControllerAgentType = reflect.TypeOf(&cloudnetworkv1.CloudPrivateIPConfig{})
	// cloudPrivateIPConfigControllerAgentName is the controller name for the CloudPrivateIPConfig controller
	cloudPrivateIPConfigControllerAgentName = "cloud-private-ip-config"
	// cloudPrivateIPConfigFinalizer is the name of the finalizer blocking
	// object deletion until the cloud confirms that the IP has been removed
	cloudPrivateIPConfigFinalizer = "cloudprivateipconfig.cloud.network.openshift.io/finalizer"
	// cloudResponseReasonPending indicates a pending response from the cloud API
	cloudResponseReasonPending = "CloudResponsePending"
	// cloudResponseReasonError indicates an error response from the cloud API
	cloudResponseReasonError = "CloudResponseError"
	// cloudResponseReasonSuccess indicates a successful response from the cloud API
	cloudResponseReasonSuccess = "CloudResponseSuccess"
)

// CloudPrivateIPConfigController is the controller implementation for CloudPrivateIPConfig resources
type CloudPrivateIPConfigController struct {
	controller.CloudNetworkConfigController
	cloudNetworkClient         cloudnetworkclientset.Interface
	cloudPrivateIPConfigLister cloudnetworklisters.CloudPrivateIPConfigLister
	nodesLister                corelisters.NodeLister
	// CloudProviderClient is a client interface allowing the controller
	// access to the cloud API
	cloudProviderClient cloudprovider.CloudProviderIntf
	// controllerContext is the passed-down global context. It's used and passed
	// down to all API client calls as to make sure all in-flight calls get
	// cancelled if the main context is
	ctx context.Context
}

// NewCloudPrivateIPConfigController returns a new CloudPrivateIPConfig controller
func NewCloudPrivateIPConfigController(
	controllerContext context.Context,
	cloudProviderClient cloudprovider.CloudProviderIntf,
	cloudNetworkClientset cloudnetworkclientset.Interface,
	cloudPrivateIPConfigInformer cloudnetworkinformers.CloudPrivateIPConfigInformer,
	nodeInformer coreinformers.NodeInformer) (*controller.CloudNetworkConfigController, error) {

	cloudPrivateIPConfigController := &CloudPrivateIPConfigController{
		nodesLister:                nodeInformer.Lister(),
		cloudProviderClient:        cloudProviderClient,
		cloudNetworkClient:         cloudNetworkClientset,
		cloudPrivateIPConfigLister: cloudPrivateIPConfigInformer.Lister(),
		ctx:                        controllerContext,
	}
	controller := controller.NewCloudNetworkConfigController(
		[]cache.InformerSynced{cloudPrivateIPConfigInformer.Informer().HasSynced, nodeInformer.Informer().HasSynced},
		cloudPrivateIPConfigController,
		cloudPrivateIPConfigControllerAgentName,
		cloudPrivateIPConfigControllerAgentType,
	)

	_, err := cloudPrivateIPConfigInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.Enqueue,
		UpdateFunc: func(old, new interface{}) {
			oldCloudPrivateIPConfig, _ := old.(*cloudnetworkv1.CloudPrivateIPConfig)
			newCloudPrivateIPConfig, _ := new.(*cloudnetworkv1.CloudPrivateIPConfig)
			// Enqueue consumer updates and deletion. Given the presence of our
			// finalizer a delete action will be treated as an update before our
			// finalizer is removed, once the finalizer has been removed by this
			// controller we will receive the delete. We can be notified of this
			// by checking that the deletion timestamp has been set and
			// verifying the existence of the finalizer
			if !newCloudPrivateIPConfig.DeletionTimestamp.IsZero() &&
				controllerutil.ContainsFinalizer(newCloudPrivateIPConfig, cloudPrivateIPConfigFinalizer) {
				controller.Enqueue(new)
				return
			}
			if !reflect.DeepEqual(oldCloudPrivateIPConfig.Spec, newCloudPrivateIPConfig.Spec) {
				controller.Enqueue(new)
				return
			}
			// Enqueue our own transitions from delete -> add. On delete we will
			// unset the status node as to indicate that we finished removing
			// the IP address from its current node, that will trigger this so
			// that we process the sync adding the IP to the new node.
			if oldCloudPrivateIPConfig.Status.Node != newCloudPrivateIPConfig.Status.Node {
				controller.Enqueue(new)
			}
		},
		DeleteFunc: controller.Enqueue,
	})
	if err != nil {
		return nil, err
	}
	return controller, nil
}

// syncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the CloudPrivateIPConfig
// resource with the current status of the resource.
// On update: we should only process the add once we've received the cloud's answer
// for the delete. We risk having the IP address being assigned to two nodes at
// the same time otherwise.

// We have two "data stores": kube API server and the cloud API. Thus, there are
// two main error conditions:

// - We couldn't update the object in the kube API, but did update the object in the cloud.
// - We couldn't update the object in the cloud, but did update the object in the kube API.

// - If we couldn't update either, we just resync the original object
// - If we could update both, we don't resync the object

// Note: that we don't retry re-syncing relentlessly, we finally give up after
// maxRetries (defined in controller.go).

//  Here's a schema of CloudPrivateIPConfig's reconciliation loop based on the consumer input:

// - ADD:
// 1. Set status.node = spec.node && status.conditions[0].Status = Pending
// 2. Send cloud API ADD request
// ...some time later
// * 	If OK: set status.conditions[0].Status = Success
// *	If !OK: set status.node == "" && set status.conditions[0].Status = Error && goto 1. by resync

// Note: OK in this context is; either a successful assignment or realizing
// that the IP is already assigned

// - DELETE:
// 1. Set status.conditions[0].Status = Pending
// 2. Send cloud API DELETE request
// ...some time later
// *	If OK: unset status.node
// * 	If !OK: set status.node = spec.node and status.conditions[0].Status = Error && goto 1. by resync

// - UPDATE:
// 1.	goto DELETE
// *	If OK: goto ADD

// Consumer should only consider ADD / UPDATE successful when:
// - 	spec.node == status.node && status.conditions[0].Status == Success
func (c *CloudPrivateIPConfigController) SyncHandler(key string) error {
	var status *cloudnetworkv1.CloudPrivateIPConfigStatus

	cloudPrivateIPConfig, err := c.getCloudPrivateIPConfig(key)
	if err != nil {
		return err
	}
	// When syncing objects which have been completely deleted: we must make
	// sure to not continue processing the object.
	if cloudPrivateIPConfig == nil {
		return nil
	}

	ip, _, err := cloudprivateipconfig.NameToIP(cloudPrivateIPConfig.Name)
	if err != nil {
		return err
	}

	nodeNameToAdd, nodeNameToDel := c.computeOp(cloudPrivateIPConfig)
	switch {
	// Dequeue on NOOP, there's nothing to do
	case nodeNameToAdd == "" && nodeNameToDel == "":
		return nil
	case nodeNameToAdd != "" && nodeNameToDel != "":
		klog.Infof("CloudPrivateIPConfig: %q will be moved from node %q to node %q", key, nodeNameToDel, nodeNameToAdd)
		nodeToDel, err := c.nodesLister.Get(nodeNameToDel)
		if err != nil && apierrors.IsNotFound(err) {
			klog.Infof("Source node: %s no longer exists for CloudPrivateIPConfig: %q", nodeNameToDel, key)
		} else if err != nil {
			return err
		}

		nodeToAdd, err := c.nodesLister.Get(nodeNameToAdd)
		if err != nil {
			if apierrors.IsNotFound(err) {
				klog.Errorf("Target node: %s does not exist for CloudPrivateIPConfig: %q", nodeNameToAdd, key)
				status = &cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameToDel,
					Conditions: []metav1.Condition{
						{
							Type:               string(cloudnetworkv1.Assigned),
							Status:             metav1.ConditionFalse,
							ObservedGeneration: cloudPrivateIPConfig.Generation,
							LastTransitionTime: metav1.Now(),
							Reason:             cloudResponseReasonError,
							Message:            fmt.Sprintf("Target node %q does not exist", nodeNameToAdd),
						},
					},
				}
				if _, err = c.updateCloudPrivateIPConfigStatus(cloudPrivateIPConfig, status); err != nil {
					return fmt.Errorf("error updating CloudPrivateIPConfig: %q status for non-existent target node, err: %v", key, err)
				}
				return nil
			}
			return err
		}

		status = &cloudnetworkv1.CloudPrivateIPConfigStatus{
			Node: nodeNameToDel,
			Conditions: []metav1.Condition{
				{
					Type:               string(cloudnetworkv1.Assigned),
					Status:             metav1.ConditionUnknown,
					ObservedGeneration: cloudPrivateIPConfig.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             cloudResponseReasonPending,
					Message:            "Moving IP address",
				},
			},
		}
		if cloudPrivateIPConfig, err = c.updateCloudPrivateIPConfigStatus(cloudPrivateIPConfig, status); err != nil {
			return fmt.Errorf("error updating CloudPrivateIPConfig: %q during move operation, err: %v", key, err)
		}

		// This is a blocking call. If the IP is not assigned then don't treat
		// it as an error.
		// If nodeToDel is nil (source node was deleted), we can still proceed with the move
		withMover, ok := c.cloudProviderClient.(cloudprovider.CloudProviderWithMoveIntf)
		if !ok {
			return fmt.Errorf("cannot convert driver to the interface with move abilities, this should never happen")
		}
		if moveErr := withMover.MovePrivateIP(ip, nodeToAdd, nodeToDel); moveErr != nil {
			// Move operation encountered an error, requeue
			status = &cloudnetworkv1.CloudPrivateIPConfigStatus{
				Node: nodeNameToDel,
				Conditions: []metav1.Condition{
					{
						Type:               string(cloudnetworkv1.Assigned),
						Status:             metav1.ConditionFalse,
						ObservedGeneration: cloudPrivateIPConfig.Generation,
						LastTransitionTime: metav1.Now(),
						Reason:             cloudResponseReasonError,
						Message:            fmt.Sprintf("Error processing cloud move request, err: %v", moveErr),
					},
				},
			}
			// Always requeue the object if we end up here. We need to make sure
			// we try to clean up the IP on the cloud
			if _, err = c.updateCloudPrivateIPConfigStatus(cloudPrivateIPConfig, status); err != nil {
				return fmt.Errorf("error updating CloudPrivateIPConfig: %q status for error releasing cloud assignment, err: %v", key, err)
			}
			return fmt.Errorf("error moving CloudPrivateIPConfig: %q from node %q to %q, err: %v", key, nodeNameToDel, nodeNameToAdd, moveErr)
		}
		// Update the status one last time, informing consumers of this status
		// that we've successfully moved the IP in the cloud
		status = &cloudnetworkv1.CloudPrivateIPConfigStatus{
			Node: nodeNameToAdd,
			Conditions: []metav1.Condition{
				{
					Type:               string(cloudnetworkv1.Assigned),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: cloudPrivateIPConfig.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             cloudResponseReasonSuccess,
					Message:            "IP address successfully moved",
				},
			},
		}

		klog.Infof("Moved IP address from node %q to %q for CloudPrivateIPConfig: %q", nodeNameToDel, nodeNameToAdd, key)
	case nodeNameToDel != "":
		klog.Infof("CloudPrivateIPConfig: %q will be deleted from node: %q", key, nodeNameToDel)

		node, err := c.nodesLister.Get(nodeNameToDel)
		// there is a case when the node was deleted and the ip still needs to be released. if the node
		// doesn't exist, nodesLister.Get() will still return and error but if that error is just that the
		// node doesn't exist, we can carry on with the release
		if err != nil && apierrors.IsNotFound(err) {
			klog.Infof("Node: %s no longer exists. Will still need to unassign CloudPrivateIPConfig: %q", nodeNameToDel, key)
		} else if err != nil {
			return err
		}

		// This is step 1. in the docbloc for the DELETE operation in the
		// syncHandler
		status = &cloudnetworkv1.CloudPrivateIPConfigStatus{
			Node: nodeNameToDel,
			Conditions: []metav1.Condition{
				{
					Type:               string(cloudnetworkv1.Assigned),
					Status:             metav1.ConditionUnknown,
					ObservedGeneration: cloudPrivateIPConfig.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             cloudResponseReasonPending,
					Message:            "Deleting IP address",
				},
			},
		}
		if cloudPrivateIPConfig, err = c.updateCloudPrivateIPConfigStatus(cloudPrivateIPConfig, status); err != nil {
			return fmt.Errorf("error updating CloudPrivateIPConfig: %q during delete operation, err: %v", key, err)
		}

		// it's possible that the node can be deleted entirely so releasing the IP
		// from the node does not make sense
		if node != nil {
			// This is a blocking call. If the IP is not assigned then don't treat
			// it as an error.
			if releaseErr := c.cloudProviderClient.ReleasePrivateIP(ip, node); releaseErr != nil && !errors.Is(releaseErr, cloudprovider.NonExistingIPError) {
				// Delete operation encountered an error, requeue
				status = &cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameToDel,
					Conditions: []metav1.Condition{
						{
							Type:               string(cloudnetworkv1.Assigned),
							Status:             metav1.ConditionFalse,
							ObservedGeneration: cloudPrivateIPConfig.Generation,
							LastTransitionTime: metav1.Now(),
							Reason:             cloudResponseReasonError,
							Message:            fmt.Sprintf("Error processing cloud release request, err: %v", releaseErr),
						},
					},
				}
				// Always requeue the object if we end up here. We need to make sure
				// we try to clean up the IP on the cloud
				if _, err = c.updateCloudPrivateIPConfigStatus(cloudPrivateIPConfig, status); err != nil {
					return fmt.Errorf("error updating CloudPrivateIPConfig: %q status for error releasing cloud assignment, err: %v", key, err)
				}
				return fmt.Errorf("error releasing CloudPrivateIPConfig: %q from node: %q, err: %v", key, node.Name, releaseErr)
			}
		}

		// Process real object deletion. We're using a finalizer, so it depends
		// on this controller whether the object is finally deleted and removed
		// from the store or not, hence don't check the store.
		if !cloudPrivateIPConfig.DeletionTimestamp.IsZero() {
			klog.Infof("CloudPrivateIPConfig: %s object has been marked for complete deletion", key)
			if controllerutil.ContainsFinalizer(cloudPrivateIPConfig, cloudPrivateIPConfigFinalizer) {
				// Everything has been cleaned up, remove the finalizer from the
				// object and update so that the object gets removed. If it
				// didn't get removed and we encountered an error we'll requeue
				// it down below
				controllerutil.RemoveFinalizer(cloudPrivateIPConfig, cloudPrivateIPConfigFinalizer)
				klog.Infof("Cleaning up IP address and finalizer for CloudPrivateIPConfig: %q, deleting it completely", key)
				_, err = c.patchCloudPrivateIPConfigFinalizer(cloudPrivateIPConfig)
				return err
			}
		}

		// Update the status one last time, informing consumers of this status
		// that we've successfully deleted the IP in the cloud
		status = &cloudnetworkv1.CloudPrivateIPConfigStatus{
			Conditions: []metav1.Condition{
				{
					Type:               string(cloudnetworkv1.Assigned),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: cloudPrivateIPConfig.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             cloudResponseReasonSuccess,
					Message:            "IP address successfully deleted",
				},
			},
		}
		klog.Infof("Deleted IP address for CloudPrivateIPConfig: %q", key)
	case nodeNameToAdd != "":
		klog.Infof("CloudPrivateIPConfig: %q will be added to node: %q", key, nodeNameToAdd)

		// This is step 1. in the docbloc for the ADD operation in the
		// syncHandler
		status = &cloudnetworkv1.CloudPrivateIPConfigStatus{
			Node: nodeNameToAdd,
			Conditions: []metav1.Condition{
				{
					Type:               string(cloudnetworkv1.Assigned),
					Status:             metav1.ConditionUnknown,
					ObservedGeneration: cloudPrivateIPConfig.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             cloudResponseReasonPending,
					Message:            "Adding IP address",
				},
			},
		}
		if cloudPrivateIPConfig, err = c.updateCloudPrivateIPConfigStatus(cloudPrivateIPConfig, status); err != nil {
			return fmt.Errorf("error updating CloudPrivateIPConfig: %q, err: %v", key, err)
		}

		// Add the finalizer now so that the object can't be removed from under
		// us while we process the cloud's answer
		if !controllerutil.ContainsFinalizer(cloudPrivateIPConfig, cloudPrivateIPConfigFinalizer) {
			klog.Infof("Adding finalizer to CloudPrivateIPConfig: %q", key)
			controllerutil.AddFinalizer(cloudPrivateIPConfig, cloudPrivateIPConfigFinalizer)
			// This is annoying, but we need two updates here since we're adding
			// a finalizer. One update for the status above and one for the
			// object. The reason for this is because we've defined:
			// +kubebuilder:subresource:status on the CRD marking the status as
			// impossible to update for anything/anyone else except for this
			// controller.
			if cloudPrivateIPConfig, err = c.patchCloudPrivateIPConfigFinalizer(cloudPrivateIPConfig); err != nil {
				return fmt.Errorf("error updating CloudPrivateIPConfig: %q, err: %v", key, err)
			}
		}

		node, err := c.nodesLister.Get(nodeNameToAdd)
		if err != nil {
			if apierrors.IsNotFound(err) {
				klog.Errorf("Node: %s does not exist for CloudPrivateIPConfig: %q", nodeNameToAdd, key)
				status = &cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameToAdd,
					Conditions: []metav1.Condition{
						{
							Type:               string(cloudnetworkv1.Assigned),
							Status:             metav1.ConditionFalse,
							ObservedGeneration: cloudPrivateIPConfig.Generation,
							LastTransitionTime: metav1.Now(),
							Reason:             cloudResponseReasonError,
							Message:            fmt.Sprintf("Node %q does not exist", nodeNameToAdd),
						},
					},
				}
				if _, err = c.updateCloudPrivateIPConfigStatus(cloudPrivateIPConfig, status); err != nil {
					return fmt.Errorf("error updating CloudPrivateIPConfig: %q status for non-existent node, err: %v", key, err)
				}
				return nil
			}
			return err
		}

		// This is a blocking call. If the IP is assigned (for ex: in case we
		// were killed during the last sync but managed sending the cloud
		// request away prior to that) then don't treat it as an error.
		if assignErr := c.cloudProviderClient.AssignPrivateIP(ip, node); assignErr != nil && !errors.Is(assignErr, cloudprovider.AlreadyExistingIPError) {
			// If we couldn't even execute the assign request, set the status to
			// failed.
			status = &cloudnetworkv1.CloudPrivateIPConfigStatus{
				Node: nodeNameToAdd,
				Conditions: []metav1.Condition{
					{
						Type:               string(cloudnetworkv1.Assigned),
						Status:             metav1.ConditionFalse,
						ObservedGeneration: cloudPrivateIPConfig.Generation,
						LastTransitionTime: metav1.Now(),
						Reason:             cloudResponseReasonError,
						Message:            fmt.Sprintf("Error processing cloud assignment request, err: %v", assignErr),
					},
				},
			}
			if _, err = c.updateCloudPrivateIPConfigStatus(cloudPrivateIPConfig, status); err != nil {
				return fmt.Errorf("error updating CloudPrivateIPConfig: %q status for error issuing cloud assignment, err: %v", key, err)
			}
			return fmt.Errorf("error assigning CloudPrivateIPConfig: %q to node: %q, err: %v", key, node.Name, assignErr)
		}

		// Add occurred and no error was encountered, keep status.node from
		// above
		status = &cloudnetworkv1.CloudPrivateIPConfigStatus{
			Node: nodeNameToAdd,
			Conditions: []metav1.Condition{
				{
					Type:               string(cloudnetworkv1.Assigned),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: cloudPrivateIPConfig.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             cloudResponseReasonSuccess,
					Message:            "IP address successfully added",
				},
			},
		}
		klog.Infof("Added IP address to node: %q for CloudPrivateIPConfig: %q", node.Name, key)
	}
	_, err = c.updateCloudPrivateIPConfigStatus(cloudPrivateIPConfig, status)
	return err
}

// updateCloudPrivateIPConfigStatus copies and updates the provided object and returns
// the new object. The return value can be useful for recursive updates
func (c *CloudPrivateIPConfigController) updateCloudPrivateIPConfigStatus(cloudPrivateIPConfig *cloudnetworkv1.CloudPrivateIPConfig, status *cloudnetworkv1.CloudPrivateIPConfigStatus) (*cloudnetworkv1.CloudPrivateIPConfig, error) {
	updatedCloudPrivateIPConfig := &cloudnetworkv1.CloudPrivateIPConfig{}
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ctx, cancel := context.WithTimeout(c.ctx, controller.ClientTimeout)
		defer cancel()
		warningTime := time.Now().Add(controller.APIResponseSoftLimit)
		var err error
		cloudPrivateIPConfig.Status = *status
		updatedCloudPrivateIPConfig, err = c.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().UpdateStatus(ctx, cloudPrivateIPConfig, metav1.UpdateOptions{})
		if time.Until(warningTime) <= 0 {
			klog.Warningf("CloudPrivateIPConfig: Update API call took longer than expected for resource %q, Egress IP configuration might be delayed",
				cloudPrivateIPConfig.Name)
		}
		return err
	})
	return updatedCloudPrivateIPConfig, err
}

type FinalizerPatch struct {
	Op    string   `json:"op"`
	Path  string   `json:"path"`
	Value []string `json:"value"`
}

// patchCloudPrivateIPConfigFinalizer patches the object and returns
// the new object. The return value can be useful for recursive updates
func (c *CloudPrivateIPConfigController) patchCloudPrivateIPConfigFinalizer(cloudPrivateIPConfig *cloudnetworkv1.CloudPrivateIPConfig) (*cloudnetworkv1.CloudPrivateIPConfig, error) {
	patchedCloudPrivateIPConfig := &cloudnetworkv1.CloudPrivateIPConfig{}
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		p := []FinalizerPatch{
			{
				Op:    "replace",
				Path:  "/metadata/finalizers",
				Value: cloudPrivateIPConfig.Finalizers,
			},
		}
		op, err := json.Marshal(&p)
		if err != nil {
			return fmt.Errorf("error serializing finalizer patch: %+v for CloudPrivateIPConfig: %s, err: %v", cloudPrivateIPConfig.Finalizers, cloudPrivateIPConfig.Name, err)
		}
		patchedCloudPrivateIPConfig, err = c.patchCloudPrivateIPConfig(cloudPrivateIPConfig.Name, op)
		return err
	})
	return patchedCloudPrivateIPConfig, err
}

func (c *CloudPrivateIPConfigController) patchCloudPrivateIPConfig(name string, patchData []byte) (*cloudnetworkv1.CloudPrivateIPConfig, error) {
	ctx, cancel := context.WithTimeout(c.ctx, controller.ClientTimeout)
	defer cancel()
	warningTime := time.Now().Add(controller.APIResponseSoftLimit)
	cloudPrivateIPConfig, err := c.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Patch(ctx, name, types.JSONPatchType, patchData, metav1.PatchOptions{})
	if time.Until(warningTime) <= 0 {
		klog.Warningf("CloudPrivateIPConfig: Patch API call took longer than expected for resource %q, Egress IP configuration might be delayed", name)
	}
	return cloudPrivateIPConfig, err
}

// getCloudPrivateIPConfig retrieves the object from the API server
func (c *CloudPrivateIPConfigController) getCloudPrivateIPConfig(name string) (*cloudnetworkv1.CloudPrivateIPConfig, error) {
	ctx, cancel := context.WithTimeout(c.ctx, controller.ClientTimeout)
	defer cancel()
	warningTime := time.Now().Add(controller.APIResponseSoftLimit)
	// This object will repeatedly be updated during this sync, hence we need to
	// retrieve the object from the API server as opposed to the informer cache
	// for every sync, otherwise we risk acting on an old object
	cloudPrivateIPConfig, err := c.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			// If the object was deleted while we were processing the request
			// there's nothing more to do, the finalizer portion of this sync
			// should have handled the last cleanup
			klog.Infof("CloudPrivateIPConfig: %q in work queue no longer exists", name)
			return nil, nil
		}
		return nil, err
	}
	if time.Until(warningTime) <= 0 {
		klog.Warningf("CloudPrivateIPConfig: Get API call took longer than expected for resource %q, Egress IP configuration might be delayed", name)
	}
	return cloudPrivateIPConfig, nil
}

// computeOp decides on what needs to be done given the state of the object. Result is (nodeToAdd, nodeToDel),
// meaning that plugin needs to remove the IP from nodeToDel and add IP to nodeToAdd. Both results are non-empty
// only when the plugin implements cloudprovider.CloudProviderWithMoveIntf and in such case MovePrivateIP will be
// called. Otherwise only one result will be populated and either AssignPrivateIP or ReleasePrivateIP will be called.
func (c *CloudPrivateIPConfigController) computeOp(cloudPrivateIPConfig *cloudnetworkv1.CloudPrivateIPConfig) (string, string) {
	// Delete if the deletion timestamp is set and we still have our finalizer listed
	if !cloudPrivateIPConfig.DeletionTimestamp.IsZero() && controllerutil.ContainsFinalizer(cloudPrivateIPConfig, cloudPrivateIPConfigFinalizer) {
		return "", cloudPrivateIPConfig.Status.Node
	}
	// If status and spec are different, attempt to move it if driver allows that or delete the
	// current object; we'll add it back with the updated value in the next sync
	if cloudPrivateIPConfig.Spec.Node != cloudPrivateIPConfig.Status.Node && cloudPrivateIPConfig.Status.Node != "" {
		if _, ok := c.cloudProviderClient.(cloudprovider.CloudProviderWithMoveIntf); ok {
			return cloudPrivateIPConfig.Spec.Node, cloudPrivateIPConfig.Status.Node
		}
		return "", cloudPrivateIPConfig.Status.Node
	}
	// Add if the status is un-assigned or if the status is marked failed
	if cloudPrivateIPConfig.Status.Node == "" || cloudPrivateIPConfig.Status.Conditions[0].Status != metav1.ConditionTrue {
		return cloudPrivateIPConfig.Spec.Node, ""
	}
	// Default to NOOP
	return "", ""
}
