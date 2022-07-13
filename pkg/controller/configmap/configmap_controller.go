package controller

import (
	"context"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	controller "github.com/openshift/cloud-network-config-controller/pkg/controller"
)

var (
	// configMapControllerAgentType is the ConfigMap controller's dedicated resource type
	configMapControllerAgentType = reflect.TypeOf(&corev1.ConfigMap{})
	// configMapControllerAgentName is the controller name for the ConfigMap controller
	configMapControllerAgentName = "configMap"
)

// ConfigMapController is the controller implementation for ConfigMap resources
// This controller is used to watch for configMap rotations by the cloud-
// credentials-operator for what concerns the cloud API configMap
type ConfigMapController struct {
	controller.CloudNetworkConfigController
	configMapLister corelisters.ConfigMapLister
	// controllerCancel is the components global cancelFunc. It's used to
	// cancel the global context, stop the leader election and subsequently
	// initiate a shut down of all control loops
	controllerCancel context.CancelFunc
}

// NewConfigMapController returns a new ConfigMap controller
func NewConfigMapController(
	controllerContext context.Context,
	controllerCancel context.CancelFunc,
	kubeClientset kubernetes.Interface,
	configMapInformer coreinformers.ConfigMapInformer,
	configMapName, configMapNamespace string) *controller.CloudNetworkConfigController {

	configMapController := &ConfigMapController{
		configMapLister:  configMapInformer.Lister(),
		controllerCancel: controllerCancel,
	}

	controller := controller.NewCloudNetworkConfigController(
		[]cache.InformerSynced{configMapInformer.Informer().HasSynced},
		configMapController,
		configMapControllerAgentName,
		configMapControllerAgentType,
	)

	configMapFilter := func(obj interface{}) bool {
		if configMap, ok := obj.(*corev1.ConfigMap); ok {
			return configMap.Name == configMapName && configMap.Namespace == configMapNamespace
		}
		if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
			if configMap, ok := tombstone.Obj.(*corev1.ConfigMap); ok {
				return configMap.Name == configMapName && configMap.Namespace == configMapNamespace
			}
		}
		return false
	}

	configMapInformer.Informer().AddEventHandler(cache.FilteringResourceEventHandler{
		FilterFunc: configMapFilter,
		Handler: cache.ResourceEventHandlerFuncs{
			// Only handle updates and deletes
			//  - Add events can be avoided since the configMap should already be
			// mounted for us to even start.
			UpdateFunc: func(old, new interface{}) {
				oldConfigMap, _ := old.(*corev1.ConfigMap)
				newConfigMap, _ := new.(*corev1.ConfigMap)

				// Don't process resync or objects that are marked for deletion
				if oldConfigMap.ResourceVersion == newConfigMap.ResourceVersion ||
					!newConfigMap.GetDeletionTimestamp().IsZero() {
					return
				}

				// Only enqueue on data change
				if !reflect.DeepEqual(oldConfigMap.Data, newConfigMap.Data) {
					controller.Enqueue(new)
				}
			},
			DeleteFunc: controller.Enqueue,
		},
	})
	return controller
}

// syncHandler does *not* compare the actual state with the desired, it's
// triggered on a configMap.data change or configMap deletion and cancels the global
// context forcing us to re-initialize the cloud credentials on restart.
func (s *ConfigMapController) SyncHandler(key string) error {
	s.shutdown()
	return nil
}

// shutdown is called in case we hit a configMap rotation. We need to: process all
// in-flight requests and pause all our controllers for any further ones (since
// we can't communicate with the cloud API using the old data anymore). I don't
// know what the "Kubernetes-y" thing to do is, but it seems like cancelling the
// global context and subsequently sending a SIGTERM will do just that.
func (s *ConfigMapController) shutdown() {
	klog.Info("Re-initializing cloud API credentials, cancelling controller context")
	s.controllerCancel()
}
