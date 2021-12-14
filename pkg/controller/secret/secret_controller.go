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
	// secretControllerAgentType is the Secret controller's dedicated resource type
	secretControllerAgentType = reflect.TypeOf(&corev1.Secret{})
	// secretControllerAgentName is the controller name for the Secret controller
	secretControllerAgentName = "secret"
)

// SecretController is the controller implementation for Secret resources
// This controller is used to watch for secret rotations by the cloud-
// credentials-operator for what concerns the cloud API secret
type SecretController struct {
	controller.CloudNetworkConfigController
	secretLister corelisters.SecretLister
	// controllerCancel is the components global cancelFunc. It's used to
	// cancel the global context, stop the leader election and subsequently
	// initiate a shut down of all control loops
	controllerCancel context.CancelFunc
}

// NewSecretController returns a new Secret controller
func NewSecretController(
	controllerContext context.Context,
	controllerCancel context.CancelFunc,
	kubeClientset kubernetes.Interface,
	secretInformer coreinformers.SecretInformer,
	secretName, secretNamespace string) *controller.CloudNetworkConfigController {

	secretController := &SecretController{
		secretLister:     secretInformer.Lister(),
		controllerCancel: controllerCancel,
	}

	controller := controller.NewCloudNetworkConfigController(
		[]cache.InformerSynced{secretInformer.Informer().HasSynced},
		secretController,
		secretControllerAgentName,
		secretControllerAgentType,
	)

	secretFilter := func(obj interface{}) bool {
		if secret, ok := obj.(*corev1.Secret); ok {
			return secret.Name == secretName && secret.Namespace == secretNamespace
		}
		if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
			if secret, ok := tombstone.Obj.(*corev1.Secret); ok {
				return secret.Name == secretName && secret.Namespace == secretNamespace
			}
		}
		return false
	}

	secretInformer.Informer().AddEventHandler(cache.FilteringResourceEventHandler{
		FilterFunc: secretFilter,
		Handler: cache.ResourceEventHandlerFuncs{
			// Only handle updates and deletes
			//  - Add events can be avoided since the secret should already be
			// mounted for us to even start.
			UpdateFunc: func(old, new interface{}) {
				oldSecret, _ := old.(*corev1.Secret)
				newSecret, _ := new.(*corev1.Secret)

				// Don't process resync or objects that are marked for deletion
				if oldSecret.ResourceVersion == newSecret.ResourceVersion ||
					!newSecret.GetDeletionTimestamp().IsZero() {
					return
				}

				// Only enqueue on data change
				if !reflect.DeepEqual(oldSecret.Data, newSecret.Data) {
					controller.Enqueue(new)
				}
			},
			DeleteFunc: controller.Enqueue,
		},
	})
	return controller
}

// syncHandler does *not* compare the actual state with the desired, it's
// triggered on a secret.data change or secret deletion and cancels the global
// context forcing us to re-initialize the cloud credentials on restart.
func (s *SecretController) SyncHandler(key string) error {
	s.shutdown()
	return nil
}

// shutdown is called in case we hit a secret rotation. We need to: process all
// in-flight requests and pause all our controllers for any further ones (since
// we can't communicate with the cloud API using the old data anymore). I don't
// know what the "Kubernetes-y" thing to do is, but it seems like cancelling the
// global context and subsequently sending a SIGTERM will do just that.
func (s *SecretController) shutdown() {
	klog.Info("Re-initializing cloud API credentials, cancelling controller context")
	s.controllerCancel()
}
