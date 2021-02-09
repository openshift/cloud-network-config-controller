package controller

import (
	"fmt"
	"reflect"
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	// maxRetries is the number of times a object will be retried before it is dropped out of the queue.
	// With the current rate-limiter in use (5ms*2^(maxRetries-1)) the following numbers represent the
	// sequence of delays between successive queueing of an object.
	//
	// 5ms, 10ms, 20ms, 40ms, 80ms, 160ms, 320ms, 640ms, 1.3s, 2.6s, 5.1s, 10.2s, 20.4s, 41s, 82s
	maxRetries = 15

	// defaultWorkerThreadiness is the number of goroutines spawned
	// to service an informer event queue. Use 10, mainly because
	// the cloud-private-ip-config controller will have a section
	// in its sync where it will block for quite a while for an
	// atomic operation. We don't want to hold up other IPs from
	// being processed during that window.
	defaultWorkerThreadiness = 10

	// ClientTimeout specifies the timeout for our calls to the API server for
	// all client operations
	ClientTimeout = 2 * time.Second
)

type CloudNetworkConfigControllerIntf interface {
	SyncHandler(key string) error
}

type CloudNetworkConfigController struct {
	// CloudNetworkConfigController implements the generic interface: which
	// allows all derived controllers an abstraction from the "bricks and pipes"
	// of the controller framework, allowing them to implement only their
	// specific control loop functionality and not bother with the rest.
	CloudNetworkConfigControllerIntf
	// Workqueue is a rate limited work queue. This is used to queue work to be
	// processed instead of performing it as soon as a change happens. This
	// means we can ensure we only process a fixed amount of resources at a
	// time, and makes it easy to ensure we are never processing the same item
	// simultaneously in two different workers.
	workqueue workqueue.RateLimitingInterface
	// Synced contains all required resource informers for a controller
	// to run
	synced []cache.InformerSynced
	// controllerKey is an internal key used for the Workqueue and
	// recorder
	controllerKey string
	// controllerType is the generic type watched for by the controller
	controllerType reflect.Type
}

func NewCloudNetworkConfigController(
	syncs []cache.InformerSynced,
	resourceController CloudNetworkConfigControllerIntf,
	resourceControllerKey string,
	resourceControllerType reflect.Type) *CloudNetworkConfigController {

	workqueue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), resourceControllerKey)

	return &CloudNetworkConfigController{
		workqueue:                        workqueue,
		synced:                           syncs,
		CloudNetworkConfigControllerIntf: resourceController,
		controllerKey:                    resourceControllerKey,
		controllerType:                   resourceControllerType,
	}
}

// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (c *CloudNetworkConfigController) Run(stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	defer c.workqueue.ShutDown()

	// Start the informer factories to begin populating the informer caches
	klog.Infof("Starting %s controller", c.controllerKey)

	// Wait for the caches to be synced before starting workers
	klog.Infof("Waiting for informer caches to sync for %s workqueue", c.controllerKey)
	if ok := cache.WaitForCacheSync(stopCh, c.synced...); !ok {
		return fmt.Errorf("failed to wait for caches to sync for %s workqueue", c.controllerKey)
	}

	klog.Infof("Starting %s workers", c.controllerKey)
	// Launch default amount of workers to process resources
	for i := 0; i < defaultWorkerThreadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	klog.Infof("Started %s workers", c.controllerKey)
	<-stopCh
	klog.Infof("Shutting down %s workers", c.controllerKey)

	return nil
}

// runWorker is a long-running function that will continually call the
// processNextWorkItem function in order to read and process a message on the
// workqueue.
func (c *CloudNetworkConfigController) runWorker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (c *CloudNetworkConfigController) processNextWorkItem() bool {
	obj, shutdown := c.workqueue.Get()

	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.workqueue.Done.
	err := func(obj interface{}) error {
		// We call Done here so the workqueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// put back on the workqueue and attempted again after a back-off
		// period.
		defer c.workqueue.Done(obj)
		var key string
		var ok bool
		// We expect strings to come off the workqueue. These are of the
		// form namespace/name. We do this as the delayed nature of the
		// workqueue means the items in the informer cache may actually be
		// more up to date that when the item was initially put onto the
		// workqueue.
		if key, ok = obj.(string); !ok {
			// As the item in the workqueue is actually invalid, we call
			// Forget here else we'd go into a loop of attempting to
			// process a work item that is invalid.
			c.workqueue.Forget(obj)
			klog.Errorf("expected string in %s workqueue but got %#v", c.controllerKey, obj)
			return nil
		}
		// Run the syncHandler, passing it the namespace/name string of the
		// Foo resource to be synced.
		if err := c.SyncHandler(key); err != nil && c.workqueue.NumRequeues(key) <= maxRetries {
			// Put the item back on the workqueue to handle any transient errors.
			c.workqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing in %s workqueue", key, err.Error(), c.controllerKey)
		}
		// Finally, if no error occurs or if we supersede maxRetries we Forget
		// this item so it does not get queued again until another change happens.
		c.workqueue.Forget(obj)
		klog.Infof("Dropping key '%s' from the %s workqueue", key, c.controllerKey)
		return nil
	}(obj)

	if err != nil {
		klog.Error(err)
		return true
	}

	return true
}

// Enqueue takes a resource object and converts it into a name/namespace or name
// string which is then put onto the work queue. This method __should__ not be
// passed resources of any type other than the dedicated controller object.
func (c *CloudNetworkConfigController) Enqueue(obj interface{}) {
	if c.controllerType == reflect.TypeOf(obj) {
		key, err := cache.MetaNamespaceKeyFunc(obj)
		if err != nil {
			klog.Error(err)
			return
		}
		klog.Infof("Assigning key: %s to %s workqueue", key, c.controllerKey)
		c.workqueue.Add(key)
		return
	}
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		klog.Errorf("error decoding object, invalid type: %#v", obj)
		return
	}
	if c.controllerType != reflect.TypeOf(tombstone.Obj) {
		klog.Errorf("error decoding object tombstone, invalid type: %#v", obj)
		return
	}
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Error(err)
		return
	}
	klog.Infof("Recovered key: %s and assigning to %s workqueue", key, c.controllerKey)
	c.workqueue.Add(key)
}
