// +build !race

package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	cloudnetworkv1 "github.com/openshift/api/cloudnetwork/v1"
	fakecloudnetworkclientset "github.com/openshift/client-go/cloudnetwork/clientset/versioned/fake"
	cloudnetworkinformers "github.com/openshift/client-go/cloudnetwork/informers/externalversions"
	cloudprovider "github.com/openshift/cloud-network-config-controller/pkg/cloudprovider"
	controller "github.com/openshift/cloud-network-config-controller/pkg/controller"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubeinformers "k8s.io/client-go/informers"
	fakekubeclient "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

// FakeRacyCloudPrivateIPConfigController is racy by design. Everything in this
// file races and will have the test runner screaaaaaam if not ignored during
// testing
type FakeRacyCloudPrivateIPConfigController struct {
	*controller.CloudNetworkConfigController
	kubeClient         *fakekubeclient.Clientset
	cloudNetworkClient *fakecloudnetworkclientset.Clientset
	cloudProvider      *cloudprovider.FakeCloudProvider
}

func NewFakeRacyCloudPrivateIPConfigController(delayCompletion time.Duration) *FakeRacyCloudPrivateIPConfigController {

	fakeCloudNetworkClient := fakecloudnetworkclientset.NewSimpleClientset()
	fakeKubeClient := fakekubeclient.NewSimpleClientset([]runtime.Object{&nodeA, &nodeB, &nodeC}...)
	fakeCloudProvider := cloudprovider.NewFakeCloudProvider(false, false, false, false, delayCompletion)

	kubeInformerFactory := kubeinformers.NewSharedInformerFactory(fakeKubeClient, 0)
	cloudNetworkInformerFactory := cloudnetworkinformers.NewSharedInformerFactory(fakeCloudNetworkClient, 0)

	cloudPrivateIPConfigController := NewCloudPrivateIPConfigController(
		context.TODO(),
		fakeCloudProvider,
		fakeCloudNetworkClient,
		cloudNetworkInformerFactory.Cloud().V1().CloudPrivateIPConfigs(),
		kubeInformerFactory.Core().V1().Nodes(),
	)

	fakeCloudPrivateIPConfigController := &FakeRacyCloudPrivateIPConfigController{
		CloudNetworkConfigController: cloudPrivateIPConfigController,
		kubeClient:                   fakeKubeClient,
		cloudNetworkClient:           fakeCloudNetworkClient,
		cloudProvider:                fakeCloudProvider,
	}

	c := make(chan struct{})
	kubeInformerFactory.Start(c)
	cloudNetworkInformerFactory.Start(c)
	go cloudPrivateIPConfigController.Run(c)

	cache.WaitForCacheSync(c, cloudNetworkInformerFactory.Cloud().V1().CloudPrivateIPConfigs().Informer().HasSynced, kubeInformerFactory.Core().V1().Nodes().Informer().HasSynced)

	return fakeCloudPrivateIPConfigController
}

func TestDelayedCompletionWithCoalescedUpdatesBeforeFirstCreateOperationFinishes(t *testing.T) {
	// The following test executes the scenario below (brackets indicate expect
	// time to execute, paranthesis: parallel event):
	// time: 0
	// +NodeA [100ms]
	// (Update to NodeB - 50ms in)
	// (Update to NodeC - 10ms in)
	// -NodeA [100ms]
	// +NodeC [100ms]
	testObject := &cloudnetworkv1.CloudPrivateIPConfig{
		ObjectMeta: v1.ObjectMeta{
			Name: cloudPrivateIPConfigName,
		},
		Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
			Node: nodeNameA,
		},
	}
	expectedObject := &cloudnetworkv1.CloudPrivateIPConfig{
		ObjectMeta: v1.ObjectMeta{
			Name: cloudPrivateIPConfigName,
			Finalizers: []string{
				cloudPrivateIPConfigFinalizer,
			},
		},
		Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
			Node: nodeNameC,
		},
		Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
			Node: nodeNameC,
			Conditions: []v1.Condition{
				{
					Type:   string(cloudnetworkv1.Assigned),
					Status: v1.ConditionTrue,
					Reason: cloudResponseReasonSuccess,
				},
			},
		},
	}
	expectedTrackedState := []string{
		fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameA),
		fmt.Sprintf("release-%s-%s", cloudPrivateIPConfigName, nodeNameA),
		fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameC),
	}

	fakeController := NewFakeRacyCloudPrivateIPConfigController(100 * time.Millisecond)

	// This will take one second to complete
	_, err := fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Create(context.TODO(), testObject, v1.CreateOptions{})
	if err != nil {
		t.Fatalf("error creating the object, err: %v", err)
	}

	// Simulate an update to nodeB in the middle of the setup to nodeA. If
	// everything goes well, this update should just be skipped.
	time.Sleep(50 * time.Millisecond)
	syncedObject, err := fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Get(context.TODO(), cloudPrivateIPConfigName, v1.GetOptions{})
	if err != nil {
		t.Fatalf("error getting the object, err: %v", err)
	}
	syncedObject.Spec.Node = nodeNameB
	if _, err := fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Update(context.TODO(), syncedObject, v1.UpdateOptions{}); err != nil {
		t.Fatalf("error updating the object, err: %v", err)
	}

	// "Cancel" the setup to nodeB and assign it to nodeC while the setup to
	// nodeA is still occuring. This should now remove the setup on nodeA and
	// assign it to nodeC, which should take an additional 2 seconds (one for
	// the removal and one for the setup)
	time.Sleep(10 * time.Millisecond)
	syncedObject, err = fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Get(context.TODO(), cloudPrivateIPConfigName, v1.GetOptions{})
	if err != nil {
		t.Fatalf("error getting the object, err: %v", err)
	}
	syncedObject.Spec.Node = nodeNameC
	tmp, err := fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Update(context.TODO(), syncedObject, v1.UpdateOptions{})
	if err != nil {
		t.Fatalf("error updating the object a second time, err: %v, %+v", err, tmp)
	}

	time.Sleep(300 * time.Millisecond)
	syncedObject, err = fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Get(context.TODO(), cloudPrivateIPConfigName, v1.GetOptions{})
	if err != nil {
		t.Fatalf("error getting the object, err: %v", err)
	}
	if err := assertSyncedExpectedObjectsEqual(syncedObject, expectedObject); err != nil {
		t.Fatalf("synced object did not match expected one, err: %v", err)
	}
	if err := assertStateEquals(fakeController.cloudProvider.StateTracker, expectedTrackedState); err != nil {
		t.Fatalf("synced tracked state did not match expected one, err: %v", err)
	}
}

func TestDelayedCompletionWithCoalescedUpdatesAfterFirstCreateOperationFinishes(t *testing.T) {
	// The following test executes the scenario below (brackets indicate expect
	// time to execute, paranthesis: parallel event):
	// time: 0
	// +NodeA [100ms]
	// (Update to NodeB - 200ms in)
	// -NodeA [100ms]
	// (Update to NodeC - 10ms in)
	// +NodeC 100ms
	// Small explainer: the above case is correct because it takes the sync
	// 100ms to remove the assignment to NodeA, during which the update to NodeC
	// comes in. The update from NodeB -> NodeC thus gets override and we don't
	// perform an additional unnecessary operation to NodeB
	testObject := &cloudnetworkv1.CloudPrivateIPConfig{
		ObjectMeta: v1.ObjectMeta{
			Name: cloudPrivateIPConfigName,
		},
		Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
			Node: nodeNameA,
		},
	}
	expectedObject := &cloudnetworkv1.CloudPrivateIPConfig{
		ObjectMeta: v1.ObjectMeta{
			Name: cloudPrivateIPConfigName,
			Finalizers: []string{
				cloudPrivateIPConfigFinalizer,
			},
		},
		Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
			Node: nodeNameC,
		},
		Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
			Node: nodeNameC,
			Conditions: []v1.Condition{
				{
					Type:   string(cloudnetworkv1.Assigned),
					Status: v1.ConditionTrue,
					Reason: cloudResponseReasonSuccess,
				},
			},
		},
	}
	expectedTrackedState := []string{
		fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameA),
		fmt.Sprintf("release-%s-%s", cloudPrivateIPConfigName, nodeNameA),
		fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameC),
	}

	fakeController := NewFakeRacyCloudPrivateIPConfigController(100 * time.Millisecond)

	// This will take 100 ms to complete
	_, err := fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Create(context.TODO(), testObject, v1.CreateOptions{})
	if err != nil {
		t.Fatalf("error creating the object, err: %v", err)
	}

	// Simulate an update to nodeB after the setup to nodeA is complete
	time.Sleep(200 * time.Millisecond)
	syncedObject, err := fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Get(context.TODO(), cloudPrivateIPConfigName, v1.GetOptions{})
	if err != nil {
		t.Fatalf("error getting the object, err: %v", err)
	}
	syncedObject.Spec.Node = nodeNameB
	if _, err := fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Update(context.TODO(), syncedObject, v1.UpdateOptions{}); err != nil {
		t.Fatalf("error updating the object, err: %v", err)
	}

	// "Cancel" the setup to nodeB and assign it to nodeC. This should now skip
	// the setup on nodeB and assign it to nodeC, since this update happens
	// while we are still removing the setup on nodeA
	time.Sleep(10 * time.Millisecond)
	syncedObject, err = fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Get(context.TODO(), cloudPrivateIPConfigName, v1.GetOptions{})
	if err != nil {
		t.Fatalf("error getting the object, err: %v", err)
	}
	syncedObject.Spec.Node = nodeNameC
	tmp, err := fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Update(context.TODO(), syncedObject, v1.UpdateOptions{})
	if err != nil {
		t.Fatalf("error updating the object a second time, err: %v, %+v", err, tmp)
	}

	time.Sleep(300 * time.Millisecond)
	syncedObject, err = fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Get(context.TODO(), cloudPrivateIPConfigName, v1.GetOptions{})
	if err != nil {
		t.Fatalf("error getting the object, err: %v", err)
	}
	if err := assertSyncedExpectedObjectsEqual(syncedObject, expectedObject); err != nil {
		t.Fatalf("synced object did not match expected one, err: %v", err)
	}
	if err := assertStateEquals(fakeController.cloudProvider.StateTracker, expectedTrackedState); err != nil {
		t.Fatalf("synced tracked state did not match expected one, err: %v", err)
	}
}

func TestDelayedCompletionWithCoalescedUpdatesAfterFirstCreateOperationFinishesAgain(t *testing.T) {
	// The following test executes the scenario below (brackets indicate expect
	// time to execute, paranthesis: parallel event):
	// time: 0
	// +NodeA [100ms]
	// (Update to NodeB - 200ms in)
	// -NodeA [100ms]
	// (Update to NodeC - 110ms in)
	// +NodeB [100ms]
	// -NodeB [100ms]
	// +NodeC 100ms
	// Small explainer: the above case is correct because it takes the sync
	// 100ms to remove the assignment to NodeA. Since the update to NodeC comes
	// in at 110ms, the assign to NodeB has already started. Once that has
	// happened it needs to finish assigning it and removing it before updating
	// the assignment to NodeC. This case cannot go any other way and there is
	// no better solution. perform an additional unnecessary operation to NodeB
	testObject := &cloudnetworkv1.CloudPrivateIPConfig{
		ObjectMeta: v1.ObjectMeta{
			Name: cloudPrivateIPConfigName,
		},
		Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
			Node: nodeNameA,
		},
	}
	expectedObject := &cloudnetworkv1.CloudPrivateIPConfig{
		ObjectMeta: v1.ObjectMeta{
			Name: cloudPrivateIPConfigName,
			Finalizers: []string{
				cloudPrivateIPConfigFinalizer,
			},
		},
		Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
			Node: nodeNameC,
		},
		Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
			Node: nodeNameC,
			Conditions: []v1.Condition{
				{
					Type:   string(cloudnetworkv1.Assigned),
					Status: v1.ConditionTrue,
					Reason: cloudResponseReasonSuccess,
				},
			},
		},
	}
	expectedTrackedState := []string{
		fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameA),
		fmt.Sprintf("release-%s-%s", cloudPrivateIPConfigName, nodeNameA),
		fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameB),
		fmt.Sprintf("release-%s-%s", cloudPrivateIPConfigName, nodeNameB),
		fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameC),
	}

	fakeController := NewFakeRacyCloudPrivateIPConfigController(100 * time.Millisecond)

	// This will take one second to complete
	_, err := fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Create(context.TODO(), testObject, v1.CreateOptions{})
	if err != nil {
		t.Fatalf("error creating the object, err: %v", err)
	}

	// Simulate an update to nodeB after the setup to nodeA is complete
	time.Sleep(200 * time.Millisecond)
	syncedObject, err := fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Get(context.TODO(), cloudPrivateIPConfigName, v1.GetOptions{})
	if err != nil {
		t.Fatalf("error getting the object, err: %v", err)
	}
	syncedObject.Spec.Node = nodeNameB
	if _, err := fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Update(context.TODO(), syncedObject, v1.UpdateOptions{}); err != nil {
		t.Fatalf("error updating the object, err: %v", err)
	}

	// "Cancel" the setup to nodeB and assign it to nodeC. This should not skip
	// the setup on nodeB since this update happens after the assignment to
	// nodeB has started
	time.Sleep(110 * time.Millisecond)
	syncedObject, err = fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Get(context.TODO(), cloudPrivateIPConfigName, v1.GetOptions{})
	if err != nil {
		t.Fatalf("error getting the object, err: %v", err)
	}
	syncedObject.Spec.Node = nodeNameC
	tmp, err := fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Update(context.TODO(), syncedObject, v1.UpdateOptions{})
	if err != nil {
		t.Fatalf("error updating the object a second time, err: %v, %+v", err, tmp)
	}

	time.Sleep(300 * time.Millisecond)
	syncedObject, err = fakeController.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Get(context.TODO(), cloudPrivateIPConfigName, v1.GetOptions{})
	if err != nil {
		t.Fatalf("error getting the object, err: %v", err)
	}
	if err := assertSyncedExpectedObjectsEqual(syncedObject, expectedObject); err != nil {
		t.Fatalf("synced object did not match expected one, err: %v", err)
	}
	if err := assertStateEquals(fakeController.cloudProvider.StateTracker, expectedTrackedState); err != nil {
		t.Fatalf("synced tracked state did not match expected one, err: %v", err)
	}
}
