package controller

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	cloudnetworkv1 "github.com/openshift/api/cloudnetwork/v1"
	fakecloudnetworkclientset "github.com/openshift/client-go/cloudnetwork/clientset/versioned/fake"
	cloudnetworkinformers "github.com/openshift/client-go/cloudnetwork/informers/externalversions"
	cloudprovider "github.com/openshift/cloud-network-config-controller/pkg/cloudprovider"
	controller "github.com/openshift/cloud-network-config-controller/pkg/controller"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubeinformers "k8s.io/client-go/informers"
	fakekubeclient "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

var (
	cloudPrivateIPConfigName = "192.168.172.12"
	nodeNameA                = "nodeA"
	nodeNameB                = "nodeB"
	nodeNameC                = "nodeC"
)

var (
	nodeA = corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: nodeNameA,
		},
	}
	nodeB = corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: nodeNameB,
		},
	}
	nodeC = corev1.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: nodeNameC,
		},
	}
)

type FakeCloudPrivateIPConfigController struct {
	*controller.CloudNetworkConfigController
	kubeClient                *fakekubeclient.Clientset
	cloudNetworkClient        *fakecloudnetworkclientset.Clientset
	cloudProvider             *cloudprovider.FakeCloudProvider
	cloudPrivateIPConfigStore cache.Store
	nodeStore                 cache.Store
}

func (f *FakeCloudPrivateIPConfigController) initTestSetup(cloudPrivateIPConfig *cloudnetworkv1.CloudPrivateIPConfig) {
	f.cloudPrivateIPConfigStore.Add(cloudPrivateIPConfig)
	f.initNodes()
}

func (f FakeCloudPrivateIPConfigController) initNodes() {
	f.nodeStore.Add(&nodeA)
	f.nodeStore.Add(&nodeB)
	f.nodeStore.Add(&nodeC)
}

type CloudPrivateIPConfigTestCase struct {
	name                               string
	isUpdate                           bool
	mockCloudAssignError               bool
	mockCloudAssignErrorWithExistingIP bool
	mockCloudReleaseError              bool
	mockCloudWaitError                 bool
	delayedCompletion                  time.Duration
	testObject                         *cloudnetworkv1.CloudPrivateIPConfig
	expectedObject                     *cloudnetworkv1.CloudPrivateIPConfig
	expectedTrackedState               []string
	expectErrorOnAssignSync            bool
	expectErrorOnReleaseSync           bool
}

func (t *CloudPrivateIPConfigTestCase) NewFakeCloudPrivateIPConfigController() *FakeCloudPrivateIPConfigController {

	fakeCloudNetworkClient := fakecloudnetworkclientset.NewSimpleClientset([]runtime.Object{t.testObject}...)
	fakeKubeClient := fakekubeclient.NewSimpleClientset()
	fakeCloudProvider := cloudprovider.NewFakeCloudProvider(t.mockCloudAssignError, t.mockCloudAssignErrorWithExistingIP, t.mockCloudReleaseError, t.mockCloudWaitError, t.delayedCompletion)

	kubeInformerFactory := kubeinformers.NewSharedInformerFactory(fakeKubeClient, 0)
	cloudNetworkInformerFactory := cloudnetworkinformers.NewSharedInformerFactory(fakeCloudNetworkClient, 0)

	cloudPrivateIPConfigController := NewCloudPrivateIPConfigController(
		context.TODO(),
		fakeCloudProvider,
		fakeCloudNetworkClient,
		cloudNetworkInformerFactory.Cloud().V1().CloudPrivateIPConfigs(),
		kubeInformerFactory.Core().V1().Nodes(),
	)

	fakeCloudPrivateIPConfigController := &FakeCloudPrivateIPConfigController{
		CloudNetworkConfigController: cloudPrivateIPConfigController,
		kubeClient:                   fakeKubeClient,
		cloudNetworkClient:           fakeCloudNetworkClient,
		cloudProvider:                fakeCloudProvider,
		cloudPrivateIPConfigStore:    cloudNetworkInformerFactory.Cloud().V1().CloudPrivateIPConfigs().Informer().GetStore(),
		nodeStore:                    kubeInformerFactory.Core().V1().Nodes().Informer().GetStore(),
	}

	fakeCloudPrivateIPConfigController.initTestSetup(t.testObject)

	return fakeCloudPrivateIPConfigController
}

func assertSyncedExpectedObjectsEqual(synced, expected *cloudnetworkv1.CloudPrivateIPConfig) error {
	if len(synced.Status.Conditions) != len(expected.Status.Conditions) {
		return fmt.Errorf("synced object does not have expected status condition length, synced: %v, expected: %v", len(synced.Status.Conditions), len(expected.Status.Conditions))
	}
	if len(synced.Status.Conditions) == 0 {
		return nil
	}
	if synced.Status.Node != expected.Status.Node {
		return fmt.Errorf("synced object does not have expected node assignment, synced: %s, expected: %s", synced.Status.Node, expected.Status.Node)
	}
	if synced.Status.Conditions[0].Reason != expected.Status.Conditions[0].Reason {
		return fmt.Errorf("synced object does not have expected condition type, synced: %v, expected: %v", synced.Status.Conditions[0].Reason, expected.Status.Conditions[0].Reason)
	}
	if synced.Status.Conditions[0].Status != expected.Status.Conditions[0].Status {
		return fmt.Errorf("synced object does not have expected condition status, synced: %s, expected: %s", synced.Status.Conditions[0].Status, expected.Status.Conditions[0].Status)
	}
	if !reflect.DeepEqual(synced.GetFinalizers(), expected.GetFinalizers()) {
		return fmt.Errorf("synced object does not have expected finalizers, synced: %v, expected: %v", synced.GetFinalizers(), expected.GetFinalizers())
	}
	return nil
}

func assertStateEquals(syncedState, expectedState []string) error {
	if len(syncedState) != len(expectedState) {
		return fmt.Errorf("synced state does not have as many changes (%v) as expected: %v\nsynced state: %v", len(syncedState), len(expectedState), syncedState)
	}
	for i := 0; i < len(syncedState); i++ {
		if syncedState[i] != expectedState[i] {
			return fmt.Errorf("synced state: %s does not match expected: %s, at change: %v", syncedState[i], expectedState[i], i)
		}
	}
	return nil
}

// TestSyncCloudPrivateIPConfig tests sync state for our CloudPrivateIPConfig
// control loop. It does not test:
//  - that the node specified is valid - that is handled by the admission controller
//  - that the CloudPrivateIPConfig name is a valid IP - that is handled by OpenAPI
// Hence, all tests here are written with a valid spec. Moreover, this
// controller neither deletes nor creates objects. Hence the only Kubernetes
// action we need to verify is update, i.e: that the control loop updates the
// resource as expected during its sync.
func TestSyncAddCloudPrivateIPConfig(t *testing.T) {
	tests := []CloudPrivateIPConfigTestCase{
		{
			name: "Should be able to sync object on add without any errors",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionTrue,
							Reason: cloudResponseReasonSuccess,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
		},
		{
			name: "Should fail to sync object on add with assign error",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionFalse,
							Reason: cloudResponseReasonError,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
			mockCloudAssignError:    true,
			expectErrorOnAssignSync: true,
		},
		{
			name: "Should fail to sync object on add with wait error",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionFalse,
							Reason: cloudResponseReasonError,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
			mockCloudWaitError:      true,
			expectErrorOnAssignSync: true,
		},
		{
			name: "Should be able to re-sync object on add with AlreadyExistingIPError",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					// Node = "nodeNameA" means the object was processed as an
					// add during the last sync, but failed
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type: string(cloudnetworkv1.Assigned),
							// Fake a pending sync in the last term by setting an
							// unknown status. This would "IRL" mean that this
							// controller died while processing this object
							// during its last sync term, and now has restarted
							// and should re-sync it correctly.
							Status: v1.ConditionUnknown,
							Reason: cloudResponseReasonPending,
						},
					},
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionTrue,
							Reason: cloudResponseReasonSuccess,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
			mockCloudAssignError:               true,
			mockCloudAssignErrorWithExistingIP: true,
		},
		{
			name: "Should be able to re-sync object and add finalizer on add with AlreadyExistingIPError",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionTrue,
							Reason: cloudResponseReasonSuccess,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
			mockCloudAssignError:               true,
			mockCloudAssignErrorWithExistingIP: true,
		},
		{
			name: "Should fail to re-sync object on add with assign error",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					// Node = "nodeNameA" means the object was processed as an
					// add during the last sync, but failed
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type: string(cloudnetworkv1.Assigned),
							// Fake a pending sync in the last term by setting an
							// unknown status. This would "IRL" mean that this
							// controller died while processing this object
							// during its last sync term, and now has restarted
							// and should re-sync it correctly.
							Status: v1.ConditionUnknown,
							Reason: cloudResponseReasonPending,
						},
					},
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionFalse,
							Reason: cloudResponseReasonError,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
			mockCloudAssignError:    true,
			expectErrorOnAssignSync: true,
		},
		{
			name: "Should fail to re-sync object on add with wait error",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					// Node = "nodeNameA" means the object was processed as an
					// add during the last sync, but didn't finish
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type: string(cloudnetworkv1.Assigned),
							// Fake a pending sync in the last term by setting an
							// unknown status. This would "IRL" mean that this
							// controller died while processing this object
							// during its last sync term, and now has restarted
							// and should re-sync it correctly.
							Status: v1.ConditionUnknown,
							Reason: cloudResponseReasonPending,
						},
					},
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionFalse,
							Reason: cloudResponseReasonError,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
			mockCloudWaitError:      true,
			expectErrorOnAssignSync: true,
		},
		{
			name: "Should be able to re-sync object on add without any cloud errors",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Conditions: []v1.Condition{
						{
							Type: string(cloudnetworkv1.Assigned),
							// Fake a failed sync in the last term by setting a
							// false status.
							Status:  v1.ConditionFalse,
							Reason:  cloudResponseReasonError,
							Message: "Something bad happened during the last sync",
						},
					},
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						v1.Condition{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionTrue,
							Reason: cloudResponseReasonSuccess,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
		},
	}
	runTests(t, tests)
}

func TestSyncDeleteCloudPrivateIPConfig(t *testing.T) {
	tests := []CloudPrivateIPConfigTestCase{
		{
			name: "Should be able to sync object on delete without any errors",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					// Fake a deletion by setting the time to anything
					DeletionTimestamp: &v1.Time{time.Now()},
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionTrue,
							Reason: cloudResponseReasonSuccess,
						},
					},
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name:       cloudPrivateIPConfigName,
					Finalizers: []string{},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionUnknown,
							Reason: cloudResponseReasonPending,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("release-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
		},
		{
			name: "Should fail to sync object on delete with release error",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					// Fake a deletion by setting the time to anything
					DeletionTimestamp: &v1.Time{time.Now()},
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionTrue,
							Reason: cloudResponseReasonSuccess,
						},
					},
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionFalse,
							Reason: cloudResponseReasonError,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("release-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
			mockCloudReleaseError:    true,
			expectErrorOnReleaseSync: true,
		},
		{
			name: "Should fail to sync object on delete with wait error",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					// Fake a deletion by setting the time to anything
					DeletionTimestamp: &v1.Time{time.Now()},
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionTrue,
							Reason: cloudResponseReasonSuccess,
						},
					},
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionFalse,
							Reason: cloudResponseReasonError,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("release-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
			mockCloudWaitError:       true,
			expectErrorOnReleaseSync: true,
		},
		{
			name: "Should be able to re-sync object on delete with no errors",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					// Fake a deletion by setting the time to anything
					DeletionTimestamp: &v1.Time{time.Now()},
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						// Fake an unsuccessful release in the last term
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionFalse,
							Reason: cloudResponseReasonError,
						},
					},
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name:       cloudPrivateIPConfigName,
					Finalizers: []string{},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionUnknown,
							Reason: cloudResponseReasonPending,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("release-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
		},
		{
			name: "Should fail to re-sync object on delete with release error",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					// Fake a deletion by setting the time to anything
					DeletionTimestamp: &v1.Time{time.Now()},
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						// Fake an unsuccessful release in the last term
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionFalse,
							Reason: cloudResponseReasonError,
						},
					},
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionFalse,
							Reason: cloudResponseReasonError,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("release-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
			mockCloudReleaseError:    true,
			expectErrorOnReleaseSync: true,
		},
		{
			name: "Should fail to re-sync object on delete with wait error",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					// Fake a deletion by setting the time to anything
					DeletionTimestamp: &v1.Time{time.Now()},
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						// Fake an unsuccessful release in the last term
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionFalse,
							Reason: cloudResponseReasonError,
						},
					},
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameA,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionFalse,
							Reason: cloudResponseReasonError,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("release-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
			mockCloudWaitError:       true,
			expectErrorOnReleaseSync: true,
		},
	}
	runTests(t, tests)
}

func TestSyncUpdateCloudPrivateIPConfig(t *testing.T) {
	tests := []CloudPrivateIPConfigTestCase{
		{
			name: "Should be able to sync object on update without any errors",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameB,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionTrue,
							Reason: cloudResponseReasonSuccess,
						},
					},
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameB,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameB,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionTrue,
							Reason: cloudResponseReasonSuccess,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("release-%s-%s", cloudPrivateIPConfigName, nodeNameA),
				fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameB),
			},
			isUpdate: true,
		},
		{
			name: "Should fail to sync object on update with release error",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameB,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionTrue,
							Reason: cloudResponseReasonSuccess,
						},
					},
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameB,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionFalse,
							Reason: cloudResponseReasonError,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("release-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
			mockCloudReleaseError:    true,
			expectErrorOnReleaseSync: true,
		},
		{
			name: "Should fail to sync object on update with wait on release error",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameB,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionTrue,
							Reason: cloudResponseReasonSuccess,
						},
					},
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameB,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionFalse,
							Reason: cloudResponseReasonError,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("release-%s-%s", cloudPrivateIPConfigName, nodeNameA),
			},
			mockCloudWaitError:       true,
			expectErrorOnReleaseSync: true,
		},
		{
			name: "Should fail to sync object on update with assign error",
			testObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameB,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Node: nodeNameA,
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionTrue,
							Reason: cloudResponseReasonSuccess,
						},
					},
				},
			},
			expectedObject: &cloudnetworkv1.CloudPrivateIPConfig{
				ObjectMeta: v1.ObjectMeta{
					Name: cloudPrivateIPConfigName,
					Finalizers: []string{
						cloudPrivateIPConfigFinalizer,
					},
				},
				Spec: cloudnetworkv1.CloudPrivateIPConfigSpec{
					Node: nodeNameB,
				},
				Status: cloudnetworkv1.CloudPrivateIPConfigStatus{
					Conditions: []v1.Condition{
						{
							Type:   string(cloudnetworkv1.Assigned),
							Status: v1.ConditionFalse,
							Reason: cloudResponseReasonError,
						},
					},
				},
			},
			expectedTrackedState: []string{
				fmt.Sprintf("release-%s-%s", cloudPrivateIPConfigName, nodeNameA),
				fmt.Sprintf("assign-%s-%s", cloudPrivateIPConfigName, nodeNameB),
			},
			isUpdate:                true,
			mockCloudAssignError:    true,
			expectErrorOnAssignSync: true,
		},
	}
	runTests(t, tests)
}

func runTests(t *testing.T, tests []CloudPrivateIPConfigTestCase) {
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller := test.NewFakeCloudPrivateIPConfigController()
			if test.isUpdate {
				if err := controller.CloudNetworkConfigController.SyncHandler(test.testObject.Name); err != nil && !test.expectErrorOnReleaseSync {
					t.Fatalf("sync expected no error, but got err: %v", err)
				}
			}
			if err := controller.CloudNetworkConfigController.SyncHandler(test.testObject.Name); err != nil && (!test.expectErrorOnAssignSync && !test.expectErrorOnReleaseSync) {
				t.Fatalf("sync expected no error, but got err: %v", err)
			}
			syncedObject, err := controller.cloudNetworkClient.CloudV1().CloudPrivateIPConfigs().Get(context.TODO(), test.testObject.Name, v1.GetOptions{})
			if err != nil {
				t.Fatalf("could not get object for test assertion, err: %v", err)
			}
			if err := assertSyncedExpectedObjectsEqual(syncedObject, test.expectedObject); err != nil {
				t.Fatalf("synced object did not match expected one, err: %v", err)
			}
			if err := assertStateEquals(controller.cloudProvider.StateTracker, test.expectedTrackedState); err != nil {
				t.Fatalf("synced tracked state did not match expected one, err: %v", err)
			}
		})
	}
}

func TestCloudPrivateIPConfigNameToIP(t *testing.T) {
	tests := []struct {
		name      string
		exectedIP net.IP
	}{
		{
			"fc00.f853.0ccd.e793.0000.0000.0000.0054",
			net.ParseIP("fc00:f853:ccd:e793::54"),
		},
		{
			"192.172.168.4",
			net.ParseIP("192.172.168.4"),
		},
	}
	for _, test := range tests {
		actualIP := cloudPrivateIPConfigNameToIP(test.name)
		if !test.exectedIP.Equal(actualIP) {
			t.Fatalf("Expected CloudPrivateIPConfigName %s to match IP: %v, but got: %v", test.name, test.exectedIP, actualIP)
		}
	}
}
