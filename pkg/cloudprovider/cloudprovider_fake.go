package cloudprovider

import (
	"fmt"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

type FakeCloudProvider struct {
	mockErrorOnAssign                        bool
	mockErrorOnAssignWithExistingIPCondition bool
	mockErrorOnRelease                       bool
	mockErrorOnWait                          bool
	mockErrorOnGetNodeEgressIPConfiguration  bool
	delayedCompletion                        time.Duration
	StateTracker                             []string
}

func NewFakeCloudProvider(mockErrorOnAssign, mockErrorOnAssignWithExistingIPCondition, mockErrorOnRelease, mockErrorOnWait bool, delayedCompletion time.Duration) *FakeCloudProvider {
	return &FakeCloudProvider{
		mockErrorOnAssign:                        mockErrorOnAssign,
		mockErrorOnAssignWithExistingIPCondition: mockErrorOnAssignWithExistingIPCondition,
		mockErrorOnRelease:                       mockErrorOnRelease,
		mockErrorOnWait:                          mockErrorOnWait,
		delayedCompletion:                        delayedCompletion,
		StateTracker:                             make([]string, 0),
	}
}

func (f *FakeCloudProvider) initCredentials() error {
	return nil
}

func (f *FakeCloudProvider) AssignPrivateIP(ip net.IP, node *corev1.Node) error {
	f.StateTracker = append(f.StateTracker, fmt.Sprintf("assign-%v-%s", ip, node.Name))
	if f.mockErrorOnAssign {
		if f.mockErrorOnAssignWithExistingIPCondition {
			return AlreadyExistingIPError
		}
		return fmt.Errorf("Assign failed")
	}
	return f.waitForCompletion()
}

func (f *FakeCloudProvider) ReleasePrivateIP(ip net.IP, node *corev1.Node) error {
	f.StateTracker = append(f.StateTracker, fmt.Sprintf("release-%v-%s", ip, node.Name))
	if f.mockErrorOnRelease {
		return fmt.Errorf("Release failed")
	}
	return f.waitForCompletion()
}

func (f *FakeCloudProvider) waitForCompletion() error {
	if f.mockErrorOnWait {
		return fmt.Errorf("Waiting failed")
	}
	if f.delayedCompletion.Nanoseconds() != 0 {
		time.Sleep(f.delayedCompletion)
	}
	return nil
}

func (f *FakeCloudProvider) GetNodeEgressIPConfiguration(node *corev1.Node, cpicIPs sets.Set[string]) ([]*NodeEgressIPConfiguration, error) {
	if f.mockErrorOnGetNodeEgressIPConfiguration {
		return nil, fmt.Errorf("Get node egress IP configuration failed")
	}
	return nil, nil
}
