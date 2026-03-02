package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	cloudnetworkclientset "github.com/openshift/client-go/cloudnetwork/clientset/versioned"
	cloudnetworkscheme "github.com/openshift/client-go/cloudnetwork/clientset/versioned/scheme"
	cloudnetworkinformers "github.com/openshift/client-go/cloudnetwork/informers/externalversions"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	cloudprovider "github.com/openshift/cloud-network-config-controller/pkg/cloudprovider"
	cloudprivateipconfigcontroller "github.com/openshift/cloud-network-config-controller/pkg/controller/cloudprivateipconfig"
	configmapcontroller "github.com/openshift/cloud-network-config-controller/pkg/controller/configmap"
	nodecontroller "github.com/openshift/cloud-network-config-controller/pkg/controller/node"
	secretcontroller "github.com/openshift/cloud-network-config-controller/pkg/controller/secret"
	signals "github.com/openshift/cloud-network-config-controller/pkg/signals"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	controllerclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// The name of the configmap used for leader election
	resourceLockName          = "cloud-network-config-controller-lock"
	controllerNameEnvVar      = "CONTROLLER_NAME"
	controllerNamespaceEnvVar = "CONTROLLER_NAMESPACE"
	operatorVersionEnvVar     = "RELEASE_VERSION"
	defaultOperatorVersion    = "0.0.1-snapshot"
	deploymentName            = "cloud-network-config-controller"
	globalInfrastructureName  = "cluster"
)

var (
	kubeConfig          string
	platformCfg         cloudprovider.CloudProviderConfig
	secretName          string
	configName          string
	controllerName      string
	controllerNamespace string
)

func main() {
	// set up wait group used for spawning all our individual controllers
	// on the bottom of this function
	wg := &sync.WaitGroup{}

	// set up a global context used for shutting down the leader election and
	// subsequently all controllers.
	ctx, cancelFunc := context.WithCancel(context.Background())

	// set up signals so we handle the first shutdown signal gracefully
	stopCh := signals.SetupSignalHandler(cancelFunc)

	// Skip passing the master URL, if debugging this controller: provide the
	// kubeconfig to your cluster. In all other cases: clientcmd will just infer
	// the in-cluster config from the environment variables in the pod.
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		klog.Exitf("Error building kubeconfig: %s", err.Error())
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		klog.Exitf("Error building kubernetes clientset: %s", err.Error())
	}

	scheme := runtime.NewScheme()
	// Setup Scheme for all resources
	setupScheme(scheme)

	platformStatus, err := getPlatformStatus(cfg, scheme)
	if err != nil {
		klog.Exitf("Error getting platform status from cluster infrastructure: %s", err.Error())
	}

	rl, err := resourcelock.New(
		resourcelock.LeasesResourceLock,
		controllerNamespace,
		resourceLockName,
		kubeClient.CoreV1(),
		kubeClient.CoordinationV1(),
		resourcelock.ResourceLockConfig{
			Identity: controllerName,
		})
	if err != nil {
		klog.Exitf("Error building resource lock: %s", err.Error())
	}

	// set up leader election, the only reason for this is to make sure we only
	// have one replica of this controller at any given moment in time. On
	// upgrades there could be small windows where one replica of the deployment
	// stops on one node while another starts on another. In such a case we
	// could have both running at the same time. This prevents that from
	// happening and ensures we only have one replica "controlling", always.
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            rl,
		ReleaseOnCancel: true,
		LeaseDuration:   137 * time.Second, // leader election values from https://github.com/openshift/library-go/pull/1104
		RenewDeadline:   107 * time.Second,
		RetryPeriod:     26 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				featureGateAccessor, err := createFeatureGateAccessor(
					ctx,
					cfg,
					os.Getenv(controllerNameEnvVar),
					os.Getenv(controllerNamespaceEnvVar),
					deploymentName,
					getReleaseVersion(),
					stopCh,
				)
				if err != nil {
					klog.Exitf("Error building feature gate accessor: %s", err.Error())
				}

				featureGates, err := awaitEnabledFeatureGates(featureGateAccessor, 1*time.Minute)
				if err != nil {
					klog.Fatalf("Failed to get feature gates: %v", err)
				}

				cloudNetworkClient, err := cloudnetworkclientset.NewForConfig(cfg)
				if err != nil {
					klog.Exitf("Error building cloudnetwork clientset: %s", err.Error())
				}

				cloudProviderClient, err := cloudprovider.NewCloudProviderClient(platformCfg, platformStatus, featureGates)
				if err != nil {
					klog.Fatalf("Error building cloud provider client, err: %v", err)
				}

				kubeInformerFactory := kubeinformers.NewSharedInformerFactoryWithOptions(kubeClient, time.Minute*2, kubeinformers.WithNamespace(controllerNamespace))
				cloudNetworkInformerFactory := cloudnetworkinformers.NewSharedInformerFactory(cloudNetworkClient, time.Minute*2)

				cloudPrivateIPConfigController, err := cloudprivateipconfigcontroller.NewCloudPrivateIPConfigController(
					ctx,
					cloudProviderClient,
					cloudNetworkClient,
					cloudNetworkInformerFactory.Cloud().V1().CloudPrivateIPConfigs(),
					kubeInformerFactory.Core().V1().Nodes(),
					platformCfg,
				)
				if err != nil {
					klog.Fatalf("Error getting cloud private ip controller, err: %v", err)
				}
				nodeController, err := nodecontroller.NewNodeController(
					ctx,
					kubeClient,
					cloudProviderClient,
					kubeInformerFactory.Core().V1().Nodes(),
					cloudNetworkInformerFactory.Cloud().V1().CloudPrivateIPConfigs(),
				)
				if err != nil {
					klog.Fatalf("Error getting node controller, err: %v", err)
				}
				secretController, err := secretcontroller.NewSecretController(
					ctx,
					cancelFunc,
					kubeClient,
					kubeInformerFactory.Core().V1().Secrets(),
					secretName,
					controllerNamespace,
				)
				if err != nil {
					klog.Fatalf("Error getting secret controller, err: %v", err)
				}

				cloudNetworkInformerFactory.Start(stopCh)
				kubeInformerFactory.Start(stopCh)

				wg.Add(1)
				go func() {
					defer wg.Done()
					if err = secretController.Run(stopCh); err != nil {
						klog.Exitf("Error running Secret controller: %s", err.Error())
					}
				}()
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err = cloudPrivateIPConfigController.Run(stopCh); err != nil {
						klog.Exitf("Error running CloudPrivateIPConfig controller: %s", err.Error())
					}
				}()

				// AWS and OpenStack use a configmap "kube-cloud-config" to keep track of additional
				// data such as the ca-bundle.pem. Add a controller that restarts the operator if that configmap
				// changes.
				if configName != "" && ((platformCfg.PlatformType == cloudprovider.PlatformTypeAWS && platformCfg.AWSCAOverride != "") ||
					platformCfg.PlatformType == cloudprovider.PlatformTypeOpenStack) {
					klog.Infof("Starting the ConfigMap operator to monitor '%s'", configName)
					configMapController, err := configmapcontroller.NewConfigMapController(
						ctx,
						cancelFunc,
						kubeClient,
						kubeInformerFactory.Core().V1().ConfigMaps(),
						configName,
						controllerNamespace,
					)
					if err != nil {
						klog.Fatalf("Error getting configmap controller, err: %v", err)
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						if err = configMapController.Run(stopCh); err != nil {
							klog.Exitf("Error running ConfigMap controller: %s", err.Error())
						}
					}()
				}

				wg.Add(1)
				go func() {
					defer wg.Done()
					if err = nodeController.Run(stopCh); err != nil {
						klog.Exitf("Error running Node controller: %s", err.Error())
					}
				}()
			},
			// There are two cases to consider for shutting down our controller.
			//  1. Cloud credential or configmap rotation - which our secret controller
			//     and configmap controller watch for and cancel the global context.
			//     That will trigger an end to the leader election loop and call
			//     OnStoppedLeading which will send a SIGTERM and shut down all controllers.
			//  2. Leader election rotation - which will send a SIGTERM and
			//     shut down all controllers.
			OnStoppedLeading: func() {
				klog.Info("Stopped leading, sending SIGTERM and shutting down controller")
				_ = signals.ShutDown()
				// This only needs to wait if we were ever leader
				wg.Wait()
			},
		},
	})
	klog.Info("Finished executing controlled shutdown")
}

func init() {
	klog.InitFlags(nil)

	// These are arguments for this controller
	flag.StringVar(&secretName, "secret-name", "", "The cloud provider secret name - used for talking to the cloud API.")
	flag.StringVar(&configName, "config-name", "kube-cloud-config", "The cloud provider config name - used for talking to the cloud API.")
	flag.StringVar(&platformCfg.PlatformType, "platform-type", "", "The cloud provider platform type this component is running on.")
	flag.StringVar(&platformCfg.Region, "platform-region", "", "The cloud provider platform region the cluster is deployed in, required for AWS")
	flag.StringVar(&platformCfg.APIOverride, "platform-api-url", "", "The cloud provider API URL to use (instead of whatever default).")
	flag.StringVar(&platformCfg.CredentialDir, "secret-override", "/etc/secret/cloudprovider", "The cloud provider secret location override, useful when running this component locally against a cluster")
	flag.StringVar(&platformCfg.ConfigDir, "config-override", "/kube-cloud-config", "The cloud provider config location override, useful when running this component locally against a cluster")
	flag.StringVar(&platformCfg.AzureEnvironment, "platform-azure-environment", "AzurePublicCloud", "The Azure environment name, used to select API endpoints")
	flag.StringVar(&platformCfg.AWSCAOverride, "platform-aws-ca-override", "", "Path to a separate CA bundle to use when connecting to the AWS API")
	flag.StringVar(&kubeConfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.Parse()

	// Verify required arguments
	if secretName == "" || platformCfg.PlatformType == "" {
		klog.Exit("-secret-name or -platform-type is empty, cannot initialize controller")
	}

	// These are populated by the downward API
	controllerNamespace = os.Getenv(controllerNamespaceEnvVar)
	controllerName = os.Getenv(controllerNameEnvVar)
	if controllerNamespace == "" || controllerName == "" {
		klog.Exitf("Controller ENV variables are empty: %q: %s, %q: %s, cannot initialize controller",
			controllerNamespaceEnvVar, controllerNamespace, controllerNameEnvVar, controllerName)
	}
}

// By default, when the enabled/disabled list of featuregates changes, os.Exit is called.
// See featuregates.NewFeatureGateAccess for more information
func createFeatureGateAccessor(ctx context.Context, cfg *rest.Config, operatorName, namespace, deploymentName, operatorVersion string, stop <-chan struct{}) (featuregates.FeatureGateAccess, error) {
	ctx, cancelFn := context.WithCancel(ctx)
	go func() {
		defer cancelFn()
		<-stop
	}()

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create kube client: %w", err)
	}

	eventRecorder := events.NewKubeRecorder(kubeClient.CoreV1().Events(namespace), operatorName, &corev1.ObjectReference{
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Namespace:  namespace,
		Name:       deploymentName,
	}, clock.RealClock{})

	configClient, err := configclient.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create config client: %w", err)
	}
	configInformers := configinformers.NewSharedInformerFactory(configClient, 10*time.Minute)

	featureGateAccessor := featuregates.NewFeatureGateAccess(
		operatorVersion, defaultOperatorVersion,
		configInformers.Config().V1().ClusterVersions(), configInformers.Config().V1().FeatureGates(),
		eventRecorder,
	)
	go featureGateAccessor.Run(ctx)
	go configInformers.Start(stop)

	return featureGateAccessor, nil
}

func awaitEnabledFeatureGates(accessor featuregates.FeatureGateAccess, timeout time.Duration) (featuregates.FeatureGate, error) {
	select {
	case <-accessor.InitialFeatureGatesObserved():
		featureGates, err := accessor.CurrentFeatureGates()
		if err != nil {
			return nil, err
		} else {
			klog.Infof("FeatureGates initialized: knownFeatureGates=%v", featureGates.KnownFeatures())
			return featureGates, nil
		}
	case <-time.After(timeout):
		return nil, fmt.Errorf("timed out waiting for FeatureGate detection")
	}
}

func getReleaseVersion() string {
	releaseVersion := os.Getenv(operatorVersionEnvVar)
	if len(releaseVersion) == 0 {
		return defaultOperatorVersion
	}
	return releaseVersion
}

func getPlatformStatus(cfg *rest.Config, scheme *runtime.Scheme) (*configv1.PlatformStatus, error) {
	client, err := controllerclient.New(cfg, controllerclient.Options{Scheme: scheme})
	if err != nil {
		klog.Exitf("Error building controller runtime client: %s", err.Error())
	}

	infra := &configv1.Infrastructure{}
	infraName := controllerclient.ObjectKey{Name: globalInfrastructureName}

	if err := client.Get(context.Background(), infraName, infra); err != nil {
		return nil, fmt.Errorf("failed to get infrastructure: %w", err)
	}

	return infra.Status.PlatformStatus, nil
}

// setupScheme serialises the scheme construction.
func setupScheme(scheme *runtime.Scheme) {
	// Setup scheme for all resources
	// Setup Openshift config scheme
	err := configv1.Install(scheme)
	if err != nil {
		klog.Fatalf("failed to install scheme: %v", err)
	}
	// Setup Openshift cloud network scheme
	err = cloudnetworkscheme.AddToScheme(scheme)
	if err != nil {
		klog.Fatalf("failed to add APIs to scheme: %v", err)
	}
}
