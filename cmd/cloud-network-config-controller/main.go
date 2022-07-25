package main

import (
	"context"
	"flag"
	"os"
	"sync"
	"time"

	cloudnetworkclientset "github.com/openshift/client-go/cloudnetwork/clientset/versioned"
	cloudnetworkinformers "github.com/openshift/client-go/cloudnetwork/informers/externalversions"
	cloudprovider "github.com/openshift/cloud-network-config-controller/pkg/cloudprovider"
	cloudprivateipconfigcontroller "github.com/openshift/cloud-network-config-controller/pkg/controller/cloudprivateipconfig"
	configmapcontroller "github.com/openshift/cloud-network-config-controller/pkg/controller/configmap"
	nodecontroller "github.com/openshift/cloud-network-config-controller/pkg/controller/node"
	secretcontroller "github.com/openshift/cloud-network-config-controller/pkg/controller/secret"
	signals "github.com/openshift/cloud-network-config-controller/pkg/signals"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog/v2"
)

const (
	// The name of the configmap used for leader election
	resourceLockName          = "cloud-network-config-controller-lock"
	controllerNameEnvVar      = "CONTROLLER_NAME"
	controllerNamespaceEnvVar = "CONTROLLER_NAMESPACE"
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

	rl, err := resourcelock.New(
		resourcelock.ConfigMapsLeasesResourceLock,
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
				cloudNetworkClient, err := cloudnetworkclientset.NewForConfig(cfg)
				if err != nil {
					klog.Exitf("Error building cloudnetwork clientset: %s", err.Error())
				}

				cloudProviderClient, err := cloudprovider.NewCloudProviderClient(platformCfg)
				if err != nil {
					klog.Fatalf("Error building cloud provider client, err: %v", err)
				}

				kubeInformerFactory := kubeinformers.NewSharedInformerFactoryWithOptions(kubeClient, time.Minute*2, kubeinformers.WithNamespace(controllerNamespace))
				cloudNetworkInformerFactory := cloudnetworkinformers.NewSharedInformerFactory(cloudNetworkClient, time.Minute*2)

				cloudPrivateIPConfigController := cloudprivateipconfigcontroller.NewCloudPrivateIPConfigController(
					ctx,
					cloudProviderClient,
					cloudNetworkClient,
					cloudNetworkInformerFactory.Cloud().V1().CloudPrivateIPConfigs(),
					kubeInformerFactory.Core().V1().Nodes(),
				)
				nodeController := nodecontroller.NewNodeController(
					ctx,
					kubeClient,
					cloudProviderClient,
					kubeInformerFactory.Core().V1().Nodes(),
				)
				secretController := secretcontroller.NewSecretController(
					ctx,
					cancelFunc,
					kubeClient,
					kubeInformerFactory.Core().V1().Secrets(),
					secretName,
					controllerNamespace,
				)

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
				wg.Add(1)

				// AWS and OpenStack use a configmap "kube-cloud-config" to keep track of additional
				// data such as the ca-bundle.pem. Add a controller that restarts the operator if that configmap
				// changes.
				if configName != "" && ((platformCfg.PlatformType == cloudprovider.PlatformTypeAWS && platformCfg.AWSCAOverride != "") ||
					platformCfg.PlatformType == cloudprovider.PlatformTypeOpenStack) {
					klog.Infof("Starting the ConfigMap operator to monitor '%s'", configName)
					configMapController := configmapcontroller.NewConfigMapController(
						ctx,
						cancelFunc,
						kubeClient,
						kubeInformerFactory.Core().V1().ConfigMaps(),
						configName,
						controllerNamespace,
					)
					wg.Add(1)
					go func() {
						defer wg.Done()
						if err = configMapController.Run(stopCh); err != nil {
							klog.Exitf("Error running ConfigMap controller: %s", err.Error())
						}
					}()
				}

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
				signals.ShutDown()
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
		klog.Exit("Controller ENV variables are empty: %q: %s, %q: %s, cannot initialize controller", controllerNamespaceEnvVar, controllerNamespace, controllerNameEnvVar, controllerName)
	}
}
