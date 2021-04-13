module github.com/openshift/cloud-network-config-controller

go 1.16

require (
	github.com/Azure/azure-sdk-for-go v53.1.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.17
	github.com/Azure/go-autorest/autorest/adal v0.9.11
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.1 // indirect
	github.com/openshift/api v0.0.0-20210423140644-156ca80f8d83
	github.com/openshift/client-go v0.0.0-20210503124028-ac0910aac9fa
	k8s.io/api v0.21.0-rc.0
	k8s.io/apimachinery v0.21.0
	k8s.io/client-go v0.21.0-rc.0
	k8s.io/klog/v2 v2.8.0
	k8s.io/utils v0.0.0-20210305010621-2afb4311ab10
	sigs.k8s.io/controller-runtime v0.8.3
)
