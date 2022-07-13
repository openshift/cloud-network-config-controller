# Cloud-network-config-controller [CNCC]

The CNCC is a controller/operator which interfaces with the cloud API endpoints
to execute and perform the set up required on behalf of the user creating /
updating / deleting the CRs this controller manages. The user in the OpenShift
use-case are the network plugins (openshift-sdn / OVN-Kubernetes) which
interface with this component using its CRDs. Currently, this is only
`cloud.network.openshift.io/cloudprivateipconfigs` which adds / removes private
IP addresses to VM instances associated with Kubernetes nodes.  

# CloudPrivateIPConfig

A CR for this looks like:

```
apiVersion: cloud.network.openshift.io/v1
kind: CloudPrivateIPConfig
metadata:
  name: 192.168.126.11
spec:
  node: nodeX
  status:
    node: nodeX
    conditions:
    - message: ""
      reason: ""
      status: "True|False|Unknown"
      type: Assigned
```

The name of the CR represent the IP address which is to be assigned / removed.
Due to a limitation in the Kube API-server, CR names need to be [RFC 1123
compliant](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names)
which means that IPv6 addresses can't just be written as-is. The format this
controller thus expects for IPv6 names are a fully expanded IP addresses with
colons replaced by dots, ex: `fc00:f853:ccd:e793::54` ->
`fc00.f853.0ccd.e793.0000.0000.0000.0054`. Any controller interfacing with this
controller for IPv6 assignments must thus be capable of performing a
bi-directional conversion to and from that format.

Any assignment of an IP adress should only be considered successful when
`.spec.node == .status.node` and `.status.conditions[0].status == True`, this
applies to creation / updates of CRs.

This controller utilizes a finalizer which it sets on any CR which is created.
The reason for doing so is to prevent an instance from being removed from the
API until this controller has reacted, i.e: making sure that even if a delete is
performed while our controller is not running: nothing actually gets deleted and
we don't loose out on the event.

The control loop for this controller perform atomic add/deletes. This is to say
that for an update there will be two syncs performed and two updates occuring:
one removal of the IP address from the current node, upon which the CR is
updated, and then a second add to the new node, upon which the CR is updated
again.  

# Credentials 

This controller requires credentials to be able to talk to the cloud API. The
format for these credentials depend on the cloud and mode of deployment. The
controller accepts an argument `-secret-name` which is to be placed in the
namespace this controller is running in. The controller figures out what that
namespace is using the environment variable `CONTROLLER_NAMESPACE` which can be
passed to it through the deployment stanza and using the downward-API. The
controller will then start watching for secret data change as to get notified of
credential rotation, upon which it exits and forces a restart of the pod. The
secret also needs to be mounted for this controller to read at start-up, this
location is by default: `/etc/secret/cloudprovider` but can be specified and
overridden using the argument `-secret-override`.

The credentials are expected to look like the following (for vanilla Kubernetes
clusters).

## GCP

```
tree /etc/secret/cloudprovider
└── service_account.json
```

or as a Kubernetes secret defined as:

```
apiVersion: v1
data:
  service_account.json: ewogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIsCiAgInByb2nmxSOIJSdijdplY3RfaWQiOiAib3BlbnNoaWZ0LWdjZS1kZXZlbC1jaSIsCiAgInByaXZhdGVfa2V5X2lkIjogImZkMjYzMTMxMjU0M2U5ZWYxMDhkY2JlODUwZGI3N2E4MDc2YWE2ZTMiLAogICJwcml2YXRlX2tleSI6ICItLS0tLUJFR0lOIFBSSVZBVEUgS0VZLS0tLS1cbk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRRGFXRktDZzV0Vm9OVjZcbkNKSVRVWW1maENzenhoVHNmS1c5Q0lMdUZ2NHBuVTlPc1JoNG5wSmNDQmk1NkhqOWtBdHRiR3E3ME1XTGhudmtcbjFJR0p0R3RQQ0pXbE0ybW9VSHN2L2h5WXh2NjczYlhTa00vYm9kRmZBVWpIcGhjUTRHY1ZwdkdndE5TRXNhU1FcbmpGWXNad3orZVRZTWtRcHN5RXdMUk5YSnRER05YZllmRGNDL2ZsNEcvUExsdElNd0JuSUFLQTZJT3JXTmdiOW9cbmppYzJVc09mT3B4T1huOFo1OHFKcTczZkNoYVd0VHZYRTIrUXM0VUhDQXIxZHFSckNrdVVqRndBTkZPS0JZdHVcbmJMU2d4NUFwWkNkUGY5cGFwSlVSU2lwSkVKa2w5VnNGTDgwZG9zV21WWi9TSWdFbzVaTW1DYVdrUFNQN2ZTdXBcbnVuMWVOVTdIQWdNQkFBRUNnZ0VBVEFFa3I1UijdijdidjidijdGFWWU5IN0ZQaGJXSWJzdkJTRFpLdEkrajcxSUtLK1EvOTUwU0Fcbkg5ZGJ1bGtRZjRLK0FMRGd0UHNZVHozSEpadTF1Q3pYSWIrclcrRDIzYXNTVkZCQ1Bqbk50OVlQNUVxWXo1S01cbndVQnhhblc0cVFhTWJCcnZ1b3N5dHdIRzZIY3A1d3JqU3dIZTJWUUIzTzhhbG1OQ3FyMUtZejNSNFlXZEhpVHJcbkUxZ1VEN1dOVldQQmFrN3J6VGZnL2V6Mkl0c21Vb0wwWi9SWGg1dGM0YlFxTzE1SHRyeVd3Vmsrc2JGWS9ZY3Bcbm5hY0RSL2JFOGZXWjE1YXRuZGJwVFJ2TVhkaUNoSDQ3WTJMSlA4RDFTUGk1Ynh0VXhyTjRiUjFscUptWDZ5TGdcbm5qb2lUTjZnRjZFZW41d0dYV2tUeE1lZ2tleDd5UnUrVUtBdTl1U3FrUUtCZ1FEOVVNS3EzWUdTMFltNmlKQ0JcbmRnaXdGalFiK3R3ODNhcHhBOWNWUVBDMXlzdUoxdjVCTWw3WXVIRkw4TVlBbSswR1NNL0JmK3BsVndJNnFSMVRcbmJEdEdHL1JBUFY1VDlYM2hDdGIwczhpOVo5MHdTbkYxQVI5Y3Jvb1NvVTZTa08xUUxkUTg3R3VPNHlWL0R3ckNcbmZZZkxNbmdLamxHZWdTUzFKbDU3SS83a21RS0JnUURjcUxBUWs4bTVOYnJJY0NzNGxuU3VzWDlKU1Z6TUlwRjhcblpGNjlLd3ZYK2V6S0RBQlJheklHK0ltdVNCVnc0R1h3ZlFnMHNUWEl4SDhDaS9oTmYrV1pDU3hPeDE3eGpaWW5cbmNwWWM1d2pNaEhzd1Y0bkVyV3dNY2tLODFwM2x0NGQwdWs2N0lGYlFoN2pUMmczbHZuWHRseTBpWGkvZFdTSjdcbllSSlU4UVNLWHdLQmdRRGFIV1hoRmVWeDg3Wnh4UkVZUi9mbkZ0YzdtRjkya1M4bkxMVlArYURLQjVvR1QvYVJcblVMdldROHBhSnpGMmFNeEljdjFna2JIVUhIMHc0Vmo4OGQ1LzJhWVFna2JzYUI5QlhNSUY1Wi9kWnNkUHcybTVcbjQ0T0xuRVlMRUpYRkljRVZIc0QyekdNNG4yRXo3RkhKY2FreFQzMkpLVTRoK3ZVT2ZjRXdxcWZaVVFLQmdGL1dcbkpDSVBEaDRTNS8wR09yOXBHV1NHVXZKUm1xeE9sMEdmbGtZeTNBSUIyb1lta0R6TWdmM2xGR2ROaDRKdTg5ZHZcbmRwRHNKcC84TisyelBUVHJ4NXlnRDA1bjZTU2dpZ2E0RGRxZnZZS1dSNnJIV2w3QnM1djBSR2dnRHBRbkVmM3dcbnJTRTQrbnUzZHQ4TVpkelN6QVZWRTVWSnN5QkFCbW52enpaMU43T2hBb0dBYzZrWGhRZ3dYbFl4SHBFTEw2cEZcbjRBV0J5VExSbWFIdGNaa1J3ZmJpc0JxNjhOMnpIbUZwMlAyb3JHSW0wSUVhVFJOT2lHM2xQSU8zb09zL200MDBcbjNpSEVhU1pwN2dLWndRUCtzSDYrdyt5K1FoaUwwQ2JlV25ud1YzYkJKN2RTMUxvT1krb0luY2RyZHVVaTY5YUNcblZHM1RJMHZpWW1MU1VPdUFkVURVeHMwPVxuLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLVxuIiwKICAiY2xpZW50X2VtYWlsIjogImNpLWxuLTVoeGswMC1vcGVuc2hpZnQtYy12dHEyN0BvcGVuc2hpZnQtZ2NlLWRldmVsLWNpLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwKICAiY2xpZW50X2lkIjogIjEwMDQyMDc0OTQyMzgyMjY0NjI3MiIsCiAgImF1dGhfdXJpIjogImh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL29hdXRoMi9hdXRoIiwKICAidG9rZW5fdXJpIjogImh0dHBzOi8vb2F1dGgyLmdvb2dsZWFwaXMuY29tL3Rva2VuIiwKICAiYXV0aF9wcm92aWRlcl94NTA5X2NlcnRfdXJsIjogImh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL29hdXRoMi92MS9jZXJ0cyIsCiAgImNsaWVudF94NTA5X2NlcnRfdXJsIjogImh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL3JvYm90L3YxL21ldGFkYXRhL3g1MDkvY2ktbG4tNWh4azAwLW9wZW5zaGlmdC1jLXZ0cTI3JTQwb3BlbnNoaWZ0LWdjZS1kZXZlbC1jaS5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSIKfQo=
kind: Secret
metadata:
  name: cloud-credentials
  namespace: openshift-cloud-network-config-controller
type: Opaque
```

## AWS

### Secret

```
tree /etc/secret/cloudprovider
├── aws_access_key_id 
└── aws_secret_access_key
```

or as a Kubernetes secret defined as:

```
apiVersion: v1
data:
  aws_access_key_id: QUtJQVdXT1NCDIAaiaNVhGREJRRVA0N04=
  aws_secret_access_key: MG0rV05WMASOKSo2VCdmR1RG9mV1pIcDh4bWJDinsaSSAbXWEx1bHQzekhJU2Jud1UyMw==
kind: Secret
metadata:
  name: cloud-credentials
  namespace: openshift-cloud-network-config-controller
type: Opaque
```

### ConfigMap

If `-platform-aws-ca-override=<file name>` is set then the CNCC expects to find
a valid CA certificate chain at that location. This CA certificate chain will be
used when talking to the AWS API.
The Cluster Network Operator will create a ConfigMap named `kube-cloud-config`
inside the CNCC's namespace and will mount this ConfigMap at location `/kube-cloud-config`.
It will then set `-platform-aws-ca-override=/kube-cloud-config/ca-bundle.pem`.
Additionally, if parameter `-config-name=<name of ConfigMap>` is set then the CNCC
will start monitoring that ConfigMap for update or delete operations. If such
an event gets triggered, the process will gracefully shutdown. Kubernetes will
subsequently restart the container, thus spawning a process with updated configuration.
The default value for `-config-name` is `kube-cloud-config`.

```
tree /kube-cloud-config
└── ca-bundle.pem
```

Or as a Kubernetes ConfigMap defined as:

```
apiVersion: v1
data:
  ca-bundle.pem: <data>
kind: ConfigMap
metadata:
  name: kube-cloud-config
  namespace: openshift-cloud-network-config-controller
```

## Azure

```
tree /etc/secret/cloudprovider
├── azure_client_id 
├── azure_client_secret 
├── azure_region 
├── azure_resource_prefix 
├── azure_resourcegroup 
├── azure_subscription_id 
└── azure_tenant_id
```

or as a Kubernetes secret defined as:

```
apiVersion: v1
data:
  azure_client_id: NGYwM2JjYWItN2I2My00SSoaNjE3LTk2NDEtMGUyZWViOWNjNWVi
  azure_client_secret: aEs3TVUzMaiajiDD2tfXy0uVGNYaDU1LVpOcm5FMHMtUndpskD4ueFBvQg==
  azure_region: ZWFzdHVz
  azure_resource_prefix: Y2ktbG4tNnNqMzMydCs0xZDA5ZC1kZHE2Mg==
  azure_resourcegroup: Y2ktbG4tNnNqMzMydC0xZDA5ZC1kZHE2Mi1yZw==
  azure_subscription_id: ZDM4ZjFlMzgsokPSAAHUDH
  azure_tenant_id: NjA0DSJAaN2M3ZTktYjJhZsokAOKADH
kind: Secret
metadata:
  name: cloud-credentials
  namespace: openshift-cloud-network-config-controller
type: Opaque
```

## OpenStack

### Secret

```
tree /etc/secret/cloudprovider
└── cloud.yaml
```

or as a Kubernetes secret defined as:

```
apiVersion: v1
data:
  clouds.yaml: <base64 string>
kind: Secret
metadata:
  name: cloud-credentials
  namespace: cloud-network-config-controller
type: Opaque
```
### ConfigMap

The Cluster Network Operator will create a ConfigMap named `kube-cloud-config`
inside the CNCC's namespace and will mount this ConfigMap at location `/kube-cloud-config`.
The CNCC will look for a file at location `/kube-cloud-config/ca-bundle.pem`. If the
content of that file is != "", then the operator will assume that this is a valid CA chain
and will use this data when talking to the OpenStack API.
If parameter `-config-name=<name of ConfigMap>` is set to anything other than "",
then the CNCC will start monitoring that ConfigMap for update or delete operations. If
such an event gets triggered, the process will gracefully shutdown. Kubernetes will
subsequently restart the container, thus spawning a process with updated configuration.
The default value for `-config-name` is `kube-cloud-config`.

```
tree /kube-cloud-config
└── ca-bundle.pem
```

Or as a Kubernetes ConfigMap defined as:

```
apiVersion: v1
data:
  ca-bundle.pem: <data>
kind: ConfigMap
metadata:
  name: kube-cloud-config
  namespace: openshift-cloud-network-config-controller
```

# Attributes affecting assignments - subnets / capacity / NICs

Assigning private IP addresses to instances on the cloud comes with some
limitations.

## Subnets

An IP address can only be assigned to subnets which can host it. In the cloud
subnets vary depending on the availability zone a instances is located in. This
controller thus also retrieves the subnet information from the cloud API and
annotates the node object with it, see below for what this annotation looks
like.

## Capacity

Clouds limit the amount of private IP addresses which can be associated with
instances. Some have a variable capacity per instance type and IP family (AWS)
others have a global and fix capacity defined (GCP/Azure). This controller *does
not* validate that if capacity is superseded or not, it is up to the client
controller to initialize its state and track how many assignments are still
possible.

# NICs

Any CloudPrivateIPConfig currently is only added to the instances' first NIC in
the order specified by the cloud. On Azure the notion of a "primary" instance
exists, and is hence used, even if that NIC might not be defined first. As to
account for future work where IP addresses might be assigned to other NICs
besides the first one, the annotation reports an array of
interface/subnet/capacity. For now this array is always of length 1, with the
first/"primary" interface.

All of these attributes are placed on the node object as an annotation, which
looks like:

```
cloud.network.openshift.io/egress-ipconfig: [{"interface": "$IFNAME/$IFID", "ifaddr": {"ipv4": "$IPv4_ADDRESS/$IPv4_SUBNET_MASK", "ipv6": "$IPv6_ADDRESS/$IPv6_SUBNET_MASK"}, "capacity": {"ip": "$IPv4_AND_IPv6_CAPACITY"}}]
```

if the capacity is IP family agnostic. If that is not the case, the annotation
will look like:

```
cloud.network.openshift.io/egress-ipconfig: [{"interface": "$IFNAME/$IFID", "ifaddr": {"ipv4": "$IPv4_ADDRESS/$IPv4_SUBNET_MASK", "ipv6": "$IPv6_ADDRESS/$IPv6_SUBNET_MASK"}, "capacity": {"ipv4": "$IPv4_CAPACITY", "ipv6": "$IPv6_CAPACITY"}}]
```

# How to hack/debug

When you want to debug this component, use one of the following methods.

## Run locally

If you want to run the operator directly on your computer, you can
run the `./hack/run-locally.sh`, but make sure you have a `KUBECONFIG`
initialized in your environment variables. If running against an OpenShift
cluster: the credentials will be copied locally to your computer. That being
said, you probably won't be able to talk to the cloud API endpoints from your
local development environment, so you might need to comment out code which is
non-essential to your testing.

## Patch the operator to run from a new image

If you have issues talking directly to the cloud API endpoints or if you want
to test how the operator runs inside the actual container, use this method.

Set up your own publicly accessible repository. For example, use a quay repository:
~~~
export CNCC_REPOSITORY="quay.io/akaris/cloud-network-config-controller"
~~~

If you prefer using docker instead of podman, run:
~~~
export CONTAINER_ENGINE="docker"
~~~

Run:
~~~
hack/run_in_cloud.sh
~~~

This will then build the container from the Dockerfile, tag the image as `${CNCC_REPOSITORY}:${UUID}`
where `${UUID}` is a unique ID, push the image to the registry and patch the clusterversion operator
and the network-operator so that this new image will be used.

In order to rollback, run `oc edit clusterversion version` and remove the configuration in
`/spec/overrides`. The clusterversion operator should then bring the cluster back to its
original state.

> Note: If the cloud-network-config-controller pod runs into authentication problems after using this method, it may be necessary to delete the pod manually to "kick" it.
