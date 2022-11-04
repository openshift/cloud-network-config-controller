package cloudprivateipconfig

import (
	"errors"
	"net"
	"strings"
)

// IPFamily string representing ip family
type IPFamily string

const (
	// IPv4 IPFamily constant ipv4 family
	IPv4 IPFamily = "ipv4"
	// IPv6 IPFamily constant ipv6 family
	IPv6 IPFamily = "ipv6"
)

// NameToIP converts the resource name to net.IP. Given a
// limitation in the Kubernetes API server (see:
// https://github.com/kubernetes/kubernetes/pull/100950)
// CloudPrivateIPConfig.metadata.name cannot represent an IPv6 address. To
// work-around this limitation it was decided that the network plugin creating
// the CR will fully expand the IPv6 address and replace all colons with dots,
// Example: The IPv6 address fc00:f853:ccd:e793::54 will be represented
// as: fc00.f853.0ccd.e793.0000.0000.0000.0054, We thus need to replace
// every fifth character's dot with a colon.
func NameToIP(name string) (net.IP, IPFamily, error) {
	// handle IPv4: this is enough since it will be serialized just fine
	if ip := net.ParseIP(name); ip != nil {
		return ip, IPv4, nil
	}
	// handle IPv6
	name = strings.ReplaceAll(name, ".", ":")
	if ip := net.ParseIP(name); ip != nil {
		return ip, IPv6, nil
	}
	return nil, "", errors.New("invalid ip family")
}
