package cloudprivateipconfig

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCloudPrivateIPConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Test CloudPrivateIPConfig")
}

var _ = Describe("CloudPrivateIPConfig", func() {
	Context("Validate Name to IP", func() {
		It("With valid names", func() {
			ip, family, err := NameToIP("192.168.0.10")
			Expect(err).To(BeNil())
			Expect(ip.String()).To(Equal(("192.168.0.10")))
			Expect(family).To(Equal(IPv4))
			ip, family, err = NameToIP("fc00.f853.0ccd.e793.0000.0000.0000.0054")
			Expect(err).To(BeNil())
			Expect(ip.String()).To(Equal(("fc00:f853:ccd:e793::54")))
			Expect(family).To(Equal(IPv6))
		})
		It("With invalid name", func() {
			_, _, err := NameToIP("invalid_config")
			Expect(err).NotTo(BeNil())
		})
	})

})
