package cloudprovider

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestSplitGCPNode(t *testing.T) {
	n := corev1.Node{
		Spec: corev1.NodeSpec{
			ProviderID: "gce://openshift-qe/us-central1-a/lwanstsg0118f-tvpsk-master-0",
		},
	}

	project, zone, instance, err := splitGCPNode(&n)
	if err != nil {
		t.Fatal(err)
	}
	if project != "openshift-qe" {
		t.Fatalf("wrong project: %s", project)
	}

	if zone != "us-central1-a" {
		t.Fatalf("wrong zone: %s", zone)
	}

	if instance != "lwanstsg0118f-tvpsk-master-0" {
		t.Fatalf("wrong name: %s", instance)
	}
}

func TestParseSubnet(t *testing.T) {
	subnetURI := "https://www.googleapis.com/compute/v1/projects/openshift-qe-shared-vpc/regions/us-central1/subnetworks/installer-shared-vpc-subnet-2"
	gcp := &GCP{}

	project, region, subnet, err := gcp.parseSubnet(subnetURI)

	if project != "openshift-qe-shared-vpc" {
		t.Fatalf("wrong project: %s", project)
	}
	if region != "us-central1" {
		t.Fatalf("wrong region: %s", region)
	}
	if subnet != "installer-shared-vpc-subnet-2" {
		t.Fatalf("wrong subnet: %s", subnet)
	}
	if err != nil {
		t.Fatalf("did not expect err: %s", err)
	}
}

func newTestGCP(t *testing.T) (*GCP, string) {
	t.Helper()
	dir := t.TempDir()
	g := &GCP{
		CloudProvider: CloudProvider{
			cfg: CloudProviderConfig{CredentialDir: dir},
			ctx: context.Background(),
		},
		nodeLockMap: make(map[string]*sync.Mutex),
	}
	return g, dir
}

func TestReadGCPCredentialsConfig_WIFPresent(t *testing.T) {
	g, dir := newTestGCP(t)
	wifData := `{"type":"external_account","audience":"//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider"}`
	if err := os.WriteFile(filepath.Join(dir, "workload_identity_config.json"), []byte(wifData), 0644); err != nil {
		t.Fatal(err)
	}

	data, err := g.readGCPCredentialsConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != wifData {
		t.Fatalf("expected WIF config, got: %s", string(data))
	}
}

func TestReadGCPCredentialsConfig_SAOnly(t *testing.T) {
	g, dir := newTestGCP(t)
	saData := `{"type":"service_account","project_id":"my-project"}`
	if err := os.WriteFile(filepath.Join(dir, "service_account.json"), []byte(saData), 0644); err != nil {
		t.Fatal(err)
	}

	data, err := g.readGCPCredentialsConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != saData {
		t.Fatalf("expected SA config, got: %s", string(data))
	}
}

func TestReadGCPCredentialsConfig_EnvVarFallback(t *testing.T) {
	g, _ := newTestGCP(t)
	envData := `{"type":"external_account","audience":"test"}`
	tmpFile := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(tmpFile, []byte(envData), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", tmpFile)

	data, err := g.readGCPCredentialsConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != envData {
		t.Fatalf("expected env var config, got: %s", string(data))
	}
}

func TestReadGCPCredentialsConfig_WIFTakesPriority(t *testing.T) {
	g, dir := newTestGCP(t)
	wifData := `{"type":"external_account","audience":"wif"}`
	saData := `{"type":"service_account","project_id":"sa"}`
	if err := os.WriteFile(filepath.Join(dir, "workload_identity_config.json"), []byte(wifData), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "service_account.json"), []byte(saData), 0644); err != nil {
		t.Fatal(err)
	}

	data, err := g.readGCPCredentialsConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != wifData {
		t.Fatalf("expected WIF config to take priority, got: %s", string(data))
	}
}

func TestReadGCPCredentialsConfig_NothingPresent(t *testing.T) {
	g, _ := newTestGCP(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

	_, err := g.readGCPCredentialsConfig()
	if err == nil {
		t.Fatal("expected error when no credentials are present")
	}
	if !strings.Contains(err.Error(), "no valid GCP credentials found") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestReadGCPCredentialsConfig_EnvVarFileMissing(t *testing.T) {
	g, _ := newTestGCP(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent/path/creds.json")

	_, err := g.readGCPCredentialsConfig()
	if err == nil {
		t.Fatal("expected error when GOOGLE_APPLICATION_CREDENTIALS file doesn't exist")
	}
	if !strings.Contains(err.Error(), "failed to read GOOGLE_APPLICATION_CREDENTIALS") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestEnsureUniverseDomain_Injected(t *testing.T) {
	input := []byte(`{"type":"service_account","project_id":"test"}`)

	result, err := ensureUniverseDomain(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resultMap map[string]interface{}
	if err := json.Unmarshal(result, &resultMap); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	if resultMap["universe_domain"] != defaultUniverseDomain {
		t.Fatalf("expected universe_domain %s, got %v", defaultUniverseDomain, resultMap["universe_domain"])
	}
}

func TestEnsureUniverseDomain_Preserved(t *testing.T) {
	customDomain := "custom.googleapis.com"
	input := []byte(`{"type":"service_account","project_id":"test","universe_domain":"` + customDomain + `"}`)

	result, err := ensureUniverseDomain(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resultMap map[string]interface{}
	if err := json.Unmarshal(result, &resultMap); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	if resultMap["universe_domain"] != customDomain {
		t.Fatalf("expected universe_domain %s, got %v", customDomain, resultMap["universe_domain"])
	}
}

func TestEnsureUniverseDomain_InvalidJSON(t *testing.T) {
	input := []byte(`{not valid json`)

	_, err := ensureUniverseDomain(input)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "cannot decode GCP credentials JSON") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestEnsureUniverseDomain_NullJSON(t *testing.T) {
	input := []byte(`null`)

	_, err := ensureUniverseDomain(input)
	if err == nil {
		t.Fatal("expected error for null JSON")
	}
	if !strings.Contains(err.Error(), "top-level JSON object is required") {
		t.Fatalf("unexpected error message: %v", err)
	}
}
