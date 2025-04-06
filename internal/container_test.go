package internal

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	metadata "github.com/checkpoint-restore/checkpointctl/lib"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestGetPodmanInfo(t *testing.T) {
	// Test case 1: Valid network info
	specDump := &specs.Spec{
		Annotations: map[string]string{
			"io.container.manager": "libpod",
		},
	}
	
	createdTime, err := time.Parse(time.RFC3339, "2025-04-06T12:00:00Z")
	if err != nil {
		t.Fatalf("Failed to parse time: %v", err)
	}

	containerConfig := &metadata.ContainerConfig{
		Name:        "test-container",
		CreatedTime: createdTime,
	}

	// Create test network.status file
	networkStatus := `{
		"podman": {
			"interfaces": {
				"eth0": {
					"subnets": [{
						"ipnet": "10.88.0.9/16",
						"gateway": "10.88.0.1"
					}],
					"mac_address": "f2:99:8d:fb:5a:57"
				}
			}
		}
	}`

	tmpDir := t.TempDir()
	networkStatusFile := filepath.Join(tmpDir, metadata.NetworkStatusFile)
	if err := os.WriteFile(networkStatusFile, []byte(networkStatus), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	task := Task{
		OutputDir:          tmpDir,
		CheckpointFilePath: "test.tar",
	}

	info := getPodmanInfo(containerConfig, specDump, task)
	if info.Name != "test-container" {
		t.Errorf("Expected name %s, got %s", "test-container", info.Name)
	}
	if info.Engine != "Podman" {
		t.Errorf("Expected engine %s, got %s", "Podman", info.Engine)
	}
	if info.IP != "10.88.0.9/16" {
		t.Errorf("Expected IP %s, got %s", "10.88.0.9/16", info.IP)
	}
	if info.MAC != "f2:99:8d:fb:5a:57" {
		t.Errorf("Expected MAC %s, got %s", "f2:99:8d:fb:5a:57", info.MAC)
	}

	// Test case 2: No network info
	specDumpNoNetwork := &specs.Spec{
		Annotations: map[string]string{},
	}
	infoNoNetwork := getPodmanInfo(containerConfig, specDumpNoNetwork, task)
	if infoNoNetwork.IP != "" || infoNoNetwork.MAC != "" {
		t.Errorf("Expected empty IP and MAC for no network info, got IP=%s, MAC=%s", infoNoNetwork.IP, infoNoNetwork.MAC)
	}
}

func TestGetContainerInfo(t *testing.T) {
	// Test case 1: Podman container
	specDump := &specs.Spec{
		Annotations: map[string]string{
			"io.container.manager": "libpod",
		},
	}

	createdTime, err := time.Parse(time.RFC3339, "2025-04-06T12:00:00Z")
	if err != nil {
		t.Fatalf("Failed to parse time: %v", err)
	}

	containerConfig := &metadata.ContainerConfig{
		Name:        "test-container",
		CreatedTime: createdTime,
	}

	task := Task{
		OutputDir:          t.TempDir(),
		CheckpointFilePath: "test.tar",
	}

	info, err := getContainerInfo(specDump, containerConfig, task)
	if err != nil {
		t.Errorf("getContainerInfo failed: %v", err)
	}
	if info.Name != "test-container" {
		t.Errorf("Expected name %s, got %s", "test-container", info.Name)
	}
	if info.Engine != "Podman" {
		t.Errorf("Expected engine %s, got %s", "Podman", info.Engine)
	}

	// Test case 2: CRI-O container
	specDumpCrio := &specs.Spec{
		Annotations: map[string]string{
			"io.container.manager":        "cri-o",
			"io.kubernetes.cri-o.Name":    "test-crio",
			"io.kubernetes.cri-o.Created": "2025-04-06T12:00:00Z",
		},
	}

	infoCrio, err := getContainerInfo(specDumpCrio, containerConfig, task)
	if err != nil {
		t.Errorf("getContainerInfo failed: %v", err)
	}
	if infoCrio.Engine != "CRI-O" {
		t.Errorf("Expected engine %s, got %s", "CRI-O", infoCrio.Engine)
	}

	// Test case 3: Unknown container type
	specDumpUnknown := &specs.Spec{
		Annotations: map[string]string{
			"io.container.manager": "unknown",
		},
	}

	infoUnknown, err := getContainerInfo(specDumpUnknown, containerConfig, task)
	if err != nil {
		t.Errorf("getContainerInfo failed: %v", err)
	}
	if infoUnknown.Engine != "Containerd" {
		t.Errorf("Expected engine %s, got %s", "Containerd", infoUnknown.Engine)
	}
}