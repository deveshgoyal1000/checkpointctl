package internal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	metadata "github.com/checkpoint-restore/checkpointctl/lib"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func setupNetworkTest(t *testing.T) (string, string) {
	tmpDir := t.TempDir()

	// Create network.status file
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
	networkStatusFile := filepath.Join(tmpDir, metadata.NetworkStatusFile)
	if err := os.WriteFile(networkStatusFile, []byte(networkStatus), 0644); err != nil {
		t.Fatalf("Failed to write network.status: %v", err)
	}

	// Create checkpoint archive with network.status
	archivePath := filepath.Join(tmpDir, "checkpoint.tar")
	if err := os.WriteFile(archivePath, []byte(networkStatus), 0644); err != nil {
		t.Fatalf("Failed to write archive: %v", err)
	}

	return tmpDir, archivePath
}

func TestGetPodmanInfo(t *testing.T) {
	tmpDir, archivePath := setupNetworkTest(t)

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
		OutputDir:          tmpDir,
		CheckpointFilePath: archivePath,
	}

	// Extract network.status to the output directory
	if err := UntarFiles(archivePath, tmpDir, []string{metadata.NetworkStatusFile}); err != nil {
		t.Fatalf("Failed to extract network.status: %v", err)
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

type crioMetadata struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
}

func TestGetContainerInfo(t *testing.T) {
	tmpDir, archivePath := setupNetworkTest(t)

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
		OutputDir:          tmpDir,
		CheckpointFilePath: archivePath,
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
	metadata := crioMetadata{
		Name:    "test-crio",
		Created: createdTime,
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Failed to marshal metadata: %v", err)
	}

	specDumpCrio := &specs.Spec{
		Annotations: map[string]string{
			"io.container.manager":        "cri-o",
			"io.kubernetes.cri-o.Metadata": string(metadataJSON),
		},
	}

	infoCrio, err := getContainerInfo(specDumpCrio, containerConfig, task)
	if err != nil {
		t.Errorf("getContainerInfo failed: %v", err)
	}
	if infoCrio.Engine != "CRI-O" {
		t.Errorf("Expected engine %s, got %s", "CRI-O", infoCrio.Engine)
	}
	if infoCrio.Name != "test-crio" {
		t.Errorf("Expected name %s, got %s", "test-crio", infoCrio.Name)
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
	if infoUnknown.Engine != "containerd" {
		t.Errorf("Expected engine %s, got %s", "containerd", infoUnknown.Engine)
	}
}