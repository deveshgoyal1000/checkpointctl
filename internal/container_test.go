package internal

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"
	"time"

	metadata "github.com/checkpoint-restore/checkpointctl/lib"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func TestGetPodmanInfo(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "checkpoint-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test config.dump
	configData := &metadata.ContainerConfig{
		ID:             "test-container-id",
		Name:           "test-container",
		RootfsImageName: "nginx:latest",
		CreatedTime:    time.Now(),
	}

	configPath := filepath.Join(tmpDir, "config.dump")
	if _, err := metadata.WriteJSONFile(configData, configPath, "config.dump"); err != nil {
		t.Fatal(err)
	}

	// Create test spec.dump
	specData := &specs.Spec{
		Annotations: map[string]string{
			"io.container.manager": "libpod",
		},
	}
	specPath := filepath.Join(tmpDir, "spec.dump")
	if _, err := metadata.WriteJSONFile(specData, specPath, "spec.dump"); err != nil {
		t.Fatal(err)
	}

	// Create test checkpoint archive
	archivePath := filepath.Join(tmpDir, "checkpoint.tar")
	if err := createTestArchive(archivePath); err != nil {
		t.Fatal(err)
	}

	// Test getPodmanInfo
	task := Task{
		CheckpointFilePath: archivePath,
		OutputDir:         tmpDir,
		Engine:            "podman",
	}

	info := getPodmanInfo(configData, specData, task)
	if info.Name != "test-container" {
		t.Errorf("Expected Name %s, got %s", "test-container", info.Name)
	}
	if info.Engine != "Podman" {
		t.Errorf("Expected Engine %s, got %s", "Podman", info.Engine)
	}
}

func TestGetContainerdInfo(t *testing.T) {
	// Create test data
	configData := &metadata.ContainerConfig{
		ID:             "test-container-id",
		Name:           "test-container",
		RootfsImageName: "nginx:latest",
		CreatedTime:    time.Now(),
	}

	specData := &specs.Spec{
		Annotations: map[string]string{
			"io.kubernetes.cri.container-name":    "test-container",
			"io.kubernetes.cri.sandbox-namespace": "test-namespace",
			"io.kubernetes.cri.sandbox-name":      "test-pod",
		},
	}

	// Test getContainerdInfo
	info := getContainerdInfo(configData, specData)

	// Verify the parsed information
	if info.Name != "test-container" {
		t.Errorf("Expected Name %s, got %s", "test-container", info.Name)
	}
	if info.Engine != "containerd" {
		t.Errorf("Expected Engine %s, got %s", "containerd", info.Engine)
	}
	if info.Namespace != "test-namespace" {
		t.Errorf("Expected Namespace %s, got %s", "test-namespace", info.Namespace)
	}
	if info.Pod != "test-pod" {
		t.Errorf("Expected Pod %s, got %s", "test-pod", info.Pod)
	}
}

func TestGetCheckpointInfo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "checkpoint-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test files
	configData := &metadata.ContainerConfig{
		ID:             "test-container-id",
		Name:           "test-container",
		RootfsImageName: "nginx:latest",
		CreatedTime:    time.Now(),
	}
	if _, err := metadata.WriteJSONFile(configData, filepath.Join(tmpDir, "config.dump"), "config.dump"); err != nil {
		t.Fatal(err)
	}

	specData := &specs.Spec{
		Annotations: map[string]string{
			"io.container.manager": "libpod",
		},
	}
	if _, err := metadata.WriteJSONFile(specData, filepath.Join(tmpDir, "spec.dump"), "spec.dump"); err != nil {
		t.Fatal(err)
	}

	// Create test checkpoint archive
	archivePath := filepath.Join(tmpDir, "checkpoint.tar")
	if err := createTestArchive(archivePath); err != nil {
		t.Fatal(err)
	}

	// Test with different engine types
	tests := []struct {
		name   string
		engine string
	}{
		{"Podman", "podman"},
		{"Containerd", "containerd"},
		{"CRI-O", "crio"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := Task{
				CheckpointFilePath: archivePath,
				OutputDir:         tmpDir,
				Engine:            tt.engine,
			}
			info, err := getCheckpointInfo(task)
			if err != nil {
				t.Errorf("getCheckpointInfo failed for %s: %v", tt.name, err)
			}
			if info == nil {
				t.Errorf("Expected non-nil info for %s", tt.name)
			}
		})
	}
}

func TestShowContainerCheckpoints(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "checkpoint-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test checkpoint archive
	archivePath := filepath.Join(tmpDir, "checkpoint.tar")
	if err := createTestArchive(archivePath); err != nil {
		t.Fatal(err)
	}

	// Test ShowContainerCheckpoints
	tasks := []Task{
		{
			CheckpointFilePath: archivePath,
			OutputDir:         tmpDir,
			Engine:            "podman",
		},
	}
	err = ShowContainerCheckpoints(tasks)
	if err != nil {
		t.Errorf("ShowContainerCheckpoints failed: %v", err)
	}
}

// Helper function to create test archive
func createTestArchive(path string) error {
	// Create a new tar file
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	tw := tar.NewWriter(file)
	defer tw.Close()

	// Add test files to archive
	files := map[string][]byte{
		"config.dump": []byte(`{"ID": "test-id", "Name": "test-container"}`),
		"spec.dump":   []byte(`{"annotations": {"io.containerd.image.name": "nginx"}}`),
	}

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(content); err != nil {
			return err
		}
	}

	return nil
}