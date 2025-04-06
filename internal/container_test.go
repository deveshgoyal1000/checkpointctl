package internal

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"

	"github.com/checkpoint-restore/checkpointctl/lib"
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
	configData := map[string]interface{}{
		"ID":     "test-container-id",
		"Name":   "test-container",
		"Image":  "nginx:latest",
		"Created": "2025-04-06T20:47:07Z",
		"State": map[string]interface{}{
			"Status": "running",
		},
		"NetworkSettings": map[string]interface{}{
			"IPAddress":  "10.88.0.39",
			"MacAddress": "7a:54:cc:62:e4:e7",
		},
	}
	
	configPath := filepath.Join(tmpDir, "config.dump")
	if err := lib.WriteJSONFile(configPath, configData); err != nil {
		t.Fatal(err)
	}

	// Create test spec.dump
	specData := map[string]interface{}{
		"annotations": map[string]string{
			"io.containerd.image.name": "nginx:latest",
		},
	}
	specPath := filepath.Join(tmpDir, "spec.dump")
	if err := lib.WriteJSONFile(specPath, specData); err != nil {
		t.Fatal(err)
	}

	// Test getPodmanInfo
	task := &Task{
		Dir: tmpDir,
	}
	info, err := getPodmanInfo(task)
	if err != nil {
		t.Errorf("getPodmanInfo failed: %v", err)
	}

	// Verify the parsed information
	if info.Config.ID != "test-container-id" {
		t.Errorf("Expected ID %s, got %s", "test-container-id", info.Config.ID)
	}
	if info.Config.Name != "test-container" {
		t.Errorf("Expected Name %s, got %s", "test-container", info.Config.Name)
	}
	if info.Config.Image != "nginx:latest" {
		t.Errorf("Expected Image %s, got %s", "nginx:latest", info.Config.Image)
	}
}

func TestGetContainerdInfo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "checkpoint-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test spec.dump
	specData := map[string]interface{}{
		"annotations": map[string]string{
			"io.containerd.image.name":            "docker.io/library/nginx:latest",
			"io.kubernetes.cri.container-name":    "test-container",
			"io.kubernetes.cri.container-id":      "test-container-id",
		},
	}
	
	specPath := filepath.Join(tmpDir, "spec.dump")
	if err := lib.WriteJSONFile(specPath, specData); err != nil {
		t.Fatal(err)
	}

	// Test getContainerdInfo
	task := &Task{
		Dir: tmpDir,
	}
	info, err := getContainerdInfo(task)
	if err != nil {
		t.Errorf("getContainerdInfo failed: %v", err)
	}

	// Verify the parsed information
	if info.Config.ID != "test-container-id" {
		t.Errorf("Expected ID %s, got %s", "test-container-id", info.Config.ID)
	}
	if info.Config.Name != "test-container" {
		t.Errorf("Expected Name %s, got %s", "test-container", info.Config.Name)
	}
	if info.Config.Image != "docker.io/library/nginx:latest" {
		t.Errorf("Expected Image %s, got %s", "docker.io/library/nginx:latest", info.Config.Image)
	}
}

func TestGetCheckpointInfo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "checkpoint-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test files
	files := []string{
		"config.dump",
		"spec.dump",
		"status",
		"deleted.files",
	}

	for _, f := range files {
		path := filepath.Join(tmpDir, f)
		if err := os.WriteFile(path, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}
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
			task := &Task{
				Dir:    tmpDir,
				Engine: tt.engine,
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
	checkpoints, err := ShowContainerCheckpoints([]string{archivePath})
	if err != nil {
		t.Errorf("ShowContainerCheckpoints failed: %v", err)
	}

	if len(checkpoints) != 1 {
		t.Errorf("Expected 1 checkpoint, got %d", len(checkpoints))
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