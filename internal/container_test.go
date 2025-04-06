package internal

import (
	"archive/tar"
	"bytes"
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
		ID:              "test-container-id",
		Name:            "test-container",
		RootfsImageName: "nginx:latest",
		CreatedTime:    time.Now(),
	}

	// Create test spec.dump
	specData := &specs.Spec{
		Annotations: map[string]string{
			"io.container.manager": "libpod",
		},
	}

	// Create test checkpoint archive
	archivePath := filepath.Join(tmpDir, "checkpoint.tar")
	if err := createTestArchiveWithNetwork(archivePath, "10.88.0.39/16", "7a:54:cc:62:e4:e7"); err != nil {
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
	if info.IP != "10.88.0.39/16" {
		t.Errorf("Expected IP %s, got %s", "10.88.0.39/16", info.IP)
	}
	if info.MAC != "7a:54:cc:62:e4:e7" {
		t.Errorf("Expected MAC %s, got %s", "7a:54:cc:62:e4:e7", info.MAC)
	}
}

func TestGetContainerdInfo(t *testing.T) {
	// Create test data
	configData := &metadata.ContainerConfig{
		ID:              "test-container-id",
		Name:            "test-container",
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

	info := getContainerdInfo(configData, specData)
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

func TestGetCRIOInfo(t *testing.T) {
	tests := []struct {
		name      string
		specData  *specs.Spec
		wantErr   bool
		wantName  string
		wantIP    string
		wantPod   string
	}{
		{
			name: "valid metadata",
			specData: &specs.Spec{
				Annotations: map[string]string{
					"io.kubernetes.cri-o.Metadata": `{"name":"test-container"}`,
					"io.kubernetes.cri-o.IP.0":     "10.88.0.39",
					"io.kubernetes.cri-o.Created":  time.Now().Format(time.RFC3339),
					"io.kubernetes.pod.namespace":  "test-namespace",
					"io.kubernetes.pod.name":       "test-pod",
				},
			},
			wantName: "test-container",
			wantIP:   "10.88.0.39",
			wantPod:  "test-pod",
		},
		{
			name: "invalid metadata json",
			specData: &specs.Spec{
				Annotations: map[string]string{
					"io.kubernetes.cri-o.Metadata": "invalid json",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := getCRIOInfo(nil, tt.specData)
			if (err != nil) != tt.wantErr {
				t.Errorf("getCRIOInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if info.Name != tt.wantName {
					t.Errorf("getCRIOInfo() got Name = %v, want %v", info.Name, tt.wantName)
				}
				if info.IP != tt.wantIP {
					t.Errorf("getCRIOInfo() got IP = %v, want %v", info.IP, tt.wantIP)
				}
				if info.Pod != tt.wantPod {
					t.Errorf("getCRIOInfo() got Pod = %v, want %v", info.Pod, tt.wantPod)
				}
			}
		})
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
		ID:              "test-container-id",
		Name:            "test-container",
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

	tests := []struct {
		name    string
		task    Task
		wantErr bool
	}{
		{
			name: "valid checkpoint",
			task: Task{
				CheckpointFilePath: archivePath,
				OutputDir:         tmpDir,
				Engine:            "podman",
			},
			wantErr: false,
		},
		{
			name: "missing config.dump",
			task: Task{
				CheckpointFilePath: archivePath,
				OutputDir:         "/nonexistent",
				Engine:            "podman",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := getCheckpointInfo(tt.task)
			if (err != nil) != tt.wantErr {
				t.Errorf("getCheckpointInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && info == nil {
				t.Error("getCheckpointInfo() returned nil info")
			}
		})
	}
}

func TestGetArchiveSizes(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "archive-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test archive with different file types
	archivePath := filepath.Join(tmpDir, "test.tar")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Add checkpoint files
	files := []struct {
		name string
		size int64
		dir  bool
	}{
		{filepath.Join("checkpoint", "pages-1"), 1024, false},
		{filepath.Join("checkpoint", "amdgpu-pages-1"), 512, false},
		{filepath.Join("checkpoint", "other-file"), 256, false},
		{"rootfs-diff.tar", 2048, false},
		{"some-directory", 0, true},
	}

	for _, f := range files {
		header := &tar.Header{
			Name: f.name,
			Size: f.size,
		}
		if f.dir {
			header.Typeflag = tar.TypeDir
			header.Mode = 0755
		} else {
			header.Typeflag = tar.TypeReg
			header.Mode = 0644
		}

		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if !f.dir {
			if _, err := tw.Write(bytes.Repeat([]byte("x"), int(f.size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	sizes, err := getArchiveSizes(archivePath)
	if err != nil {
		t.Fatalf("getArchiveSizes() error = %v", err)
	}

	if sizes.checkpointSize != 1792 { // 1024 + 512 + 256
		t.Errorf("Expected checkpointSize %d, got %d", 1792, sizes.checkpointSize)
	}
	if sizes.pagesSize != 1024 {
		t.Errorf("Expected pagesSize %d, got %d", 1024, sizes.pagesSize)
	}
	if sizes.amdgpuPagesSize != 512 {
		t.Errorf("Expected amdgpuPagesSize %d, got %d", 512, sizes.amdgpuPagesSize)
	}
	if sizes.rootFsDiffTarSize != 2048 {
		t.Errorf("Expected rootFsDiffTarSize %d, got %d", 2048, sizes.rootFsDiffTarSize)
	}
}

// Helper function to create test archive with network status
func createTestArchiveWithNetwork(path, ip, mac string) error {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	networkStatus := fmt.Sprintf(`{
		"podman": {
			"interfaces": {
				"eth0": {
					"subnets": [
						{
							"ipnet": "%s",
							"gateway": "10.88.0.1"
						}
					],
					"mac_address": "%s"
				}
			}
		}
	}`, ip, mac)

	header := &tar.Header{
		Name: "network.status",
		Mode: 0644,
		Size: int64(len(networkStatus)),
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	if _, err := tw.Write([]byte(networkStatus)); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}

	return os.WriteFile(path, buf.Bytes(), 0644)
}

// Helper function to create test archive
func createTestArchive(path string) error {
	// Create test files
	tmpDir, err := os.MkdirTemp("", "archive-test")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// Create spec.dump
	specData := &specs.Spec{
		Annotations: map[string]string{
			"io.containerd.image.name": "nginx:latest",
		},
	}
	if _, err := metadata.WriteJSONFile(specData, filepath.Join(tmpDir, "spec.dump"), "spec.dump"); err != nil {
		return err
	}

	// Create config.dump
	configData := &metadata.ContainerConfig{
		ID:              "test-id",
		Name:            "test-container",
		RootfsImageName: "nginx:latest",
		CreatedTime:    time.Now(),
	}
	if _, err := metadata.WriteJSONFile(configData, filepath.Join(tmpDir, "config.dump"), "config.dump"); err != nil {
		return err
	}

	// Create tar archive
	if err := os.WriteFile(path, []byte("test archive"), 0644); err != nil {
		return err
	}

	return nil
}