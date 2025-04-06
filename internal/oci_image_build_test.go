package internal

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	metadata "github.com/checkpoint-restore/checkpointctl/lib"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// Mock exec.Command
func mockExecCommand(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

// TestHelperProcess isn't a real test. It's used to mock exec.Command
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "No command\n")
		os.Exit(2)
	}

	cmd, args := args[0], args[1:]
	switch cmd {
	case "buildah":
		if len(args) > 0 && args[0] == "from" {
			fmt.Println("test-container")
			os.Exit(0)
		}
		if len(args) > 0 && args[0] == "add" {
			os.Exit(0)
		}
		if len(args) > 0 && args[0] == "config" {
			os.Exit(0)
		}
		if len(args) > 0 && args[0] == "commit" {
			os.Exit(0)
		}
		if len(args) > 0 && args[0] == "rm" {
			os.Exit(0)
		}
	}
	os.Exit(1)
}

func TestNewImageBuilder(t *testing.T) {
	builder := NewImageBuilder("test-image", "/tmp/checkpoint.tar")
	if builder == nil {
		t.Error("Expected non-nil ImageBuilder")
	}
	if builder.imageName != "test-image" {
		t.Errorf("Expected imageName %s, got %s", "test-image", builder.imageName)
	}
	if builder.checkpointPath != "/tmp/checkpoint.tar" {
		t.Errorf("Expected checkpointPath %s, got %s", "/tmp/checkpoint.tar", builder.checkpointPath)
	}
}

func TestCreateImageFromCheckpoint(t *testing.T) {
	// Save current exec.Command and restore after test
	execCommand := exec.Command
	defer func() { exec.Command = execCommand }()
	exec.Command = mockExecCommand

	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "checkpoint-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test checkpoint directory and files
	checkpointDir := filepath.Join(tmpDir, "checkpoint")
	if err := os.MkdirAll(checkpointDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create test spec.dump with annotations
	specData := &specs.Spec{
		Annotations: map[string]string{
			"io.containerd.image.name":         "docker.io/library/nginx:latest",
			"io.kubernetes.cri.sandbox-name":   "test-pod",
			"io.kubernetes.cri.sandbox-id":     "test-pod-id",
			"io.kubernetes.cri.container-type": "container",
		},
	}
	if _, err := metadata.WriteJSONFile(specData, filepath.Join(checkpointDir, "spec.dump"), "spec.dump"); err != nil {
		t.Fatal(err)
	}

	// Create test config.dump
	configData := &metadata.ContainerConfig{
		ID:              "test-container-id",
		Name:            "test-container",
		RootfsImageName: "nginx:latest",
		CreatedTime:     time.Now(),
	}
	if _, err := metadata.WriteJSONFile(configData, filepath.Join(checkpointDir, "config.dump"), "config.dump"); err != nil {
		t.Fatal(err)
	}

	// Create test archive
	archivePath := filepath.Join(tmpDir, "checkpoint.tar")
	if err := createTestArchive(archivePath); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		targetImage string
		wantErr     bool
	}{
		{
			name:        "successful build",
			targetImage: "quay.io/test/image:latest",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewImageBuilder(tt.targetImage, archivePath)
			err := builder.CreateImageFromCheckpoint(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateImageFromCheckpoint() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetCheckpointAnnotations(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "checkpoint-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test spec.dump with annotations
	specData := &specs.Spec{
		Annotations: map[string]string{
			"io.containerd.image.name":         "docker.io/library/nginx:latest",
			"io.kubernetes.cri.sandbox-name":   "test-pod",
			"io.kubernetes.cri.sandbox-id":     "test-pod-id",
			"io.kubernetes.cri.container-type": "container",
		},
	}
	if _, err := metadata.WriteJSONFile(specData, filepath.Join(tmpDir, "spec.dump"), "spec.dump"); err != nil {
		t.Fatal(err)
	}

	// Create test config.dump
	configData := &metadata.ContainerConfig{
		ID:              "test-container-id",
		Name:            "test-container",
		RootfsImageName: "nginx:latest",
		CreatedTime:     time.Now(),
	}
	if _, err := metadata.WriteJSONFile(configData, filepath.Join(tmpDir, "config.dump"), "config.dump"); err != nil {
		t.Fatal(err)
	}

	// Create test archive
	archivePath := filepath.Join(tmpDir, "checkpoint.tar")
	if err := createTestArchive(archivePath); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid checkpoint",
			path:    archivePath,
			wantErr: false,
		},
		{
			name:    "invalid path",
			path:    "/nonexistent/path",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewImageBuilder("test-image", tt.path)
			annotations, err := builder.getCheckpointAnnotations()
			if (err != nil) != tt.wantErr {
				t.Errorf("getCheckpointAnnotations() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(annotations) == 0 {
				t.Error("Expected non-empty annotations")
			}
		})
	}
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
		CreatedTime:     time.Now(),
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