package internal

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	metadata "github.com/checkpoint-restore/checkpointctl/lib"
	"github.com/opencontainers/runtime-spec/specs-go"
)

type mockImageBuilder struct {
	commands []string
	err      error
}

func (m *mockImageBuilder) runCommand(args ...string) error {
	m.commands = append(m.commands, args...)
	return m.err
}

func TestNewImageBuilder(t *testing.T) {
	builder := NewImageBuilder("buildah", "/tmp")
	if builder == nil {
		t.Error("Expected non-nil ImageBuilder")
	}
}

func TestCreateImageFromCheckpoint(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "checkpoint-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test checkpoint directory
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

	specPath := filepath.Join(checkpointDir, "spec.dump")
	if _, err := metadata.WriteJSONFile(specData, specPath, "spec.dump"); err != nil {
		t.Fatal(err)
	}

	// Create test config.dump
	configData := &metadata.ContainerConfig{
		ID:              "test-container-id",
		Name:            "test-container",
		RootfsImageName: "nginx:latest",
		CreatedTime:     time.Now(),
	}

	configPath := filepath.Join(checkpointDir, "config.dump")
	if _, err := metadata.WriteJSONFile(configData, configPath, "config.dump"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		targetImage string
		wantErr     bool
		mockErr     error
	}{
		{
			name:        "successful build",
			targetImage: "quay.io/test/image:latest",
			wantErr:     false,
			mockErr:     nil,
		},
		{
			name:        "build error",
			targetImage: "quay.io/test/image:latest",
			wantErr:     true,
			mockErr:     os.ErrPermission,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockImageBuilder{
				err: tt.mockErr,
			}

			task := Task{
				CheckpointFilePath: filepath.Join(tmpDir, "checkpoint.tar"),
				OutputDir:         checkpointDir,
			}

			err := BuildImageFromCheckpoint(mock, task, tt.targetImage)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildImageFromCheckpoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify the buildah commands were called correctly
				expectedCommands := []string{
					"buildah", "from", "scratch",
					"buildah", "add",
					"buildah", "config",
					"buildah", "commit",
				}

				for _, cmd := range expectedCommands {
					found := false
					for _, actual := range mock.commands {
						if actual == cmd {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected command %s not found in executed commands", cmd)
					}
				}
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
			"test.annotation.1": "value1",
			"test.annotation.2": "value2",
		},
	}

	specPath := filepath.Join(tmpDir, "spec.dump")
	if _, err := metadata.WriteJSONFile(specData, specPath, "spec.dump"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		dir     string
		want    map[string]string
		wantErr bool
	}{
		{
			name: "valid annotations",
			dir:  tmpDir,
			want: map[string]string{
				"test.annotation.1": "value1",
				"test.annotation.2": "value2",
			},
			wantErr: false,
		},
		{
			name:    "invalid directory",
			dir:     "/nonexistent",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := Task{
				OutputDir: tt.dir,
			}
			got, err := GetCheckpointAnnotations(task)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCheckpointAnnotations() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				for k, v := range tt.want {
					if got[k] != v {
						t.Errorf("GetCheckpointAnnotations() = %v, want %v", got[k], v)
					}
				}
			}
		})
	}
}