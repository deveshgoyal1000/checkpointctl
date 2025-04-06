package internal

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	metadata "github.com/checkpoint-restore/checkpointctl/lib"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestGetCheckpointAnnotations(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()

	// Create test files
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

	// Write spec.dump
	specFile := filepath.Join(tmpDir, "spec.dump")
	specData, err := json.Marshal(specDump)
	if err != nil {
		t.Fatalf("Failed to marshal spec.dump: %v", err)
	}
	if err := os.WriteFile(specFile, specData, 0644); err != nil {
		t.Fatalf("Failed to write spec.dump: %v", err)
	}

	// Write config.dump
	configFile := filepath.Join(tmpDir, "config.dump")
	configData, err := json.Marshal(containerConfig)
	if err != nil {
		t.Fatalf("Failed to marshal config.dump: %v", err)
	}
	if err := os.WriteFile(configFile, configData, 0644); err != nil {
		t.Fatalf("Failed to write config.dump: %v", err)
	}

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

	// Create test archive
	archivePath := filepath.Join(tmpDir, "checkpoint.tar")
	if err := os.WriteFile(archivePath, []byte("test data"), 0644); err != nil {
		t.Fatalf("Failed to write archive: %v", err)
	}

	// Create ImageBuilder
	ib := NewImageBuilder(archivePath, "test-image:latest")

	// Test getCheckpointAnnotations
	annotations, err := ib.getCheckpointAnnotations()
	if err != nil {
		t.Errorf("getCheckpointAnnotations failed: %v", err)
	}

	// Verify annotations
	if annotations["io.container.manager"] != "libpod" {
		t.Errorf("Expected io.container.manager=libpod, got %s", annotations["io.container.manager"])
	}

	// Test error cases
	// 1. Invalid archive path
	ibInvalid := NewImageBuilder("invalid.tar", "test-image:latest")
	_, err = ibInvalid.getCheckpointAnnotations()
	if err == nil {
		t.Error("Expected error for invalid archive path")
	}

	// 2. Missing spec.dump
	if err := os.Remove(specFile); err != nil {
		t.Fatalf("Failed to remove spec.dump: %v", err)
	}
	_, err = ib.getCheckpointAnnotations()
	if err == nil {
		t.Error("Expected error for missing spec.dump")
	}

	// 3. Missing config.dump
	if err := os.Remove(configFile); err != nil {
		t.Fatalf("Failed to remove config.dump: %v", err)
	}
	_, err = ib.getCheckpointAnnotations()
	if err == nil {
		t.Error("Expected error for missing config.dump")
	}
}

func TestCreateImageFromCheckpoint(t *testing.T) {
	// Create test archive
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "checkpoint.tar")
	if err := os.WriteFile(archivePath, []byte("test data"), 0644); err != nil {
		t.Fatalf("Failed to write archive: %v", err)
	}

	// Create ImageBuilder
	ib := NewImageBuilder(archivePath, "test-image:latest")

	// Test CreateImageFromCheckpoint
	ctx := context.Background()
	err := ib.CreateImageFromCheckpoint(ctx)
	// Since we can't actually run buildah commands in tests,
	// we expect an error about missing buildah
	if err == nil {
		t.Error("Expected error for missing buildah")
	}
}