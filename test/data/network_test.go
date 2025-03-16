package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/checkpoint-restore/checkpointctl/internal"
	"github.com/stretchr/testify/assert"
)

func TestPodmanNetworkStatus(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "checkpoint-test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Copy the test network.status file to the temporary directory
	networkStatusData, err := os.ReadFile("data/network.status")
	if err != nil {
		t.Fatalf("Failed to read test network.status file: %v", err)
	}

	err = os.WriteFile(filepath.Join(tempDir, "network.status"), networkStatusData, 0644)
	if err != nil {
		t.Fatalf("Failed to write network.status file: %v", err)
	}

	// Create a container with the temporary directory
	container := &internal.Container{
		Dir: tempDir,
	}

	// Parse the network status
	networkStatus, err := container.ParsePodmanNetworkStatus()
	if err != nil {
		t.Fatalf("Failed to parse network status: %v", err)
	}

	// Assert that the network status was parsed correctly
	assert.NotNil(t, networkStatus, "Network status should not be nil")
	assert.Equal(t, 1, len(networkStatus.Podman.Interfaces), "Should have one interface")
	
	// Check eth0 interface
	eth0, ok := networkStatus.Podman.Interfaces["eth0"]
	assert.True(t, ok, "Should have eth0 interface")
	assert.Equal(t, "f2:99:8d:fb:5a:57", eth0.MAC, "MAC address should match")
	
	// Check subnet
	assert.Equal(t, 1, len(eth0.Subnets), "Should have one subnet")
	assert.Equal(t, "10.88.0.9/16", eth0.Subnets[0].IPNet, "IP should match")
	assert.Equal(t, "10.88.0.1", eth0.Subnets[0].Gateway, "Gateway should match")
}
