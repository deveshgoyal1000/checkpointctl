// network.go
package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	metadata "github.com/checkpoint-restore/checkpointctl/lib"
)

// PodmanNetworkStatus represents the structure of the network.status file in Podman checkpoints
type PodmanNetworkStatus struct {
	Podman struct {
		Interfaces map[string]struct {
			Subnets []struct {
				IPNet   string `json:"ipnet"`
				Gateway string `json:"gateway"`
			} `json:"subnets"`
			MacAddress string `json:"mac_address"`
		} `json:"interfaces"`
	} `json:"podman"`
}

// ReadPodmanNetworkStatus reads and parses the network.status file from a Podman checkpoint
func ReadPodmanNetworkStatus(checkpointDirectory string) (*PodmanNetworkStatus, error) {
	networkStatusFile := filepath.Join(checkpointDirectory, metadata.NetworkStatusFile)
	
	// Check if the file exists
	if _, err := os.Stat(networkStatusFile); os.IsNotExist(err) {
		return nil, nil // Network status file does not exist, return nil
	}
	
	content, err := os.ReadFile(networkStatusFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read network status file: %w", err)
	}
	
	var networkStatus PodmanNetworkStatus
	if err := json.Unmarshal(content, &networkStatus); err != nil {
		return nil, fmt.Errorf("failed to unmarshal network status: %w", err)
	}
	
	return &networkStatus, nil
}

// GetPodmanNetworkInfo extracts IP and MAC address information from the network.status file
func GetPodmanNetworkInfo(checkpointDirectory string) (string, string, error) {
	networkStatus, err := ReadPodmanNetworkStatus(checkpointDirectory)
	if err != nil {
		return "", "", err
	}
	
	// If network status is nil, return empty strings
	if networkStatus == nil {
		return "", "", nil
	}
	
	// Default to empty strings
	var ip, mac string
	
	// We'll take the first interface we find (typically "eth0")
	for _, iface := range networkStatus.Podman.Interfaces {
		mac = iface.MacAddress
		// Take the first subnet's IP address
		if len(iface.Subnets) > 0 {
			ip = iface.Subnets[0].IPNet
		}
		break // Just take the first interface
	}
	
	return ip, mac, nil
}
