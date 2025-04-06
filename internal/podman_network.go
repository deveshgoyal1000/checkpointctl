package internal

import (
	"encoding/json"
	"fmt"
	"os"
)

// PodmanNetworkStatus represents the network status structure for Podman
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

// NetworkInfo contains network interface details
type NetworkInfo struct {
	IP      string
	MAC     string
	Gateway string
}

// getPodmanNetworkInfo reads and parses the network.status file from a Podman checkpoint
func getPodmanNetworkInfo(networkStatusFile string) ([]NetworkInfo, error) {
	data, err := os.ReadFile(networkStatusFile)
	if err != nil {
		// Return empty slice if file doesn't exist or can't be read
		// This maintains compatibility with containers that don't have network info
		return nil, nil
	}

	var status PodmanNetworkStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("failed to parse network status: %w", err)
	}

	var networks []NetworkInfo
	for _, info := range status.Podman.Interfaces {
		if len(info.Subnets) > 0 {
			networks = append(networks, NetworkInfo{
				IP:      info.Subnets[0].IPNet,
				MAC:     info.MacAddress,
				Gateway: info.Subnets[0].Gateway,
			})
		}
	}

	return networks, nil
}