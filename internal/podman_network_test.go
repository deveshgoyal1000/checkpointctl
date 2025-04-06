package internal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetPodmanNetworkInfo(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "network-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Test case 1: Valid network status file
	networkStatus := `{
		"podman": {
			"interfaces": {
				"eth0": {
					"subnets": [
						{
							"ipnet": "10.88.0.39/16",
							"gateway": "10.88.0.1"
						}
					],
					"mac_address": "7a:54:cc:62:e4:e7"
				}
			}
		}
	}`

	networkStatusFile := filepath.Join(tmpDir, "network.status")
	if err := os.WriteFile(networkStatusFile, []byte(networkStatus), 0644); err != nil {
		t.Fatal(err)
	}

	ip, mac, err := getPodmanNetworkInfo(networkStatusFile)
	if err != nil {
		t.Errorf("getPodmanNetworkInfo failed: %v", err)
	}
	if ip != "10.88.0.39/16" {
		t.Errorf("Expected IP %s, got %s", "10.88.0.39/16", ip)
	}
	if mac != "7a:54:cc:62:e4:e7" {
		t.Errorf("Expected MAC %s, got %s", "7a:54:cc:62:e4:e7", mac)
	}

	// Test case 2: Invalid JSON file
	invalidJSON := `{invalid json}`
	invalidJSONFile := filepath.Join(tmpDir, "invalid.status")
	if err := os.WriteFile(invalidJSONFile, []byte(invalidJSON), 0644); err != nil {
		t.Fatal(err)
	}

	ip, mac, err = getPodmanNetworkInfo(invalidJSONFile)
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
	if ip != "" || mac != "" {
		t.Errorf("Expected empty IP and MAC for invalid JSON, got IP=%s, MAC=%s", ip, mac)
	}

	// Test case 3: Non-existent file
	nonExistentFile := filepath.Join(tmpDir, "nonexistent.status")
	ip, mac, err = getPodmanNetworkInfo(nonExistentFile)
	if err != nil {
		t.Errorf("Expected no error for non-existent file, got %v", err)
	}
	if ip != "" || mac != "" {
		t.Errorf("Expected empty IP and MAC for non-existent file, got IP=%s, MAC=%s", ip, mac)
	}

	// Test case 4: Empty interfaces
	emptyStatus := `{
		"podman": {
			"interfaces": {}
		}
	}`
	emptyFile := filepath.Join(tmpDir, "empty.status")
	if err := os.WriteFile(emptyFile, []byte(emptyStatus), 0644); err != nil {
		t.Fatal(err)
	}

	ip, mac, err = getPodmanNetworkInfo(emptyFile)
	if err != nil {
		t.Errorf("Expected no error for empty interfaces, got %v", err)
	}
	if ip != "" || mac != "" {
		t.Errorf("Expected empty IP and MAC for empty interfaces, got IP=%s, MAC=%s", ip, mac)
	}

	// Test case 5: Multiple interfaces
	multiStatus := `{
		"podman": {
			"interfaces": {
				"eth0": {
					"subnets": [
						{
							"ipnet": "10.88.0.39/16",
							"gateway": "10.88.0.1"
						}
					],
					"mac_address": "7a:54:cc:62:e4:e7"
				},
				"eth1": {
					"subnets": [
						{
							"ipnet": "192.168.1.100/24",
							"gateway": "192.168.1.1"
						}
					],
					"mac_address": "7a:54:cc:62:e4:e8"
				}
			}
		}
	}`
	multiFile := filepath.Join(tmpDir, "multi.status")
	if err := os.WriteFile(multiFile, []byte(multiStatus), 0644); err != nil {
		t.Fatal(err)
	}

	ip, mac, err = getPodmanNetworkInfo(multiFile)
	if err != nil {
		t.Errorf("Expected no error for multiple interfaces, got %v", err)
	}
	// Should get first interface info
	if ip != "10.88.0.39/16" {
		t.Errorf("Expected IP %s, got %s", "10.88.0.39/16", ip)
	}
	if mac != "7a:54:cc:62:e4:e7" {
		t.Errorf("Expected MAC %s, got %s", "7a:54:cc:62:e4:e7", mac)
	}
}