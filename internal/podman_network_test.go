package internal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetPodmanNetworkInfo(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []NetworkInfo
		wantErr  bool
	}{
		{
			name: "valid network status",
			content: `{
				"podman": {
					"interfaces": {
						"eth0": {
							"subnets": [
								{
									"ipnet": "10.88.0.9/16",
									"gateway": "10.88.0.1"
								}
							],
							"mac_address": "f2:99:8d:fb:5a:57"
						},
						"eth1": {
							"subnets": [
								{
									"ipnet": "192.168.1.10/24",
									"gateway": "192.168.1.1"
								}
							],
							"mac_address": "f2:99:8d:fb:5a:58"
						}
					}
				}
			}`,
			expected: []NetworkInfo{
				{
					IP:      "10.88.0.9/16",
					MAC:     "f2:99:8d:fb:5a:57",
					Gateway: "10.88.0.1",
				},
				{
					IP:      "192.168.1.10/24",
					MAC:     "f2:99:8d:fb:5a:58",
					Gateway: "192.168.1.1",
				},
			},
			wantErr: false,
		},
		{
			name: "empty interfaces",
			content: `{
				"podman": {
					"interfaces": {}
				}
			}`,
			expected: nil,
			wantErr:  false,
		},
		{
			name:     "invalid json",
			content:  "invalid json",
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file with test content
			tmpDir, err := os.MkdirTemp("", "network-test")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			tmpFile := filepath.Join(tmpDir, "network.status")
			if err := os.WriteFile(tmpFile, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to write test file: %v", err)
			}

			// Test getPodmanNetworkInfo
			got, err := getPodmanNetworkInfo(tmpFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("getPodmanNetworkInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(got) != len(tt.expected) {
					t.Errorf("getPodmanNetworkInfo() got %d networks, want %d", len(got), len(tt.expected))
					return
				}

				for i, network := range got {
					if network.IP != tt.expected[i].IP {
						t.Errorf("Network %d IP = %v, want %v", i, network.IP, tt.expected[i].IP)
					}
					if network.MAC != tt.expected[i].MAC {
						t.Errorf("Network %d MAC = %v, want %v", i, network.MAC, tt.expected[i].MAC)
					}
					if network.Gateway != tt.expected[i].Gateway {
						t.Errorf("Network %d Gateway = %v, want %v", i, network.Gateway, tt.expected[i].Gateway)
					}
				}
			}
		})
	}
}