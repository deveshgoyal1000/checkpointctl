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

	tests := []struct {
		name     string
		content  string
		wantIP   string
		wantMAC  string
		wantErr  bool
		skipFile bool // if true, don't create the file
	}{
		{
			name: "valid network status",
			content: `{
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
			}`,
			wantIP:  "10.88.0.39/16",
			wantMAC: "7a:54:cc:62:e4:e7",
		},
		{
			name: "empty interfaces",
			content: `{
				"podman": {
					"interfaces": {}
				}
			}`,
			wantIP:  "",
			wantMAC: "",
		},
		{
			name: "interface without subnets",
			content: `{
				"podman": {
					"interfaces": {
						"eth0": {
							"subnets": [],
							"mac_address": "7a:54:cc:62:e4:e7"
						}
					}
				}
			}`,
			wantIP:  "",
			wantMAC: "",
		},
		{
			name: "multiple interfaces",
			content: `{
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
			}`,
			wantIP:  "10.88.0.39/16",
			wantMAC: "7a:54:cc:62:e4:e7",
		},
		{
			name:     "non-existent file",
			skipFile: true,
			wantIP:   "",
			wantMAC:  "",
		},
		{
			name:     "empty file",
			content:  "",
			wantIP:   "",
			wantMAC:  "",
			wantErr:  true,
		},
		{
			name:     "invalid JSON",
			content:  "invalid json",
			wantIP:   "",
			wantMAC:  "",
			wantErr:  true,
		},
		{
			name: "missing required fields",
			content: `{
				"podman": {
					"interfaces": {
						"eth0": {
							"mac_address": "7a:54:cc:62:e4:e7"
						}
					}
				}
			}`,
			wantIP:  "",
			wantMAC: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			networkStatusFile := filepath.Join(tmpDir, "network.status")

			if !tt.skipFile {
				if err := os.WriteFile(networkStatusFile, []byte(tt.content), 0644); err != nil {
					t.Fatal(err)
				}
			}

			ip, mac, err := getPodmanNetworkInfo(networkStatusFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("getPodmanNetworkInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if ip != tt.wantIP {
				t.Errorf("getPodmanNetworkInfo() got IP = %v, want %v", ip, tt.wantIP)
			}
			if mac != tt.wantMAC {
				t.Errorf("getPodmanNetworkInfo() got MAC = %v, want %v", mac, tt.wantMAC)
			}

			if !tt.skipFile {
				if err := os.Remove(networkStatusFile); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}