// SPDX-License-Identifier: Apache-2.0

// This file is used to handle container checkpoint archives

package internal

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/checkpoint-restore/checkpointctl/lib"
)

// Container represents a container checkpoint
type Container struct {
	Dir           string      `json:"dir"`
	Created       time.Time   `json:"created"`
	Name          string      `json:"name"`
	Runtime       string      `json:"runtime"`
	Engine        string      `json:"engine"`
	UUID          string      `json:"id"`
	ImagesDir     string      `json:"images-dir"`
	TCPEstablished bool        `json:"tcp-established"`
	TarFile       string      `json:"tarfile,omitempty"`
	Config        ConfigSpec  `json:"config,omitempty"`
	Spec          interface{} `json:"spec,omitempty"`
	Size          int64       `json:"size,omitempty"`
	OwnerID       uint32      `json:"-"`
}

// ConfigSpec is the container configuration
type ConfigSpec struct {
	OCIRuntime       string    `json:"oci-runtime,omitempty"`
	OCIBundlePath    string    `json:"oci-bundle-path,omitempty"`
	OCIContainer     string    `json:"oci-container,omitempty"`
	RootfsPath       string    `json:"rootfs-path,omitempty"`
	NetNS            string    `json:"netns,omitempty"`
	LockFile         string    `json:"lock-file,omitempty"`
	Container        string    `json:"container,omitempty"`
	OCIContainer_OLD string    `json:"OCIContainer,omitempty"`
	RuntimeConfig    *RunConf  `json:"RuntimeConfig,omitempty"`
	Labels           []string  `json:"labels,omitempty"`
	LogFile          string    `json:"log-file,omitempty"`
	LogLevel         string    `json:"log-level,omitempty"`
	Exec             string    `json:"exec,omitempty"`
	PodmanCtrConfig  *PodmanC  `json:"PodmanCtrConfig,omitempty"`
	CRIOCtrConfig    *CRIOC    `json:"CRIOCtrConfig,omitempty"`
	IPs              []*CRIOIP `json:"ips,omitempty"`
	Routes           []*Route  `json:"routes,omitempty"`
}

// PodmanNetworkSubnet represents a network subnet configuration in Podman
type PodmanNetworkSubnet struct {
	IPNet   string `json:"ipnet"`
	Gateway string `json:"gateway"`
}

// PodmanNetworkInterface represents a network interface in Podman
type PodmanNetworkInterface struct {
	MAC     string                `json:"mac_address"`
	Subnets []PodmanNetworkSubnet `json:"subnets"`
}

// PodmanNetwork represents the network configuration in Podman
type PodmanNetwork struct {
	Interfaces map[string]PodmanNetworkInterface `json:"interfaces"`
}

// PodmanNetworkStatus represents the top-level network status for Podman
type PodmanNetworkStatus struct {
	Podman PodmanNetwork `json:"podman"`
}

// PodmanC represents the Podman container config
type PodmanC struct {
	PodmanContainerInfo struct {
		ID           string                 `json:"id"`
		Creator      string                 `json:"creator"`
		Name         string                 `json:"name"`
		Namespace    string                 `json:"namespace"`
		RootFsImageI string                 `json:"rootfs-image-id"`
		RootfsInfoI  map[string]interface{} `json:"rootfs-image-info,omitempty"`
		Labels       map[string]string      `json:"labels,omitempty"`
		Mounts       []PodmanMount          `json:"mounts,omitempty"`
		SELinux      bool                   `json:"selinux"`
		Pid          uint32                 `json:"pid"`
	} `json:"podman-container-info,omitempty"`
}

// PodmanMount represents the Podman mount
type PodmanMount struct {
	Destination         string                 `json:"destination"`
	Source              string                 `json:"source"`
	Options             []string               `json:"options"`
	HostSourceImageID   string                 `json:"host-source-image-id"`
	HostSourceImageInfo map[string]interface{} `json:"host-source-image-info,omitempty"`
}

// RunConf represents the runtime config
type RunConf struct {
	Linux struct {
		CgroupsPath string `json:"cgroups-path"`
	} `json:"linux"`
}

// CRIOC represents the CRI-O container config
type CRIOC struct {
	PodName             string `json:"pod-name"`
	PodID               string `json:"pod-id"`
	PodNetns            string `json:"pod-netns"`
	PodInfraContainerID string `json:"pod-infra-container-id"`
}

// CRIOIP represents the CRI-O IPs
type CRIOIP struct {
	Address    string `json:"address"`
	Gateway    string `json:"gateway"`
	IPNet      string `json:"ipnet"`
	IPPrefix   string `json:"ip-prefix"`
	MacAddress string `json:"mac-address"`
	Interface  string `json:"interface"`
}

// Route represents network routes
type Route struct {
	Dst       string `json:"dst"`
	Gateway   string `json:"gw"`
	Dev       string `json:"dev"`
	Protocol  string `json:"protocol"`
	Scope     string `json:"scope"`
	Src       string `json:"src"`
	Mtu       string `json:"mtu"`
	Window    string `json:"window"`
	Advmss    string `json:"advmss"`
	RouteInfo string `json:"route-info"`
}

func containerCreationTime(cdir string) (time.Time, error) {
	var st syscall.Stat_t
	err := syscall.Stat(cdir, &st)
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)), nil
}

// ParsePodmanNetworkStatus extracts network information from network.status for Podman checkpoints
func (c *Container) ParsePodmanNetworkStatus() (*PodmanNetworkStatus, error) {
	networkPath := filepath.Join(c.Dir, "network.status")
	if _, err := os.Stat(networkPath); os.IsNotExist(err) {
		return nil, nil // No network.status file, not an error
	}

	data, err := os.ReadFile(networkPath)
	if err != nil {
		return nil, err
	}

	var networkStatus PodmanNetworkStatus
	if err := json.Unmarshal(data, &networkStatus); err != nil {
		return nil, err
	}

	return &networkStatus, nil
}

// LoadContainer loads a container from the provided directory
func LoadContainer(dir string) (*Container, error) {
	c := &Container{
		Dir: dir,
	}

	var err error
	c.Created, err = containerCreationTime(dir)
	if err != nil {
		return nil, err
	}

	// Load config.dump
	configFile := filepath.Join(dir, "config.dump")
	if _, err := os.Stat(configFile); err == nil {
		config, err := os.ReadFile(configFile)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(config, &c.Config); err != nil {
			return nil, err
		}
	}

	// Load spec.dump
	specFile := filepath.Join(dir, "spec.dump")
	if _, err := os.Stat(specFile); err == nil {
		spec, err := os.ReadFile(specFile)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(spec, &c.Spec); err != nil {
			return nil, err
		}
	}

	// Load metadata.json to get UUID
	metadataFile := filepath.Join(dir, "metadata.json")
	if _, err := os.Stat(metadataFile); err == nil {
		meta, err := lib.ReadMetadata(metadataFile)
		if err != nil {
			return nil, err
		}
		c.UUID = meta.ID
	}

	// Get owner id
	cStat, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	cStatT, ok := cStat.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("Not a syscall.Stat_t")
	}
	c.OwnerID = cStatT.Uid

	i := strings.LastIndex(dir, "/")
	c.Name = dir[i+1:]

	// Find TCPEstablished file
	tcpFile := filepath.Join(dir, "tcp-established")
	if _, err := os.Stat(tcpFile); err == nil {
		c.TCPEstablished = true
	}

	c.ImagesDir = filepath.Join(dir, "images")
	if _, err := os.Stat(c.ImagesDir); os.IsNotExist(err) {
		c.ImagesDir = filepath.Join(dir, "criu.work", "images")
		if _, err := os.Stat(c.ImagesDir); os.IsNotExist(err) {
			c.ImagesDir = filepath.Join(dir, "checkpoint")
			if _, err := os.Stat(c.ImagesDir); os.IsNotExist(err) {
				c.ImagesDir = ""
			}
		}
	}

	// Get dir size
	size, err := dirSize(dir)
	if err != nil {
		size = 0
	}
	c.Size = size

	// Get default runtime
	if c.Config.OCIRuntime != "" {
		c.Runtime = c.Config.OCIRuntime
	} else {
		c.Runtime = "runc"
	}

	// Get engine
	engine, err := ContainerEngine(c)
	if err != nil {
		c.Engine = "unknown"
	} else {
		c.Engine = engine
	}

	tarFile := filepath.Join(dir, "checkpoint.tar")
	if _, err := os.Stat(tarFile); err == nil {
		c.TarFile = tarFile
	}

	return c, nil
}

// ContainerEngine tries to figure out the container engine
func ContainerEngine(c *Container) (string, error) {
	// First check for CRI-O
	if c.Config.CRIOCtrConfig != nil {
		return "cri-o", nil
	}

	// Next try Podman
	if c.Config.PodmanCtrConfig != nil {
		return "podman", nil
	}

	// Then Docker
	cgPath := ""
	if c.Config.RuntimeConfig != nil {
		cgPath = c.Config.RuntimeConfig.Linux.CgroupsPath
	}

	if strings.HasPrefix(cgPath, "/docker/") {
		return "docker", nil
	}

	// Unknown
	return "", fmt.Errorf("Unknown engine")
}

// PrintContainerCheckpoint prints checkpoint metadata
func PrintContainerCheckpoint(c Container) {
	fmt.Printf("Name: %s\n", c.Name)
	fmt.Printf("ID: %s\n", c.UUID)
	fmt.Printf("Engine: %s\n", c.Engine)
	fmt.Printf("Runtime: %s\n", c.Runtime)
	fmt.Printf("Created: %s\n", c.Created)
	fmt.Printf("Size: %s\n", ByteCountBinary(c.Size))
	fmt.Printf("TCP Established: %t\n", c.TCPEstablished)

	if c.Config.NetNS != "" {
		fmt.Printf("Network Namespace: %s\n", c.Config.NetNS)
	}

	if c.Config.IPs != nil {
		for _, ip := range c.Config.IPs {
			fmt.Printf("IP Address: %s\n", ip.Address)
			fmt.Printf("  Interface: %s\n", ip.Interface)
			fmt.Printf("  Gateway: %s\n", ip.Gateway)
			fmt.Printf("  MAC: %s\n", ip.MacAddress)
		}
	}
}

// ByteCountBinary converts bytes to human readable string in binary format
func ByteCountBinary(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func dirSize(path string) (int64, error) {
	var size int64
	err := filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			size += info.Size()
		}
		return nil
	})
	return size, err
}
