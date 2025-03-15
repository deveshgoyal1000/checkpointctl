package internal

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/checkpoint-restore/checkpointctl/lib"
)

const (
	specFileName               = "spec.dump"
	configFileName             = "config.dump"
	imageConfigFileName        = "config"
	netStatusFileName          = "network.status"
	imageIDFileName            = "image-id"
	specFileNameCriO           = "spec.dump.cri-o"
	statusInterfacesFormatting = "%v %v (%v)"
)

// IPAddress is a structure describing the container IP
type IPAddress struct {
	Interface string
	Address   string
	Gateway   string
	MacAddr   string
}

// Container is a structure describing a container
type Container struct {
	Engine            string
	PID               int
	ID                string
	PodID             string
	Name              string
	Bundle            string
	Path              string
	LogPath           string
	Labels            map[string]string
	RestoreCommand    []string
	Rootfs            string
	RootfsMount       string
	Image             string
	ImageManifest     string
	ImageID           string
	OCIVersion        string
	Created           time.Time
	Memory            uint64
	MemoryLimit       uint64
	CPU               uint64
	CPULimit          uint64
	IPs               []IPAddress
	DefaultRoutes     []string
	AdditionalRoutes  []string
	DNS               []string
	DNSOptions        []string
	DNSSearch         []string
	NetworkNamespace  string
	RuntimeSpec       *lib.Spec
	OCICRISpec        *lib.Spec
	NetworkInterfaces []string
	Status            string
	Stats             string
	Driver            string
	MountLabel        string
	ProcessLabel      string
	AppArmorProfile   string
	ExecIDs           []string
	Dependencies      []string
	Running           bool
	Snapshotted       bool
	SnapshotKey       string
	Snapshotter       string
	CgroupPath        string
	CgroupParent      string
	CgroupManager     string
}

// parsePodmanNetworkStatus extracts network information from Podman checkpoint's network.status file
func parsePodmanNetworkStatus(path string, container *Container) error {
	networkStatusPath := filepath.Join(path, "network.status")
	if _, err := os.Stat(networkStatusPath); os.IsNotExist(err) {
		return nil // Not an error if file doesn't exist
	}

	data, err := os.ReadFile(networkStatusPath)
	if err != nil {
		return fmt.Errorf("failed to read network.status file: %w", err)
	}

	var networkStatus struct {
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

	if err := json.Unmarshal(data, &networkStatus); err != nil {
		return fmt.Errorf("failed to parse network.status JSON: %w", err)
	}

	// Extract network information
	for ifName, ifData := range networkStatus.Podman.Interfaces {
		for _, subnet := range ifData.Subnets {
			// Parse IP address from CIDR notation
			ipAddr, _, err := net.ParseCIDR(subnet.IPNet)
			if err != nil {
				// If parsing fails, use the original string
				container.IPs = append(container.IPs, IPAddress{
					Interface: ifName,
					Address:   subnet.IPNet,
					Gateway:   subnet.Gateway,
					MacAddr:   ifData.MacAddress,
				})
			} else {
				container.IPs = append(container.IPs, IPAddress{
					Interface: ifName,
					Address:   ipAddr.String(),
					Gateway:   subnet.Gateway,
					MacAddr:   ifData.MacAddress,
				})
			}
		}
	}

	return nil
}

// ExtractContainerInfo extracts container info from path
func ExtractContainerInfo(path string) (*Container, error) {
	container := new(Container)
	container.Path = path

	// look for spec.dump
	filePath := filepath.Join(path, specFileName)
	if _, err := os.Stat(filePath); err == nil {
		spec, err := lib.LoadSpec(filePath)
		if err != nil {
			return nil, err
		}
		container.RuntimeSpec = spec
		container.OCIVersion = "v2"
	} else {
		// look for spec.dump.cri-o
		filePath = filepath.Join(path, specFileNameCriO)
		if _, err := os.Stat(filePath); err == nil {
			spec, err := lib.LoadSpec(filePath)
			if err != nil {
				return nil, err
			}
			container.OCICRISpec = spec

			var containerName, podID string
			if spec.Annotations != nil {
				// cri pod id
				podID = spec.Annotations["io.kubernetes.cri.sandbox-id"]
				// cri container name
				containerName = spec.Annotations["io.kubernetes.cri.container-name"]
				// container image
				container.Image = spec.Annotations["io.kubernetes.cri.image-name"]
			}
			container.PodID = podID
			container.Name = containerName

			// container id is the checkpoint directory name
			pathSplitter := strings.Split(path, "/")
			container.ID = pathSplitter[len(pathSplitter)-1]
		} else {
			// no specs found
			return nil, fmt.Errorf("no specs found at path %v", path)
		}
	}

	// look for config.dump
	filePath = filepath.Join(path, configFileName)
	if _, err := os.Stat(filePath); err == nil {
		fileData, err := ParseJSONFile(filePath)
		if err != nil {
			return nil, err
		}

		// extract network info from config.dump
		// container id
		if id, ok := fileData["id"]; ok {
			container.ID = id.(string)
		}

		// pod id
		if podID, ok := fileData["pod_id"]; ok {
			container.PodID = podID.(string)
		}

		// container name
		if name, ok := fileData["name"]; ok {
			container.Name = name.(string)
		}

		// containerd bundle
		if bundle, ok := fileData["bundle"]; ok {
			container.Bundle = bundle.(string)
		}

		// Image
		if image, ok := fileData["image"]; ok {
			container.Image = image.(string)
		}

		// Image ID
		if imageID, ok := fileData["image_id"]; ok {
			container.ImageID = imageID.(string)
		}

		// Created
		if created, ok := fileData["created"]; ok {
			layout := "2006-01-02T15:04:05.999999999Z"
			container.Created, err = time.Parse(layout, created.(string))
			if err != nil {
				return nil, err
			}
		}

		// rootfs
		if rootfs, ok := fileData["rootfs"]; ok {
			container.Rootfs = rootfs.(string)
		}

		// rootfs_mount
		if rootfsMount, ok := fileData["rootfs_mount"]; ok {
			container.RootfsMount = rootfsMount.(string)
		}

		// log_path
		if logPath, ok := fileData["log_path"]; ok {
			container.LogPath = logPath.(string)
		}

		// labels
		if rawLabels, ok := fileData["labels"]; ok {
			labels := make(map[string]string)
			for k, v := range rawLabels.(map[string]interface{}) {
				labels[k] = v.(string)
			}
			container.Labels = labels
		}

		// status
		if status, ok := fileData["status"]; ok {
			container.Status = status.(string)
		}

		// driver
		if driver, ok := fileData["driver"]; ok {
			container.Driver = driver.(string)
		}

		// mountlabel
		if mountLabel, ok := fileData["mountlabel"]; ok {
			container.MountLabel = mountLabel.(string)
		}

		// processlabel
		if processLabel, ok := fileData["processlabel"]; ok {
			container.ProcessLabel = processLabel.(string)
		}

		// apparmor_profile
		if apparmorProfile, ok := fileData["apparmor_profile"]; ok {
			container.AppArmorProfile = apparmorProfile.(string)
		}

		// exec_ids
		if execIDs, ok := fileData["exec_ids"]; ok {
			container.ExecIDs = make([]string, len(execIDs.([]interface{})))
			for i, execID := range execIDs.([]interface{}) {
				container.ExecIDs[i] = execID.(string)
			}
		}

		// dependencies
		if dependencies, ok := fileData["dependencies"]; ok {
			container.Dependencies = make([]string, len(dependencies.([]interface{})))
			for i, dependency := range dependencies.([]interface{}) {
				container.Dependencies[i] = dependency.(string)
			}
		}

		// running
		if running, ok := fileData["running"]; ok {
			container.Running = running.(bool)
		}

		// snapshotted
		if snapshotted, ok := fileData["snapshotted"]; ok {
			container.Snapshotted = snapshotted.(bool)
		}

		// snapshot_key
		if snapshotKey, ok := fileData["snapshot_key"]; ok {
			container.SnapshotKey = snapshotKey.(string)
		}

		// snapshotter
		if snapshotter, ok := fileData["snapshotter"]; ok {
			container.Snapshotter = snapshotter.(string)
		}

		// cgroup_path
		if cgroupPath, ok := fileData["cgroup_path"]; ok {
			container.CgroupPath = cgroupPath.(string)
		}

		// cgroup_parent
		if cgroupParent, ok := fileData["cgroup_parent"]; ok {
			container.CgroupParent = cgroupParent.(string)
		}

		// cgroup_manager
		if cgroupManager, ok := fileData["cgroup_manager"]; ok {
			container.CgroupManager = cgroupManager.(string)
		}

		// interfaces
		if networkInterfaces, ok := fileData["interfaces"]; ok {
			container.NetworkInterfaces = make([]string, len(networkInterfaces.([]interface{})))
			for i, netInterface := range networkInterfaces.([]interface{}) {
				container.NetworkInterfaces[i] = netInterface.(string)
			}
		}

		// interface.veth
		if rawIPs, ok := fileData["interface.veth"]; ok {
			ips := rawIPs.([]interface{})

			for _, rawIP := range ips {
				rawIPObj := rawIP.(map[string]interface{})
				// interface
				var ipAddr IPAddress
				if iface, ok := rawIPObj["interface"]; ok {
					ipAddr.Interface = iface.(string)
				}

				// address
				if address, ok := rawIPObj["address"]; ok {
					ipAddr.Address = address.(string)
				}

				// gateway
				if gateway, ok := rawIPObj["gateway"]; ok {
					ipAddr.Gateway = gateway.(string)
				}

				// mac
				if mac, ok := rawIPObj["mac"]; ok {
					ipAddr.MacAddr = mac.(string)
				}

				container.IPs = append(container.IPs, ipAddr)
			}
		}

		// routes
		if rawRoutes, ok := fileData["routes"]; ok {
			routes := rawRoutes.([]interface{})
			for _, rawRoute := range routes {
				container.DefaultRoutes = append(container.DefaultRoutes, rawRoute.(string))
			}
		}

		// routes.add
		if rawRoutesAdd, ok := fileData["routes.add"]; ok {
			routesAdd := rawRoutesAdd.([]interface{})
			for _, rawRouteAdd := range routesAdd {
				container.AdditionalRoutes = append(container.AdditionalRoutes, rawRouteAdd.(string))
			}
		}

		// dns
		if rawDNS, ok := fileData["dns"]; ok {
			dns := rawDNS.([]interface{})
			for _, rawDNS := range dns {
				container.DNS = append(container.DNS, rawDNS.(string))
			}
		}

		// dns.opts
		if rawDNSOpts, ok := fileData["dns.opts"]; ok {
			dnsOpts := rawDNSOpts.([]interface{})
			for _, rawDNSOpt := range dnsOpts {
				container.DNSOptions = append(container.DNSOptions, rawDNSOpt.(string))
			}
		}

		// dns.search
		if rawDNSSearch, ok := fileData["dns.search"]; ok {
			dnsSearch := rawDNSSearch.([]interface{})
			for _, rawDNSSearch := range dnsSearch {
				container.DNSSearch = append(container.DNSSearch, rawDNSSearch.(string))
			}
		}

		// network_namespace
		if networkNamespace, ok := fileData["network_namespace"]; ok {
			container.NetworkNamespace = networkNamespace.(string)
		}

		// resources
		if rawResources, ok := fileData["resources"]; ok {
			if rawResources != nil {
				resources := rawResources.(map[string]interface{})
				// resources.memory
				if rawMemory, ok := resources["memory"]; ok {
					container.Memory = uint64(rawMemory.(float64))
				}

				// resources.memory.limit
				if rawMemoryLimit, ok := resources["memory.limit"]; ok {
					container.MemoryLimit = uint64(rawMemoryLimit.(float64))
				}

				// resources.cpu
				if rawCPU, ok := resources["cpu"]; ok {
					container.CPU = uint64(rawCPU.(float64))
				}

				// resources.cpu.limit
				if rawCPULimit, ok := resources["cpu.limit"]; ok {
					container.CPULimit = uint64(rawCPULimit.(float64))
				}
			}
		}

		// restore_cmd
		if rawRestoreCmd, ok := fileData["restore_cmd"]; ok {
			restoreCmd := make([]string, len(rawRestoreCmd.([]interface{})))
			for i, cmd := range rawRestoreCmd.([]interface{}) {
				restoreCmd[i] = cmd.(string)
			}
			container.RestoreCommand = restoreCmd
		}
	}

	// Look for image-id
	filePath = filepath.Join(path, imageIDFileName)
	if _, err := os.Stat(filePath); err == nil {
		imageID, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		container.ImageID = string(imageID)
	}

	// Try to extract Podman network status information
	if err := parsePodmanNetworkStatus(path, container); err != nil {
		// Don't return error, just log it so we don't fail the entire extraction
		fmt.Printf("Warning: Failed to extract Podman network info: %v\n", err)
	}

	return
