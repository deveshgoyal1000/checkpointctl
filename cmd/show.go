package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/checkpoint-restore/checkpointctl/internal"
	"github.com/spf13/cobra"
)

var showCmd = &cobra.Command{
	Use:   "show [checkpoint-directory]",
	Short: "Show details about a checkpoint",
	Long:  `Show details about a checkpoint.`,
	RunE:  runShow,
	Args:  cobra.MinimumNArgs(1),
}

func init() {
	rootCmd.AddCommand(showCmd)
}

func runShow(cmd *cobra.Command, args []string) error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}

	var checkpointDir string
	if filepath.IsAbs(args[0]) {
		checkpointDir = args[0]
	} else {
		checkpointDir = filepath.Join(dir, args[0])
	}

	container, err := internal.LoadContainer(checkpointDir)
	if err != nil {
		return err
	}

	fmt.Printf("Name: %s\n", container.Name)
	fmt.Printf("ID: %s\n", container.UUID)
	fmt.Printf("Engine: %s\n", container.Engine)
	fmt.Printf("Runtime: %s\n", container.Runtime)
	fmt.Printf("Created: %s\n", container.Created)
	fmt.Printf("Size: %s\n", internal.ByteCountBinary(container.Size))
	fmt.Printf("TCP Established: %t\n", container.TCPEstablished)

	if container.Config.NetNS != "" {
		fmt.Printf("Network Namespace: %s\n", container.Config.NetNS)
	}

	if container.Config.IPs != nil {
		fmt.Printf("Network interfaces:\n")
		for _, ip := range container.Config.IPs {
			fmt.Printf("  %s:\n", ip.Interface)
			fmt.Printf("    IP: %s\n", ip.Address)
			fmt.Printf("    Gateway: %s\n", ip.Gateway)
			fmt.Printf("    MAC: %s\n", ip.MacAddress)
		}
	}

	// Check for Podman network information
	podmanNetworkStatus, err := container.ParsePodmanNetworkStatus()
	if err != nil {
		log.Printf("Warning: Failed to parse Podman network status: %v", err)
	}

	if podmanNetworkStatus != nil && len(podmanNetworkStatus.Podman.Interfaces) > 0 {
		fmt.Printf("Network interfaces:\n")
		for ifName, ifData := range podmanNetworkStatus.Podman.Interfaces {
			fmt.Printf("  %s:\n", ifName)
			fmt.Printf("    MAC: %s\n", ifData.MAC)
			
			for _, subnet := range ifData.Subnets {
				fmt.Printf("    IP: %s\n", subnet.IPNet)
				if subnet.Gateway != "" {
					fmt.Printf("    Gateway: %s\n", subnet.Gateway)
				}
			}
		}
	}

	if container.Config.PodmanCtrConfig != nil {
		fmt.Printf("Podman Container Info:\n")
		fmt.Printf("  ID: %s\n", container.Config.PodmanCtrConfig.PodmanContainerInfo.ID)
		fmt.Printf("  Name: %s\n", container.Config.PodmanCtrConfig.PodmanContainerInfo.Name)
		fmt.Printf("  Namespace: %s\n", container.Config.PodmanCtrConfig.PodmanContainerInfo.Namespace)
		fmt.Printf("  Creator: %s\n", container.Config.PodmanCtrConfig.PodmanContainerInfo.Creator)
		fmt.Printf("  RootFS Image ID: %s\n", container.Config.PodmanCtrConfig.PodmanContainerInfo.RootFsImageI)
		fmt.Printf("  SELinux: %t\n", container.Config.PodmanCtrConfig.PodmanContainerInfo.SELinux)
		fmt.Printf("  PID: %d\n", container.Config.PodmanCtrConfig.PodmanContainerInfo.Pid)

		if container.Config.PodmanCtrConfig.PodmanContainerInfo.Labels != nil {
			fmt.Printf("  Labels:\n")
			for k, v := range container.Config.PodmanCtrConfig.PodmanContainerInfo.Labels {
				fmt.Printf("    %s: %s\n", k, v)
			}
		}

		if container.Config.PodmanCtrConfig.PodmanContainerInfo.Mounts != nil {
			fmt.Printf("  Mounts:\n")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintf(w, "    Source\tDestination\tOptions\n")
			for _, mount := range container.Config.PodmanCtrConfig.PodmanContainerInfo.Mounts {
				fmt.Fprintf(w, "    %s\t%s\t%s\n", mount.Source, mount.Destination, strings.Join(mount.Options, ","))
			}
			w.Flush()
		}
	}

	if container.Config.CRIOCtrConfig != nil {
		fmt.Printf("CRI-O Container Info:\n")
		fmt.Printf("  Pod Name: %s\n", container.Config.CRIOCtrConfig.PodName)
		fmt.Printf("  Pod ID: %s\n", container.Config.CRIOCtrConfig.PodID)
		fmt.Printf("  Pod Namespace: %s\n", container.Config.CRIOCtrConfig.PodNetns)
		fmt.Printf("  Pod Infra Container ID: %s\n", container.Config.CRIOCtrConfig.PodInfraContainerID)
	}

	if container.Config.Routes != nil {
		fmt.Printf("Routes:\n")
		for _, route := range container.Config.Routes {
			fmt.Printf("  %s via %s dev %s\n", route.Dst, route.Gateway, route.Dev)
		}
	}

	return nil
}
