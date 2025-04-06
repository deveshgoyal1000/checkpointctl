package internal

import (
	"testing"

	"github.com/checkpoint-restore/checkpointctl/lib/metadata"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// TreeNode represents a node in the tree view
type TreeNode struct {
	Text     string
	Nodes    []*TreeNode
	Selected bool
}

func TestRenderTreeView(t *testing.T) {
	tests := []struct {
		name        string
		checkpoint  *checkpointInfo
		wantOutput  bool
		wantErr     bool
	}{
		{
			name: "valid checkpoint",
			checkpoint: &checkpointInfo{
				Config: &metadata.ContainerConfig{
					Name:    "test-container",
					Image:   "nginx:latest",
					ID:      "test-id",
					Created: "2025-04-06T20:47:07Z",
					NetworkSettings: metadata.NetworkSettings{
						IPAddress:  "10.88.0.39",
						MacAddress: "7a:54:cc:62:e4:e7",
					},
				},
				Spec: &specs.Spec{
					Version: "1.0.0",
					Root: &specs.Root{
						Path: "rootfs",
					},
				},
				Engine: "podman",
			},
			wantOutput: true,
			wantErr:    false,
		},
		{
			name:       "empty checkpoint",
			checkpoint: &checkpointInfo{},
			wantOutput: true,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := RenderTreeView(tt.checkpoint)
			if (err != nil) != tt.wantErr {
				t.Errorf("RenderTreeView() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantOutput && output == "" {
				t.Error("RenderTreeView() expected non-empty output")
			}
		})
	}
}

func TestBuildTree(t *testing.T) {
	tests := []struct {
		name       string
		info       *checkpointInfo
		wantNodes  int
		wantErr    bool
	}{
		{
			name: "valid info",
			info: &checkpointInfo{
				Config: &metadata.ContainerConfig{
					ID:      "test-id",
					Name:    "test-container",
					Image:   "nginx:latest",
					Created: "2025-04-06T20:47:07Z",
					State: metadata.State{
						Status: "running",
					},
					NetworkSettings: metadata.NetworkSettings{
						IPAddress:  "10.88.0.39",
						MacAddress: "7a:54:cc:62:e4:e7",
					},
				},
				Spec: &specs.Spec{
					Version: "1.0.0",
					Root: &specs.Root{
						Path: "rootfs",
					},
				},
				Engine: "podman",
			},
			wantNodes: 6,
			wantErr:   false,
		},
		{
			name: "empty info",
			info: &checkpointInfo{},
			wantNodes: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := buildTree(tt.info)
			if tree == nil {
				t.Error("buildTree() returned nil")
				return
			}

			nodeCount := countNodes(tree)
			if nodeCount != tt.wantNodes {
				t.Errorf("buildTree() got %v nodes, want %v", nodeCount, tt.wantNodes)
			}
		})
	}
}

func TestAddMountsToTree(t *testing.T) {
	mounts := []specs.Mount{
		{
			Source:      "/test/source",
			Destination: "/test/dest",
			Type:        "bind",
		},
	}

	tree := &TreeNode{
		Text: "root",
	}

	addMountsToTree(tree, mounts)

	// Verify mount node was added
	found := false
	for _, child := range tree.Nodes {
		if child.Text == "Mounts" {
			found = true
			if len(child.Nodes) != 1 {
				t.Errorf("Expected 1 mount entry, got %d", len(child.Nodes))
			}
			break
		}
	}

	if !found {
		t.Error("Mounts node not found in tree")
	}
}

func TestAddPsTreeToTree(t *testing.T) {
	psTree := map[string]interface{}{
		"1": map[string]interface{}{
			"comm": "init",
			"children": map[string]interface{}{
				"2": map[string]interface{}{
					"comm": "nginx",
				},
			},
		},
	}

	tree := &TreeNode{
		Text: "root",
	}

	addPsTreeToTree(tree, psTree)

	// Verify process tree was added
	found := false
	for _, child := range tree.Nodes {
		if child.Text == "Process tree" {
			found = true
			if len(child.Nodes) != 1 {
				t.Errorf("Expected 1 process entry, got %d", len(child.Nodes))
			}
			break
		}
	}

	if !found {
		t.Error("Process tree node not found in tree")
	}
}

// Helper function to count nodes in tree
func countNodes(node *TreeNode) int {
	if node == nil {
		return 0
	}

	count := 1 // Count current node
	for _, child := range node.Nodes {
		count += countNodes(child)
	}
	return count
}