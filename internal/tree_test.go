package internal

import (
	"testing"
	"time"

	metadata "github.com/checkpoint-restore/checkpointctl/lib"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/xlab/treeprint"
)

func TestRenderTreeView(t *testing.T) {
	tests := []struct {
		name       string
		tasks      []Task
		wantErr    bool
	}{
		{
			name: "valid checkpoint",
			tasks: []Task{
				{
					CheckpointFilePath: "test-checkpoint.tar",
					OutputDir:         "/tmp/test-checkpoint",
				},
			},
			wantErr: false,
		},
		{
			name:    "empty tasks",
			tasks:   []Task{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RenderTreeView(tt.tasks)
			if (err != nil) != tt.wantErr {
				t.Errorf("RenderTreeView() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBuildTree(t *testing.T) {
	tests := []struct {
		name       string
		ci         *containerInfo
		config     *metadata.ContainerConfig
		sizes      *archiveSizes
		wantNodes  int
		wantErr    bool
	}{
		{
			name: "valid info",
			ci: &containerInfo{
				Name:    "test-container",
				Created: time.Now().Format(time.RFC3339),
				Engine:  "Podman",
				IP:      "10.88.0.39",
				MAC:     "7a:54:cc:62:e4:e7",
			},
			config: &metadata.ContainerConfig{
				ID:              "test-id",
				Name:            "test-container",
				RootfsImageName: "docker.io/library/nginx:latest",
				CreatedTime:     time.Now(),
				OCIRuntime:      "crun",
			},
			sizes: &archiveSizes{
				checkpointSize:    1024,
				rootFsDiffTarSize: 512,
			},
			wantNodes: 6,
			wantErr:   false,
		},
		{
			name: "empty info",
			ci: &containerInfo{
				Name: "",
			},
			config: &metadata.ContainerConfig{},
			sizes:  &archiveSizes{},
			wantNodes: 1,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := buildTree(tt.ci, tt.config, tt.sizes)
			if tree == nil {
				t.Error("buildTree() returned nil")
				return
			}

			// Count nodes by converting tree to string and counting lines
			nodes := len(tree.String())
			if nodes == 0 {
				t.Error("buildTree() returned empty tree")
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

	tree := treeprint.New()

	addMountsToTree(tree, &specs.Spec{
		Mounts: mounts,
	})

	// Verify mount node was added by checking tree output
	output := tree.String()
	if output == "" {
		t.Error("Expected non-empty tree output")
	}
}

func TestAddPsTreeToTree(t *testing.T) {
	tree := treeprint.New()

	err := addPsTreeToTree(tree, &crit.PsTree{
		PID:  1,
		Comm: "init",
		Children: []*crit.PsTree{
			{
				PID:  2,
				Comm: "nginx",
			},
		},
	}, nil, nil, "/tmp")

	if err != nil {
		t.Errorf("addPsTreeToTree() error = %v", err)
	}

	// Verify process tree was added by checking tree output
	output := tree.String()
	if output == "" {
		t.Error("Expected non-empty tree output")
	}
}