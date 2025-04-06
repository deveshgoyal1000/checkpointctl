package internal

import (
	"fmt"
	"os"

	metadata "github.com/checkpoint-restore/checkpointctl/lib"
)

// Task represents a checkpoint task with necessary file paths.
type Task struct {
	CheckpointFilePath string
	OutputDir         string
	Engine            string
}

// CreateTasks creates Task instances for each input archive file.
func CreateTasks(args []string, requiredFiles []string) ([]Task, error) {
	tasks := make([]Task, 0, len(args))

	for _, input := range args {
		tar, err := os.Stat(input)
		if err != nil {
			return nil, err
		}
		if !tar.Mode().IsRegular() {
			return nil, fmt.Errorf("input %s not a regular file", input)
		}

		// Check if there is a checkpoint directory in the archive file
		checkpointDirExists, err := isFileInArchive(input, metadata.CheckpointDirectory, true)
		if err != nil {
			return nil, err
		}

		if !checkpointDirExists {
			return nil, fmt.Errorf("checkpoint directory is missing in the archive file: %s", input)
		}

		dir, err := os.MkdirTemp("", "checkpointctl")
		if err != nil {
			return nil, err
		}

		if err := UntarFiles(input, dir, requiredFiles); err != nil {
			return nil, err
		}

		tasks = append(tasks, Task{
			CheckpointFilePath: input,
			OutputDir:         dir,
		})
	}

	return tasks, nil
}

// CleanupTasks removes all output directories of given tasks.
func CleanupTasks(tasks []Task) {
	for _, task := range tasks {
		if err := os.RemoveAll(task.OutputDir); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
}