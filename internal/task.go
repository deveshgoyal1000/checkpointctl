package internal

// Task represents a checkpoint task with necessary file paths.
type Task struct {
	CheckpointFilePath string
	OutputDir         string
	Engine            string
}