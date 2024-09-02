package main

import (
	"log/slog"
	"os"
	"path/filepath"
)

const (
	UnknownVersion  = "(devel)"
	UnknownProperty = "N/A"
)

var (
	LastCommitHash = UnknownProperty
	BranchName     = UnknownProperty
	ServiceName    = filepath.Base(os.Args[0])
	ProjectID      = UnknownProperty
	Version        = UnknownVersion
)

func Dump() {
	slog.Info("build version information",
		"version", Version,
		"last_commit", LastCommitHash,
		"branch_name", BranchName,
		"service_name", ServiceName,
		"project_id", ProjectID,
	)
}

