package config

import (
	"os"
	"path/filepath"
)

func GetLogsDir() (string, error) {

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(filepath.Join(homeDir, RootDirName, "logs"), 0700); err != nil {
		return "", err
	}

	return filepath.Join(homeDir, RootDirName, "logs"), nil
}
