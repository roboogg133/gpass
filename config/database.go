package config

import (
	"os"
	"path/filepath"
)

func SecretsDirPath() (string, error) {

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(homeDir, RootDirName, SecretsDirName), nil
}

func NoncesDatabasePath() (string, error) {

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(homeDir, RootDirName, NoncesDatabaseName), nil
}
