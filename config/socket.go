package config

import (
	"fmt"
	"os"
	"path/filepath"
)

func SocketPathForMyUser() string {
	return filepath.Join(SocketDir, fmt.Sprintf("%d", os.Getuid()), "gpass-manager", "gpass.socket")
}
