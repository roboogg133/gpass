package logs

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/roboogg133/gpass/config"
)

func ErrorsAndStatuses(info string) (*log.Logger, *os.File, error) {

	p, err := config.GetLogsDir()
	if err != nil {
		return log.New(nil, "", 0), nil, err
	}
	f, err := os.OpenFile(filepath.Join(p, fmt.Sprintf("%s.log", info)), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return log.New(nil, "", 0), nil, err
	}

	return log.New(f, "", log.Ldate|log.Ltime), f, nil
}

func CliError() *log.Logger { return log.New(os.Stderr, "error: ", log.Lshortfile) }
