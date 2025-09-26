package logs

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/roboogg133/gpass/config"
)

func ErrorsAndStatuses(info string) (*log.Logger, error) {

	p, err := config.GetLogsDir()
	if err != nil {
		return log.New(nil, "", 0), err
	}
	f, err := os.OpenFile(filepath.Join(p, fmt.Sprintf("%s.log", info)), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return log.New(nil, "", 0), err
	}
	defer f.Close()

	return log.New(f, "", log.Ldate|log.Ltime|log.Lshortfile), nil
}
