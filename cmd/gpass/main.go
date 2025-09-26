package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/roboogg133/gpass/config"
	"github.com/roboogg133/gpass/internal"
	"github.com/roboogg133/gpass/internal/logs"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var conn net.Conn
var clilog *log.Logger

func init() {
	clilog = logs.CliError()

	var err error
	conn, err = net.Dial("unix", config.SocketPathForMyUser())
	if err != nil {
		clilog.Fatal(err)
	}
}

var rootCmd = &cobra.Command{Use: "packets"}

var add = &cobra.Command{
	Use:   "add {path} {secret} [otp]",
	Args:  cobra.RangeArgs(2, 3),
	Short: "Store a secret",
	Run: func(cmd *cobra.Command, args []string) {
		otp := ""

		if len(args) == 3 {
			otp = args[2]
		}

		addrequest := &internal.Request{
			Service: "secrets",
			Action:  "add",
			Secret:  args[1],
			OTP:     otp,
			Path:    args[0],
		}

		if err := Authorized(); err != nil {
			if err == internal.ErrInvalidPassword {
				fmt.Println("Invalid password, this try will be notified")
				os.Exit(1)
			}
		}

		addreq, err := json.Marshal(addrequest)
		if err != nil {
			clilog.Fatal(err)
		}

		if _, err := conn.Write(addreq); err != nil {
			log.Fatal(err)
		}
		buffer := make([]byte, 1)
		if _, err := conn.Read(buffer); err != nil {
			log.Fatal(err)
		}

		if buffer[0] == 1 {
			fmt.Println("Secret added!")
		} else {
			logsdir, err := config.GetLogsDir()
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("error, take a look in %s\n", logsdir)
		}
	},
}

func main() {
	rootCmd.AddCommand(add)
	rootCmd.Execute()

	defer conn.Close()
}

func ReadPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	password, err := term.ReadPassword(fd)
	if err != nil {
		return "", err
	}
	return string(password), nil
}

func Authorized() error {
	request := &internal.Request{
		Service: "key",
		Action:  "check",
	}

	req, err := json.Marshal(request)
	if err != nil {
		return err
	}

	if _, err := conn.Write(req); err != nil {
		return err
	}

	buffer := make([]byte, 1)
	if _, err := conn.Read(buffer); err != nil {
		return err
	}

	conn, err = net.Dial("unix", config.SocketPathForMyUser())
	if err != nil {
		return err
	}

	if buffer[0] == 1 {
		return err
	}

	fmt.Println("Insert password: ")
	pass, err := ReadPassword()
	if err != nil {
		return err
	}
	unlockreq := &internal.Request{
		Service:        "key",
		Authentication: pass,
		Action:         "unlock",
	}
	unlockRequistion, err := json.Marshal(unlockreq)
	if err != nil {
		return err
	}

	if _, err := conn.Write(unlockRequistion); err != nil {
		return err
	}

	buf := make([]byte, 1)

	if _, err := conn.Read(buf); err != nil {
		return err
	}

	conn, err = net.Dial("unix", config.SocketPathForMyUser())
	if err != nil {
		return err
	}

	if buf[0] == 1 {
		return nil
	} else {
		return internal.ErrInvalidPassword
	}

}
