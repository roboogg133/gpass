package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/roboogg133/gpass/config"
	"github.com/roboogg133/gpass/internal/crypt"
	"github.com/roboogg133/gpass/internal/logs"
	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func zero(data []byte) {
	if data == nil {
		return
	}
	for i := range data {
		data[i] = 0
	}
}

func main() {
	log := logs.CliError()
	fmt.Print("insert a initial password: ")

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	fd := int(os.Stdin.Fd())
	password, err := term.ReadPassword(fd)
	if err != nil {
		log.Fatal(err)
		return
	}

	strpassword := string(password)
	strpassword = strings.Replace(strpassword, " ", "", 1)
	fmt.Printf("s%sf", strpassword)
	MasterKey := argon2.IDKey([]byte(strpassword), []byte(config.Pepper), 3, 64*1024, 4, 32)
	fmt.Println(MasterKey)
	unix.Mlock(MasterKey)

	defer func() {
		zero(MasterKey)
		unix.Munlock(MasterKey)
	}()

	root := filepath.Join(homeDir, config.RootDirName)

	if err := os.MkdirAll(root, 0700); err != nil {
		log.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(root, config.ConfigurationDirName), 0700); err != nil {
		log.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(root, config.SecretsDirName), 0700); err != nil {
		log.Fatal(err)
	}

	db, err := sql.Open("sqlite3", filepath.Join(root, config.NoncesDatabaseName))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE nonces(
    path TEXT NOT NULL UNIQUE PRIMARY KEY,
    nonce BLOB NOT NULL
	)`); err != nil {
		log.Fatal(err)
	}

	ciphertext, nonce, err := crypt.Encrypt(MasterKey, []byte("NEVER CHANGE THIS FILE CONTENT"))
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, config.TestFileName), ciphertext, 0700); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%s.nonce", config.TestFileName)), nonce, 0700); err != nil {
		log.Fatal(err)
	}

}
