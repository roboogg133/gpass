package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	config "github.com/roboogg133/gpass/config"
	"github.com/roboogg133/gpass/internal"
	"github.com/roboogg133/gpass/internal/crypt"
	"github.com/roboogg133/gpass/internal/logs"
	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/unix"
)

var statLog *log.Logger
var errorLog *log.Logger

var MasterKey []byte
var locked bool

var mu sync.Mutex

func init() {
	var err error
	statLog, err = logs.ErrorsAndStatuses("status")
	if err != nil {
		log.Panic(err)
	}

	errorLog, err = logs.ErrorsAndStatuses("error")
	if err != nil {
		log.Panic(err)
	}
}

func ControlMasterKey() {
	if locked {
		return
	}
	locked = true
	time.Sleep(config.TimeSleep * time.Minute)
	mu.Lock()
	defer mu.Unlock()
	MasterKey = nil
	locked = false
}

func IfExistsDelete() error {
	_, err := os.Stat(config.SocketPathForMyUser())
	if err != nil {
		return nil
	}
	return os.Remove(config.SocketPathForMyUser())
}

func main() {

	if err := IfExistsDelete(); err != nil {
		errorLog.Panic(err)
	}

	socketPath := config.SocketPathForMyUser()

	if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
		errorLog.Panic(err)
	}

	l, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: socketPath,
		Net:  "unix",
	})
	if err != nil {
		errorLog.Panic(err)
	}

	defer l.Close()

	if err := os.Chmod(socketPath, 0700); err != nil {
		errorLog.Panic(err)
	}

	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			errorLog.Println(err)
			continue
		}

		go handleConnection(conn)

	}

}

type NonceDB struct {
	Path  string
	Nonce []byte
}

func handleConnection(c *net.UnixConn) {
	defer c.Close()

	fd, err := c.File()
	if err != nil {
		errorLog.Println("in a connection got an error : ", err)
		return
	}
	defer fd.Close()

	ucred, err := unix.GetsockoptUcred(int(fd.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		errorLog.Println("in a connection got an error : ", err)
		return
	}

	if ucred.Uid != uint32(os.Getuid()) {
		statLog.Println("mismatched process owner uid and caller uid")
		return
	}

	var rawRequest []byte

	_, err = c.Read(rawRequest)
	if err != nil {
		errorLog.Println("in a connection got an error : ", err)
		return
	}

	var request internal.Request

	if err := json.Unmarshal(rawRequest, &request); err != nil {
		errorLog.Println("in a connection got an error : ", err)
		return
	}

	if request.Service == "key" {
		switch request.Action {
		case "unlock":
			success := false
			MasterKey = argon2.IDKey([]byte(request.Authentication), []byte(config.Pepper), 3, 64*1024, 4, 32)
			go ControlMasterKey()
			defer func() {
				if !success {
					c.Write([]byte("FAILED"))
				}
			}()
			test, testnonce, err := crypt.GetTestFileAndNonce()
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}
			if string(test) != "NEVER CHANGE THIS FILE CONTENT" {
				_, err := crypt.Decrypt(MasterKey, test, testnonce)
				if err != nil {
					statLog.Println("wrong password inserted")
				}
			}
			if _, err := c.Write([]byte("OK")); err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}
			success = true
			return
		case "change":
			success := false
			defer func() {
				if !success {
					c.Write([]byte("FAILED"))
				}
			}()

			if MasterKey == nil {
				statLog.Println("tried to change password")
				return
			}
			p, err := config.NoncesDatabasePath()
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}
			db, err := sql.Open("sqlite3", p)
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			defer db.Close()

			rows, err := db.Query("SELECT path, nonce FROM nonces")
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}
			defer rows.Close()

			var AllFiles []NonceDB

			for rows.Next() {
				var row NonceDB
				if err := rows.Scan(&row.Path, &row.Nonce); err != nil {
					errorLog.Println("in a connection got an error : ", err)
					return
				}

				AllFiles = append(AllFiles, row)
			}
			mu.Lock()
			defer mu.Unlock()

			for i, v := range AllFiles {
				f, err := os.Open(v.Path)
				if err != nil {
					errorLog.Println("in a connection got an error : ", err)
					return
				}

				buf, err := io.ReadAll(f)
				if err != nil {
					errorLog.Println("in a connection got an error : ", err)
					return
				}

				rawDataBuffer, err := crypt.Decrypt(MasterKey, buf, v.Nonce)
				if err != nil {
					errorLog.Println("in a connection got an error : ", err)
					return
				}

				neoKey := argon2.IDKey([]byte(request.Authentication), []byte(config.Pepper), 3, 64*1024, 4, 32)
				ciphertext, nonce, err := crypt.Encrypt(neoKey, rawDataBuffer)
				if err != nil {
					errorLog.Println("in a connection got an error : ", err)
					return
				}

				if err := os.WriteFile(v.Path, ciphertext, 0700); err != nil {
					errorLog.Println("in a connection got an error : ", err)
					return
				}
				AllFiles[i].Nonce = nonce

			}

			_, err = db.Exec("DELETE * FROM nonces")
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			for _, v := range AllFiles {
				_, err = db.Exec("INSERT INTO nonces (path, nonce) VALUES (?, ?)", v.Path, v.Nonce)
				if err != nil {
					errorLog.Println("in a connection got an error : ", err)
					return
				}
			}
			if _, err := c.Write([]byte("OK")); err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}
			statLog.Println("changed password")
			success = true
			return
		}

	} else if request.Service == "secrets" {
		switch request.Action {
		case "add":

			success := false
			defer func() {
				if !success {
					c.Write([]byte("FAILED"))
				}
			}()

			if MasterKey == nil {
				statLog.Println("tried to add a secret")
				return
			}

			p, err := config.SecretsDirPath()
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			db, err := sql.Open("sqlite3", p)
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			secret := &internal.Secret{
				Value: request.Secret,
				OTP:   request.OTP,
			}

			rawContent, err := json.Marshal(&secret)
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			ciphertext, nonce, err := crypt.Encrypt(MasterKey, rawContent)
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			_, err = db.Exec("INSERT INTO nonces (path, nonce) VALUES (?, ?)", filepath.Join(p, request.Path), nonce)
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			if err := os.WriteFile(filepath.Join(p, request.Path), ciphertext, 0700); err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			if _, err := c.Write([]byte("OK")); err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}
			statLog.Println("added a secret")
			success = true
			return
		}
	}
}
