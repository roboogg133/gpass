package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	config "github.com/roboogg133/gpass/config"
	config_lua "github.com/roboogg133/gpass/config/lua"
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
var databaseMu sync.Mutex

var initLua string

var f1 *os.File
var f2 *os.File

func init() {
	var err error
	statLog, f1, err = logs.ErrorsAndStatuses("status")
	if err != nil {
		log.Panic(err)
	}

	errorLog, f2, err = logs.ErrorsAndStatuses("error")
	if err != nil {
		log.Panic(err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		errorLog.Panic(err)
	}

	initLua = filepath.Join(homeDir, config.RootDirName, config.ConfigurationDirName, config.LuaFName)
}

func zero(data []byte) {
	if data == nil {
		return
	}
	for i := range data {
		data[i] = 0
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
	zero(MasterKey)
	unix.Munlock(MasterKey)
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

	defer f1.Close()
	defer f2.Close()

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
		_ = config_lua.UsualRunFunction("connection_received", initLua)
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
		config_lua.RunFunctionIntParam("other_user_trying_to_acess", int(ucred.Uid), initLua)
		statLog.Println("mismatched process owner uid and caller uid")
		return
	}

	rawRequest := make([]byte, 2048)

	n, err := c.Read(rawRequest)
	if err != nil {
		errorLog.Println("in a connection got an error : ", err)
		return
	}

	rawRequest = rawRequest[:n]

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
			unix.Mlock(MasterKey)
			go ControlMasterKey()
			defer func() {
				if !success {
					c.Write([]byte{0})
					zero(MasterKey)
					unix.Munlock(MasterKey)
					MasterKey = nil
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
					return
				}
			}
			if _, err := c.Write([]byte{1}); err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			_ = config_lua.UsualRunFunction("unlocked_key", initLua)
			success = true
			return
		case "change":
			success := false
			defer func() {
				if !success {
					c.Write([]byte{0})
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

			databaseMu.Lock()
			defer databaseMu.Unlock()
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

			secretsDir, err := config.SecretsDirPath()
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			mu.Lock()
			defer mu.Unlock()

			for i, v := range AllFiles {
				buf, err := os.ReadFile(filepath.Join(secretsDir, v.Path))
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
			if _, err := c.Write([]byte{1}); err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}
			statLog.Println("changed key")

			_ = config_lua.UsualRunFunction("changed_key", initLua)
			success = true
			return

		case "lock":
			zero(MasterKey)
			unix.Munlock(MasterKey)
			MasterKey = nil

			locked = false
			return
		case "check":
			if MasterKey == nil {
				c.Write([]byte{0})
			} else {
				c.Write([]byte{1})
			}
			fmt.Println("escrevi")
			return
		}

	} else if request.Service == "secrets" {
		switch request.Action {
		case "add":

			success := false
			defer func() {
				if !success {
					c.Write([]byte{0})
				}
			}()

			if MasterKey == nil {
				statLog.Println("tried to add a secret but data is locked")
				_ = config_lua.UsualRunFunction("action_with_lock", initLua)
				return
			}

			p, err := config.SecretsDirPath()
			if err != nil {
				return
			}

			noncesDb, err := config.NoncesDatabasePath()
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			databaseMu.Lock()
			defer databaseMu.Unlock()
			db, err := sql.Open("sqlite3", noncesDb)
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			defer db.Close()

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

			_, err = db.Exec("INSERT INTO nonces (path, nonce) VALUES (?, ?)", request.Path, nonce)
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}
			if err := os.MkdirAll(filepath.Dir(filepath.Join(p, request.Path)), 0700); err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}
			if err := os.WriteFile(filepath.Join(p, request.Path), ciphertext, 0700); err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			if _, err := c.Write([]byte{1}); err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}
			statLog.Println("added a secret")
			_ = config_lua.UsualRunFunction("added_secret", initLua)
			success = true
			return

		case "spell-secret":
			success := false
			defer func() {
				if !success {
					c.Write([]byte{0})
				}
			}()

			secretsDir, err := config.SecretsDirPath()
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			if MasterKey == nil {
				statLog.Println("tried to spell a secret without unlocking")
				_ = config_lua.UsualRunFunction("action_with_lock", initLua)
				return
			}

			noncesDb, err := config.NoncesDatabasePath()
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			databaseMu.Lock()
			defer databaseMu.Unlock()
			db, err := sql.Open("sqlite3", noncesDb)
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			var nonce []byte

			if err := db.QueryRow("SELECT nonce WHERE path = ?", request.Path).Scan(&nonce); err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			buf, err := os.ReadFile(filepath.Join(secretsDir, request.Path))
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			plaintext, err := crypt.Decrypt(MasterKey, buf, nonce)
			if err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			var secret internal.Secret

			if err := json.Unmarshal(plaintext, &secret); err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}

			if _, err := c.Write([]byte(secret.Value)); err != nil {
				errorLog.Println("in a connection got an error : ", err)
				return
			}
			statLog.Println("spelled a secret")
			_ = config_lua.UsualRunFunction("secret_spelled", initLua)
			success = true
			return
		}
	}
}
