package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"
	_ "github.com/mattn/go-sqlite3"
)

// Reply statuses
const (
	OK                = "OK"
	REPLAYED_OTP      = "REPLAYED_OTP"
	MISSING_PARAMETER = "MISSING_PARAMETER"
	BAD_OTP           = "BAD_OTP"
	BAD_SIGNATURE     = "BAD_SIGNATURE"
	NO_SUCH_CLIENT    = "NO_SUCH_CLIENT"
	BACKEND_ERROR     = "BACKEND_ERROR"
)

// Db structure
type Db struct {
	sqlite *sql.DB
}

// Keyring structure
type Keyring struct {
	Id     int64
	Name   string
	ApiKey []byte
}

// Key structure
type Key struct {
	Id      int64
	Created time.Time
	Counter int64
	Session int64
	Public  string
	Secret  string
	Keyring int64
}

func air(err error) {
	if err != nil {
		panic(err)
	}
}

func initSqlite(dbPath string) *Db {
	dsn := "file:" + dbPath + "?_foreign_keys=1&_secure_delete=1"
	db, err := sql.Open("sqlite3", dsn)
	air(err)

	keyringTable := `
	CREATE TABLE IF NOT EXISTS keyrings(
		id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE,
		key TEXT UNIQUE,
		created DATETIME
	);
	`
	db.Exec(keyringTable)

	keyTable := `
	CREATE TABLE IF NOT EXISTS keys(
		id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		created DATETIME,
		counter INT64,
		session INT64,
		public TEXT UNIQUE,
		secret TEXT UNIQUE,
		keyring INTEGER REFERENCES keyrings(id) ON DELETE CASCADE
	);
	`
	db.Exec(keyTable)

	return &Db{sqlite: db}
}

func (db *Db) createKeyring(name string) (*Keyring, error) {
	// generate our ApiKey
	key := generateApiKey(name)

	// insert it in the keyring database
	stmt, err := db.sqlite.Prepare(`INSERT INTO keyrings(name, key, created) VALUES(?, ?, ?)`)
	defer stmt.Close()
	air(err)

	res, err := stmt.Exec(name, base64.StdEncoding.EncodeToString(key), time.Now())
	if sqlErr, ok := err.(sqlite3.Error); ok {
		switch sqlErr.ExtendedCode {
		case sqlite3.ErrConstraintUnique:
			return nil, errors.New("This keyring already exists")
		default:
			return nil, errors.New("Unknown error")
		}
	}

	air(err)

	i64, err := res.LastInsertId()
	air(err)

	var keyring Keyring

	keyring.Id = i64
	keyring.Name = name
	keyring.ApiKey = key

	return &keyring, nil
}

func (db *Db) addKey(id int64, public, secret string) (*Key, error) {

	stmt, err := db.sqlite.Prepare(`INSERT INTO keys(created, counter, session, public, secret, keyring) values(?, ?, ?, ?, ?, ?)`)
	defer stmt.Close()
	air(err)

	var key Key

	key.Created = time.Now()
	key.Counter = 0
	key.Session = 0
	key.Public = public
	key.Secret = secret
	key.Keyring = id

	res, err := stmt.Exec(key.Created, key.Counter, key.Session, key.Public, key.Secret, key.Keyring)
	if sqlErr, ok := err.(sqlite3.Error); ok {
		switch sqlErr.ExtendedCode {
		case sqlite3.ErrConstraintUnique:
			return nil, errors.New("This public or secret key already exists")
		default:
			return nil, errors.New("Unknown error")
		}
	}

	air(err)

	key.Id, err = res.LastInsertId()
	air(err)

	return &key, nil
}

func (db *Db) getKey(public string) (*Key, error) {
	stmt, err := db.sqlite.Prepare(`SELECT created, counter, session, public, secret, keyring FROM keys WHERE public = ?`)
	defer stmt.Close()
	air(err)

	// get the designated key in the database
	key := Key{}

	err = stmt.QueryRow(public).Scan(&key.Created, &key.Counter, &key.Session, &key.Public, &key.Secret, &key.Keyring)
	if err == sql.ErrNoRows {
		return nil, errors.New("No such key exists")
	}

	air(err)

	return &key, nil
}

func (db *Db) getKeyring(id int64) (*Keyring, error) {
	stmt, err := db.sqlite.Prepare(`SELECT id, name, key FROM keyrings WHERE id = ?`)
	defer stmt.Close()
	air(err)

	keyring := Keyring{}

	err = stmt.QueryRow(id).Scan(&keyring.Id, &keyring.Name, &keyring.ApiKey)
	if err == sql.ErrNoRows {
		return nil, errors.New("No such keyring exists")
	}

	air(err)

	keyring.ApiKey, err = base64.StdEncoding.DecodeString(string(keyring.ApiKey))
	if err != nil {
		return nil, errors.New("Unable to decode keyring key")
	}

	return &keyring, nil
}

func generateApiKey(keyringName string) []byte {

	// entropy to generate a random byte key
	randomKey := make([]byte, 256)
	rand.Read(randomKey)

	return sign([]string{keyringName}, randomKey)
}

func sign(params []string, key []byte) []byte {
	sort.Strings(params)
	strings.Join(params, "&")

	// generate hmac signature of params
	hmacHdl := hmac.New(sha1.New, key)
	hmacHdl.Write([]byte(key))
	return hmacHdl.Sum(nil)
}

func (db *Db) handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	otp := r.URL.Query().Get("otp")
	nonce := r.URL.Query().Get("nonce")

	if id == "" || otp == "" || nonce == "" {
		db.reply(w, MISSING_PARAMETER, "", "", "")
		return
	}

	if len(otp) < 12 {
		db.reply(w, BAD_OTP, id, otp, nonce)
		return
	}
}

// TODO: check two times if everything is ok
func (db *Db) reply(w http.ResponseWriter, status, id, otp, nonce string) {
	var keyring *Keyring
	params := []string{}

	if status != MISSING_PARAMETER {
		if id64, err := strconv.ParseInt(id, 10, 64); err == nil {
			if keyring, err = db.getKeyring(id64); err == nil {

				params = append(params, "nonce="+nonce)
				params = append(params, "otp="+otp)

			} else {
				status = NO_SUCH_CLIENT
			}
		} else {
			status = NO_SUCH_CLIENT
		}
	}

	params = append(params, "status="+status)
	params = append(params, "t="+time.Now().Format(time.RFC3339))

	if status != MISSING_PARAMETER && status != NO_SUCH_CLIENT {
		params = append(params, "h="+base64.StdEncoding.EncodeToString(sign(params, keyring.ApiKey)))
	}

	w.Write([]byte(strings.Join(params, "\n")))
}

func main() {
	// initialize the database
	db := initSqlite("kyubi.db")

	// new keyring flagset
	new := flag.NewFlagSet("new", flag.ExitOnError)
	newKeyring := new.String("name", "", "keyring name")

	// add credentials flagset
	add := flag.NewFlagSet("add", flag.ExitOnError)
	addId := add.Int64("id", 0, "keyring id")
	addPublic := add.String("public", "", "yubikey's public identify")
	addSecret := add.String("secret", "", "yubikey's secret aes key")

	// help message
	flag.Usage = func() {
		fmt.Println("Usage:", os.Args[0], "COMMAND [OPTIONS]")
		fmt.Println("\nCommands:")
		fmt.Println("  new\tcreate a new keyring")
		fmt.Println("  add\tadd credentials to a keyring")
		fmt.Println("  rm\tdelete a keyring")
	}

	if len(os.Args) < 2 {
		//flag.Usage()
		//os.Exit(1)
		http.HandleFunc("/wsapi/2.0/verify", db.handler)
		http.ListenAndServe(":4242", nil)
	}

	switch os.Args[1] {
	case "new":
		new.Parse(os.Args[2:])
	case "add":
		add.Parse(os.Args[2:])
	default:
		flag.Usage()
		os.Exit(1)
	}

	if new.Parsed() {
		if *newKeyring == "" {
			new.PrintDefaults()
			os.Exit(1)
		}

		keyring, err := db.createKeyring(*newKeyring)

		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("id:", keyring.Id, "key:", base64.StdEncoding.EncodeToString(keyring.ApiKey))
		}
	}

	if add.Parsed() {
		if *addId == 0 || *addPublic == "" || *addSecret == "" {
			add.PrintDefaults()
			os.Exit(1)
		}

		key, err := db.addKey(*addId, *addPublic, *addSecret)

		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("Key", key.Public, "has been added to keyring", key.Keyring)
		}
	}
}
