package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
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

func air(err error) {
	// panic on error
	if err != nil {
		panic(err)
	}
}

func initSqlite(dbPath string) *Db {
	db, err := sql.Open("sqlite3", dbPath)
	air(err)

	// TODO: check if table already exists
	// TODO: change sqlite bad layout

	keyringTable := `
	CREATE TABLE IF NOT EXISTS keyrings(
		id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		key TEXT,
		created DATETIME
	);
	`
	db.Exec(keyringTable)

	keyTable := `
	CREATE TABLE IF NOT EXISTS keys(
		id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		created DATETIME,
		used DATETIME,
		counter INT,
		session INT,
		public TEXT,
		secret TEXT
	);
	`
	db.Exec(keyTable)

	return &Db{sqlite: db}
}

func generateApiKey(keyringName string) []byte {

	// entropy to generate a random byte key
	randomKey := make([]byte, 256)
	rand.Read(randomKey)

	// generate hmac signature of keyring name
	hmacHdl := hmac.New(sha1.New, randomKey)
	hmacHdl.Write([]byte(keyringName))
	return hmacHdl.Sum(nil)
}

func (db *Db) createKeyring(name string) Keyring {
	// generate our ApiKey
	key := generateApiKey(name)

	// insert it in the keyring database
	stmt, err := db.sqlite.Prepare(`INSERT INTO keyrings(name, key, created) VALUES(?, ?, ?)`)
	defer stmt.Close()
	air(err)

	res, err := stmt.Exec(name, base64.StdEncoding.EncodeToString(key), time.Now())
	air(err)

	i64, err := res.LastInsertId()
	air(err)

	var keyring Keyring

	keyring.Id = i64
	keyring.Name = name
	keyring.ApiKey = key

	return keyring
}

func main() {
	// initialize the database
	db := initSqlite("kyubi.db")

	// new keyring flagset
	new := flag.NewFlagSet("new", flag.ExitOnError)
	newKeyring := new.String("keyring", "", "keyring name")

	// add credentials flagset
	add := flag.NewFlagSet("add", flag.ExitOnError)
	addKeyring := add.String("keyring", "", "keyring name")
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
		flag.Usage()
		os.Exit(1)
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

		keyring := db.createKeyring(*newKeyring)
		fmt.Println("id:", keyring.Id, "key:", base64.StdEncoding.EncodeToString(keyring.ApiKey))
	}

	if add.Parsed() {
		if *addKeyring == "" || *addPublic == "" || *addSecret == "" {
			add.PrintDefaults()
			os.Exit(1)
		}
	}
}
