package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Db structure
type Db struct {
	sqlite *sql.DB
}

// App structure
type App struct {
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

	appTable := `
	CREATE TABLE IF NOT EXISTS apps(
		id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		key TEXT,
		created DATETIME
	);
	`
	db.Exec(appTable)

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

func generateApiKey(appName string) []byte {

	// entropy to generate a random byte key
	randomKey := make([]byte, 256)
	rand.Read(randomKey)

	// generate hmac signature of app name
	hmacHdl := hmac.New(sha1.New, randomKey)
	hmacHdl.Write([]byte(appName))
	return hmacHdl.Sum(nil)
}

func (db *Db) createApp(name string) App {
	// generate our ApiKey
	key := generateApiKey(name)

	// insert it in the app database
	stmt, err := db.sqlite.Prepare(`INSERT INTO apps(name, key, created) VALUES(?, ?, ?)`)
	defer stmt.Close()
	air(err)

	res, err := stmt.Exec(name, base64.StdEncoding.EncodeToString(key), time.Now())
	air(err)

	i64, err := res.LastInsertId()
	air(err)

	var app App

	app.Id = i64
	app.Name = name
	app.ApiKey = key

	return app
}

func main() {
	// initialize the database
	db := initSqlite("kyubi.db")

	name := flag.String("name", "", "name of the app")
	//public := flag.String("public", "", "public identity")
	//secret := flag.String("secret", "", "secret aes key")
	flag.Parse()

	if *name != "" {
		app := db.createApp(*name)
		fmt.Println("id:", app.Id, "key:", base64.StdEncoding.EncodeToString(app.ApiKey))
	}
}
