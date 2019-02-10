package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/mattn/go-sqlite3"
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

// Token structure
type Token struct {
	Uid   [UidSize]byte
	Ctr   uint16
	Tstpl uint16
	Tstph uint8
	Use   uint8
	Rnd   uint16
	Crc   uint16
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
		counter INTEGER,
		session INTEGER,
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

func (db *Db) updateKey(key *Key) error {
	stmt, err := db.sqlite.Prepare("UPDATE keys SET counter = ?, session = ? WHERE public = ?")
	defer stmt.Close()
	if err != nil {
		return errors.New(BACKEND_ERROR)
	}

	_, err = stmt.Exec(key.Counter, key.Session, key.Public)
	if err != nil {
		return errors.New(BACKEND_ERROR)
	}

	return nil
}

func (db *Db) addKey(id int64, public, secret string) (*Key, error) {

	_, err := hex.DecodeString(secret)
	if err != nil {
		return nil, errors.New("Unable to convert secret key to hexadecimal format")
	}

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
