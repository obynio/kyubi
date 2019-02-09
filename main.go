package main

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
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
	CRC_FAILURE       = "CRC_FAILURE"
	BACKEND_ERROR     = "BACKEND_ERROR"
)

// Fixed values
const (
	UidSize      = 6
	AesSize      = 16
	OtpSize      = 32
	PubSize      = 32
	CrcOkResidue = 0xf0b8
	ModHexMap    = "cbdefghijklnrtuv"
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

func generateApiKey(keyringName string) []byte {

	// entropy to generate a random byte key
	randomKey := make([]byte, 256)
	rand.Read(randomKey)

	return sign([]string{keyringName}, randomKey)
}

func sign(params []string, key []byte) []byte {
	sort.Strings(params)
	payload := strings.Join(params, "&")

	// generate hmac signature of params
	hmacHdl := hmac.New(sha1.New, key)
	hmacHdl.Write([]byte(payload))
	return hmacHdl.Sum(nil)
}

func parseToken(token string) ([]byte, []byte, error) {
	// check minimal otp length
	token = strings.TrimSpace(token)
	tokenLen := len(token)
	if tokenLen <= 32 {
		return nil, nil, errors.New(BAD_OTP)
	}

	// TODO: useless ?
	// TODO: use const variables
	// where the otp starts in the token
	canary := tokenLen - 32

	// extract public key
	if lng := len(token[:canary]); lng < 1 || lng > 32 {
		return nil, nil, errors.New(BAD_OTP)
	}
	pub := make([]byte, len(token[:canary]))
	copy(pub, []byte(token[:canary]))

	// extract otp
	otp := make([]byte, len(token[canary:]))
	copy(otp, []byte(token[canary:]))

	return pub, otp, nil
}

func modHexDecode(src []byte) []byte {
	dst := make([]byte, (len(src)+1)/2)
	alt := false
	idx := 0

	for _, val := range src {
		b := bytes.IndexByte([]byte(ModHexMap), val)
		if b == -1 {
			b = 0
		}
		bb := byte(b)

		alt = !alt
		if alt {
			dst[idx] = bb
		} else {
			dst[idx] <<= 4
			dst[idx] |= bb
			idx++
		}
	}
	return dst
}

func crc16(buf []byte) uint16 {
	m_crc := uint16(0xffff)
	for _, val := range buf {
		m_crc ^= uint16(val & 0xff)
		for i := 0; i < 8; i++ {
			j := m_crc & 1
			m_crc >>= 1
			if j > 0 {
				m_crc ^= 0x8408
			}
		}
	}

	return m_crc
}

func extractOtp(buf []byte) (*Token, error) {
	var token Token

	if len(buf) != 16 || crc16(buf) != CrcOkResidue {
		return nil, errors.New(CRC_FAILURE)
	}

	copy(token.Uid[:], buf[:6])

	token.Ctr = binary.LittleEndian.Uint16(buf[6:])
	token.Tstpl = binary.LittleEndian.Uint16(buf[8:])

	token.Tstph = buf[10]
	token.Use = buf[11]

	token.Rnd = binary.LittleEndian.Uint16(buf[12:])
	token.Crc = binary.LittleEndian.Uint16(buf[14:])

	return &token, nil
}

func decipherOtp(otp [OtpSize]byte, key [AesSize]byte) (*Token, error) {
	// decipher the token using the aes key
	buf := make([]byte, len(otp))
	copy(buf, otp[:])

	buf = modHexDecode(buf)

	cipher, _ := aes.NewCipher(key[:])
	cipher.Decrypt(buf, buf)

	// extract the deciphered token
	token, err := extractOtp(buf)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (db *Db) eatToken(tok string) error {
	// parse the token and extract otp and public key
	pub, otp, err := parseToken(tok)
	if err != nil {
		return err
	}

	// fetch the private key corresponding to the public key in the database
	key, err := db.getKey(string(pub))
	if err != nil {
		return errors.New(BAD_OTP)
	}

	// verify the the aes128b key coherence
	priv, err := hex.DecodeString(strings.TrimSpace(key.Secret))
	if err != nil {
		return errors.New(BACKEND_ERROR)
	}

	var aes [AesSize]byte
	copy(aes[:], priv)

	// decipher the token
	var o [OtpSize]byte
	copy(o[:], otp)
	token, err := decipherOtp(o, aes)
	if err != nil {
		return err
	}

	// check token validity
	if token.Ctr < uint16(key.Counter) {
		return errors.New(REPLAYED_OTP)
	} else if token.Ctr == uint16(key.Counter) && token.Use <= uint8(key.Session) {
		return errors.New(REPLAYED_OTP)
	}

	// consume the token in the database
	key.Counter = int64(token.Ctr)
	key.Session = int64(token.Use)

	err = db.updateKey(key)
	if err != nil {
		return err
	}

	return nil
}

func (db *Db) handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	otp := r.URL.Query().Get("otp")
	nonce := r.URL.Query().Get("nonce")

	if id == "" || otp == "" || nonce == "" {
		db.reply(w, MISSING_PARAMETER, "", "", "")
		return
	}

	err := db.eatToken(otp)
	if err != nil {
		db.reply(w, err.Error(), id, otp, nonce)
		return
	}

	db.reply(w, OK, id, otp, nonce)
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
