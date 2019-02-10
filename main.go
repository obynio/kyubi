package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
)

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

	// run flagset
	run := flag.NewFlagSet("run", flag.ExitOnError)
	runHost := add.String("host", "127.0.0.1", "host to use for the server")
	runPort := add.Int("port", 4242, "port to use for the server")

	// help message
	flag.Usage = func() {
		fmt.Println("Usage:", os.Args[0], "COMMAND [OPTIONS]")
		fmt.Println("\nCommands:")
		fmt.Println("  new\tcreate a new keyring")
		fmt.Println("  add\tadd credentials to a keyring")
		fmt.Println("  run\trun the validation server")
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
	case "run":
		run.Parse(os.Args[2:])
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

	if run.Parsed() {
		if *runPort > 65535 {
			fmt.Println(errors.New("Unconventional port number"))
			os.Exit(1)
		}

		http.HandleFunc("/wsapi/2.0/verify", db.handler)

		fmt.Printf("Running on http://%s:%d/wsapi/2.0/verify\n", *runHost, *runPort)
		http.ListenAndServe(*runHost+":"+strconv.Itoa(*runPort), nil)
	}
}
