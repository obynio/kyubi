package main

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

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
		params = append(params, "h="+base64.StdEncoding.EncodeToString(hmacSign(params, keyring.ApiKey)))
	}

	w.Write([]byte(strings.Join(params, "\n")))
}
