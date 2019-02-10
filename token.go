package main

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
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

func generateApiKey(keyringName string) []byte {

	// entropy to generate a random byte key
	randomKey := make([]byte, 256)
	rand.Read(randomKey)

	return hmacSign([]string{keyringName}, randomKey)
}

func hmacSign(params []string, key []byte) []byte {
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
	if tokenLen <= OtpSize {
		return nil, nil, errors.New(BAD_OTP)
	}

	// where the otp starts in the token
	canary := tokenLen - OtpSize

	// extract public key
	if lng := len(token[:canary]); lng < 1 || lng > PubSize {
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
