package hufu

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"

	"github.com/google/uuid"
)

const magic = "hufu"
const keyLength = 32

var (
	hu = []byte(magic)[0:2]
	fu = []byte(magic)[2:]

	header = []byte("01")
)

// Tally represents the confidential data.
type Tally interface{}

// SplitTally represents the split data to be stored separately.
type SplitTally struct {
	Stock string
	Foil  string
}

// ID returns a unique ID
func ID() string {
	id := uuid.New()
	return id.String()
}

func bisect(b []byte) ([]byte, []byte) {
	l := len(b)
	s1 := make([]byte, l/2+l%2)
	s2 := make([]byte, l/2)
	for i := 0; i < l/2; i++ {
		s1[i] = b[2*i]
		s2[i] = b[2*i+1]
	}
	if l%2 == 1 {
		s1[l/2] = b[l-1]
	}
	return s1, s2
}

func couple(s1, s2 []byte) []byte {
	// s1 is longer but not more than 1.
	l1 := len(s1)
	l2 := len(s2)
	if l1 != l2 && l1 != l2+1 {
		return nil
	}
	b := make([]byte, l1+l2)
	for i := 0; i < l2; i++ {
		b[2*i] = s1[i]
		b[2*i+1] = s2[i]
	}
	if l1 > l2 {
		b[2*l2] = s1[l2]
	}
	return b
}

func random(length int) ([]byte, error) {
	b := make([]byte, length)

	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Encode encrypts the object's json with a random key
// and splits its base64 encoding into two parts for keeping separately.
func Encode(t Tally) (*SplitTally, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}

	key, err := random(keyLength)
	if err != nil {
		return nil, err
	}

	// prepend header
	plain := append(header, data...)
	cipher, err := encrypt(plain, key)
	if err != nil {
		return nil, err
	}

	b := append(key, cipher...)
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
	base64.StdEncoding.Encode(enc, b)

	stock, foil := bisect(enc)
	s := SplitTally{
		Stock: string(append(hu, stock...)),
		Foil:  string(append(fu, foil...)),
	}

	return &s, nil
}

// Decode is the reverse of Encode that joins and decrypts the two separate pieces of data
// into the original object.
func Decode(s *SplitTally, t Tally) error {
	stock := []byte(s.Stock)[len(hu):]
	foil := []byte(s.Foil)[len(fu):]

	enc := couple(stock, foil)
	b, err := base64.StdEncoding.DecodeString(string(enc))
	if err != nil {
		return err
	}

	key := b[0:keyLength]
	cipher := b[keyLength:]

	plain, err := decrypt(cipher, key)
	if err != nil {
		return err
	}

	// discard header
	data := plain[len(header):]
	if err := json.Unmarshal(data, &t); err != nil {
		return err
	}

	return nil
}
