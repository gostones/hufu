package hufu

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestBisect(t *testing.T) {
	testdata := []struct {
		data     string
		expected []string
	}{
		{"", []string{"", ""}},
		{"a", []string{"a", ""}},
		{"ab", []string{"a", "b"}},
		{"abc", []string{"ac", "b"}},
		{"abcdefgh", []string{"aceg", "bdfh"}},
		{"abcdefghi", []string{"acegi", "bdfh"}},
	}
	for _, d := range testdata {
		s1, s2 := bisect([]byte(d.data))
		if string(s1) != d.expected[0] || string(s2) != d.expected[1] {
			t.Fatalf("data: %s got: %s %s expected: %s %s", d.data, string(s1), string(s2), d.expected[0], d.expected[1])
		}
	}
}

func TestCouple(t *testing.T) {
	testdata := []struct {
		expected string
		data     []string
	}{
		{"", []string{"", ""}},
		{"a", []string{"a", ""}},
		{"ab", []string{"a", "b"}},
		{"abc", []string{"ac", "b"}},
		{"abcdefgh", []string{"aceg", "bdfh"}},
		{"abcdefghi", []string{"acegi", "bdfh"}},
	}
	for _, d := range testdata {
		s := couple([]byte(d.data[0]), []byte(d.data[1]))
		if string(s) != d.expected {
			t.Fatalf("data: %s %s got: %s expected: %s", d.data[0], d.data[1], string(s), d.expected)
		}
	}
}

func TestEncryptDecrypt(t *testing.T) {
	testdata := "this is confidential"
	hexKey := "638f8ab42f5edf4b67702433273ffa56c04c8888b5d3d8c48958b10164752c7e"
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		t.Fatal(err)
	}

	cipher, err := encrypt([]byte(testdata), key)
	if err != nil {
		t.Fatal(err)
	}

	plain, err := decrypt(cipher, key)
	if err != nil {
		t.Fatal(err)
	}

	if string(plain) != testdata {
		t.Fatalf("got: %s expected: %s", string(plain), testdata)
	}
}

func TestEncodeDecode(t *testing.T) {
	type Data struct {
		Name     string
		Username string
		Password string
		Note     string
	}
	testdata := Data{
		Name:     "Top secret",
		Username: "top",
		Password: "secret",
		Note:     "this is confidential",
	}

	encoded, err := Encode(testdata)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Data
	if err := Decode(encoded, &decoded); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(testdata, decoded) {
		t.Fatalf("got: %v expected: %v", decoded, testdata)
	}
}
