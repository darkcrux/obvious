package crypto

import (
	"testing"
)

func TestEncrypt(t *testing.T) {
	key := "my secret"
	data := "my super sensitive data"
	encryptedData, err := encrypt(key, data)
	if err != nil {
		t.Error("error encrypting data", err)
	}

	decryptedData, err := decrypt(key, encryptedData)
	if err != nil {
		t.Error("error decrypting data", err)
	}

	if string(data) != string(decryptedData) {
		t.Errorf(`invalid data retrieved. should be "%v", but is "%v".`, data, decryptedData)
	}
}

func TestEncryptFail(t *testing.T) {
	_, err := encrypt("", "test data")
	if err == nil {
		t.Error("should fail if no key is defined")
	}

	_, err = encrypt("test key", "")
	if err == nil {
		t.Error("should fail if no data is defined")
	}
}

func TestDecryptFail(t *testing.T) {
	key := "my super secret key"
	data := "hello world"
	encryptedData, _ := encrypt(key, data)

	_, err := decrypt("", encryptedData)
	if err == nil {
		t.Error("should fail if no key is defined")
	}

	_, err = decrypt(key, "")
	if err == nil {
		t.Error("should fail if no encrypted data is defined")
	}
}

func encrypt(key, data string) (string, error) {
	d, e := Encrypt([]byte(key), []byte(data))
	return string(d), e
}

func decrypt(key, encryptedData string) (string, error) {
	d, e := Decrypt([]byte(key), []byte(encryptedData))
	return string(d), e
}
