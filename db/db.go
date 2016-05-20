package db

import (
	"encoding/json"
	"io/ioutil"

	"github.com/darkcrux/obvious/crypto"
)

type FileDatabase struct {
	Secrets map[string][]byte `json:"secrets"`
}

func Save(key []byte, filename string, database *FileDatabase) error {

	data, err := json.Marshal(database)
	if err != nil {
		return err
	}

	db, err := crypto.Encrypt(key, data)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(filename, db, 0600); err != nil {
		return err
	}
	return nil
}

func List(key []byte, filename string) ([]string, error) {
	data, err := decryptDatabase(key, filename)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(data.Secrets))
	for k := range data.Secrets {
		keys = append(keys, k)
	}
	return keys, nil
}

func Put(key []byte, filename string, secretName string, secret []byte) error {
	data, err := decryptDatabase(key, filename)
	if err != nil {
		return err
	}
	encryptedSecret, err := crypto.Encrypt(key, secret)
	if err != nil {
		return err
	}
	data.Secrets[secretName] = encryptedSecret

	return Save(key, filename, data)
}

func Get(key []byte, filename string, secretName string) ([]byte, error) {
	data, err := decryptDatabase(key, filename)
	if err != nil {
		return nil, err
	}
	encryptedSecret := data.Secrets[secretName]
	decrytedSecret, err := crypto.Decrypt(key, encryptedSecret)
	if err != nil {
		return nil, err
	}
	return decrytedSecret, nil
}

func Delete(key []byte, filename string, secretName string) error {
	data, err := decryptDatabase(key, filename)
	if err != nil {
		return err
	}
	delete(data.Secrets, secretName)
	return Save(key, filename, data)
}

func decryptDatabase(key []byte, filename string) (*FileDatabase, error) {
	db, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	decryptedDb, err := crypto.Decrypt(key, db)
	if err != nil {
		return nil, err
	}

	var data FileDatabase
	if err := json.Unmarshal(decryptedDb, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
