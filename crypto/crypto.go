package crypto

import (
    "io"
	"errors"
    
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
    "crypto/md5"
)
    
// Encrypt encrypts a data using AES
func Encrypt(key, data []byte) (encryptedData []byte, err error) {
    
    if len(key) == 0 || len(data) == 0 {
        err = errors.New("key and/or data should not be empty or nil")
        return
    }
    
    key = md5Hash(key)
    
    var block cipher.Block
    if block, err = aes.NewCipher(key); err != nil {
        return
    }
    
    encryptedData = make([]byte, aes.BlockSize+len(data))
    
    iv := encryptedData[:aes.BlockSize]
    if _, err = io.ReadFull(rand.Reader, iv); err != nil {
        return
    }
    
    cfb := cipher.NewCFBEncrypter(block, iv)
    cfb.XORKeyStream(encryptedData[aes.BlockSize:], data)
    
    return
}

// Decrypt decrypts an encrypted data using AES
func Decrypt(key, encryptedData []byte) (data []byte, err error) {

    if len(key) == 0 || len(encryptedData) == 0 {
        err = errors.New("key and/or encryptedData should not be empty or nil")
        return
    }

    key = md5Hash(key)

    var block cipher.Block
    if block, err = aes.NewCipher(key); err != nil {
        return
    }
    
    if len(encryptedData) < aes.BlockSize {
        err = errors.New("encrypted data is too short")
        return
    }
    
    iv := encryptedData[:aes.BlockSize]
    encryptedData = encryptedData[aes.BlockSize:]
    
    cfb := cipher.NewCFBDecrypter(block, iv)
    cfb.XORKeyStream(encryptedData, encryptedData)
    
    data = encryptedData
    return
}

func md5Hash(key []byte) (md5Hash []byte) {
    h := md5.New()
    h.Write(key)
    md5Hash = h.Sum(nil)
    return
}