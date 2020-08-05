package mycrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

const (
	sKey        = "wodeshijiehenmei"
	ivParameter = "010101012345abcd"
)

//加密
func AesEncrypt(src string) string {
	key := []byte(sKey)
	iv := []byte(ivParameter)
	result, err := Aes128Encrypt([]byte(src), key, iv)
	if err != nil {
		return ""
		//panic(err)
	}
	if len(result) == 0 {
		return ""
	}
	//return base64.RawStdEncoding.EncodeToString(result)
	return base64.StdEncoding.EncodeToString(result)
}

//解密
func AesDecrypt(src string) string {

	key := []byte(sKey)
	iv := []byte(ivParameter)
	var result []byte
	var err error
	//result, err = base64.RawStdEncoding.DecodeString(src)
	result, err = base64.StdEncoding.DecodeString(src)
	if err != nil {
		return ""
		//panic(err)
	}
	if len(result) == 0 {
		return ""
	}
	origData, err := Aes128Decrypt(result, key, iv)
	if err != nil {
		return ""
		//panic(err)
	}
	return string(origData)

}
func Aes128Encrypt(origData, key []byte, IV []byte) ([]byte, error) {
	if key == nil || len(key) != 16 {
		return nil, nil
	}
	if IV != nil && len(IV) != 16 {
		return nil, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, IV[:blockSize])
	crypted := make([]byte, len(origData))
	// 根据CryptBlocks方法的说明，如下方式初始化crypted也可以
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func Aes128Decrypt(crypted, key []byte, IV []byte) ([]byte, error) {
	if key == nil || len(key) != 16 {
		return nil, nil
	}
	if IV != nil && len(IV) != 16 {
		return nil, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, IV[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
