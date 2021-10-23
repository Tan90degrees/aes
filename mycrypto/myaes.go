package mycrypto

import (
	"aes/myerror"
	"bufio"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
)

var keyLetters = []byte(`~!@#$%^&*()_+{}:"<>?/.,';][=-\|0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`) // Except `

var err error

const (
	AES128 int8 = 16
	AES192 int8 = 24
	AES256 int8 = 32
)

type key struct {
	key  []byte
	size int8
}

func MakeKey(mykey []byte) *key {
	newKey := new(key)
	newKey.size = int8(len(mykey))
	keyf(newKey, mykey)
	return newKey
}

func (k key) KeyString() string {
	return string(k.key)
}

func GenKey(strength int8) *key {
	var tmp *big.Int
	newKey := new(key)
	newKey.size = strength
	newKey.key = make([]byte, strength)
	var i int8 = 0
	for ; i < strength; i++ {
		tmp, err = rand.Int(rand.Reader, big.NewInt(93))
		myerror.CheckError(err)
		newKey.key[i] = keyLetters[tmp.Int64()]
	}
	return newKey
}

func (k key) encrypt(data []byte) []byte {
	dst := make([]byte, aes.BlockSize)
	block, err := aes.NewCipher(k.key)
	myerror.CheckError(err)
	block.Encrypt(dst, data)
	return dst
}

func (k key) decrypt(data []byte) []byte {
	dst := make([]byte, aes.BlockSize)
	block, err := aes.NewCipher(k.key)
	myerror.CheckError(err)
	block.Decrypt(dst, data)
	return dst
}

func keyf(key *key, mykey []byte) {
	emptyKey := make([]byte, aes.BlockSize)
	if key.size < AES128 {
		key.key = append(mykey, emptyKey[:(AES128-key.size)]...)
	} else if key.size > AES128 && key.size < AES256 {
		key.key = append(mykey, emptyKey[:(AES192-key.size)]...)
	} else if key.size > AES256 {
		fmt.Printf("\033[0;32;31m" + "The key you input is too long!!! (do not input longer than 32 bytes)\n" + "\033[0m")
		os.Exit(0)
	} else {
		key.key = mykey
	}
}

func FileEncrypto(key key, filePath string, outPath string) {
	tmp := make([]byte, aes.BlockSize)
	fp1, err := os.Open(filePath)
	myerror.CheckError(err)
	defer fp1.Close()
	fp2, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0777)
	myerror.CheckError(err)
	defer fp2.Close()
	fs1, err := fp1.Stat()
	myerror.CheckError(err)
	blockNum := fs1.Size() / aes.BlockSize
	reader := bufio.NewReader(fp1)
	var i int64
	var j int64
	for ; j < blockNum; j++ {
		for i = 0; i < aes.BlockSize; i++ {
			tmp[i], err = reader.ReadByte()
			myerror.CheckError(err)
		}
		ret := key.encrypt(tmp)
		fp2.Write(ret)
	}
	for i = 0; i < aes.BlockSize; i++ {
		tmp[i], err = reader.ReadByte()
		if err != nil && err.Error() == "EOF" {
			end := aes.BlockSize - i
			for ; i < aes.BlockSize; i++ {
				tmp[i] = byte(end)
			}
		}
	}
	ret := key.encrypt(tmp)
	fp2.Write(ret)
}

func FileDecrypto(key key, filePath string, outPath string) {
	tmp := make([]byte, aes.BlockSize)
	fp1, err := os.Open(filePath)
	myerror.CheckError(err)
	defer fp1.Close()
	fp2, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0777)
	myerror.CheckError(err)
	defer fp2.Close()
	fs1, err := fp1.Stat()
	myerror.CheckError(err)
	blockNum := fs1.Size() / aes.BlockSize
	reader := bufio.NewReader(fp1)
	var i int64
	var j int64
	for ; j < blockNum-1; j++ {
		for i = 0; i < aes.BlockSize; i++ {
			tmp[i], err = reader.ReadByte()
			myerror.CheckError(err)
		}
		ret := key.decrypt(tmp)
		fp2.Write(ret)
	}
	for i = 0; i < aes.BlockSize; i++ {
		tmp[i], _ = reader.ReadByte()
	}
	ret := key.decrypt(tmp)
	end := ret[aes.BlockSize-1]
	endLine := make([]byte, 0)
	for i = 0; i < aes.BlockSize-int64(end); i++ {
		endLine = append(endLine, ret[i])
	}
	fp2.Write(endLine)
}

func BigFileEncrypto(key key, filePath string, outPath string, bufSize int) {
	bigTmp := make([]byte, bufSize)
	smallTmp := make([]byte, aes.BlockSize)
	fp1, err := os.Open(filePath)
	myerror.CheckError(err)
	defer fp1.Close()
	fp2, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0777)
	myerror.CheckError(err)
	defer fp2.Close()
	fs1, err := fp1.Stat()
	myerror.CheckError(err)
	bigBlockNum := fs1.Size() / int64(bufSize)
	blockRemain := int((fs1.Size() - bigBlockNum*int64(bufSize)) / aes.BlockSize)
	reader := bufio.NewReaderSize(fp1, bufSize)
	writer := bufio.NewWriterSize(fp2, bufSize)
	var i int64
	var j int
	var k int
	for ; i < bigBlockNum; i++ {
		for j = 0; j < bufSize/aes.BlockSize; j++ {
			for k = 0; k < aes.BlockSize; k++ {
				smallTmp[k], _ = reader.ReadByte()
			}
			enTmp := key.encrypt(smallTmp)
			for k = 0; k < aes.BlockSize; k++ {
				bigTmp[j*aes.BlockSize+k] = enTmp[k]
			}
		}
		// fp2.Write(bigTmp)
		writer.Write(bigTmp)
	}
	for j = 0; j < blockRemain; j++ {
		for i = 0; i < aes.BlockSize; i++ {
			smallTmp[i], err = reader.ReadByte()
			myerror.CheckError(err)
		}
		ret := key.encrypt(smallTmp)
		// fp2.Write(ret)
		writer.Write(ret)
	}
	for i = 0; i < aes.BlockSize; i++ {
		smallTmp[i], err = reader.ReadByte()
		if err != nil && err.Error() == "EOF" {
			end := aes.BlockSize - i
			for ; i < aes.BlockSize; i++ {
				smallTmp[i] = byte(end)
			}
		}
	}
	ret := key.encrypt(smallTmp)
	// fp2.Write(ret)
	writer.Write(ret)
	writer.Flush()
}

func BigFileDecrypto(key key, filePath string, outPath string, bufSize int) {
	bigTmp := make([]byte, bufSize)
	smallTmp := make([]byte, aes.BlockSize)
	fp1, err := os.Open(filePath)
	myerror.CheckError(err)
	defer fp1.Close()
	fp2, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0777)
	myerror.CheckError(err)
	defer fp2.Close()
	fs1, err := fp1.Stat()
	myerror.CheckError(err)
	bigBlockNum := fs1.Size()/int64(bufSize) - 1
	blockRemain := int((fs1.Size() - bigBlockNum*int64(bufSize)) / aes.BlockSize)
	reader := bufio.NewReaderSize(fp1, bufSize)
	writer := bufio.NewWriterSize(fp2, bufSize)
	var i int64
	var j int
	var k int
	for ; i < bigBlockNum; i++ {
		for j = 0; j < bufSize/aes.BlockSize; j++ {
			for k = 0; k < aes.BlockSize; k++ {
				smallTmp[k], _ = reader.ReadByte()
			}
			enTmp := key.decrypt(smallTmp)
			for k = 0; k < aes.BlockSize; k++ {
				bigTmp[j*aes.BlockSize+k] = enTmp[k]
			}
		}
		// fp2.Write(bigTmp)
		writer.Write(bigTmp)
	}
	for j = 0; j < blockRemain-1; j++ {
		for i = 0; i < aes.BlockSize; i++ {
			smallTmp[i], err = reader.ReadByte()
			myerror.CheckError(err)
		}
		ret := key.decrypt(smallTmp)
		// fp2.Write(ret)
		writer.Write(ret)
	}
	for i = 0; i < aes.BlockSize; i++ {
		smallTmp[i], _ = reader.ReadByte()
	}
	ret := key.decrypt(smallTmp)
	end := ret[aes.BlockSize-1]
	endLine := make([]byte, 0)
	for i = 0; i < aes.BlockSize-int64(end); i++ {
		endLine = append(endLine, ret[i])
	}
	// fp2.Write(endLine)
	writer.Write(endLine)
	writer.Flush()
}
