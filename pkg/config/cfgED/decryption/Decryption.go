package decryption

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"golang.org/x/crypto/chacha20"
)

func DecryptFileContents(inputFilePath string) ([]byte, error) {
	//默认256位的解密key
	const key = "c24e17615c44b33c69573888bbb69eb550f4b7eb53fe907fe442a0d91cb60633"

	// 1. 打开加密文件
	inputFile, err := os.Open(inputFilePath)
	if err != nil {
		return nil, err
	}
	defer inputFile.Close()

	// 2. 读取初始化向量
	iv := make([]byte, aes.BlockSize)
	if _, err := inputFile.Read(iv); err != nil {
		return nil, err
	}

	// 3. 将密钥转换为字节数组
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}

	// 4. 创建AES解密块
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	// 5. 创建AES解密器
	stream := cipher.NewCFBDecrypter(block, iv)

	// 6. 创建缓冲区来存储解密后的文件内容
	var decryptedData []byte
	buffer := make([]byte, 1024)
	for {
		n, err := inputFile.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		stream.XORKeyStream(buffer[:n], buffer[:n])
		decryptedData = append(decryptedData, buffer[:n]...)
	}

	return decryptedData, nil
}

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Base62Decode 解码 Base62 字符串为字节切片。
func Base62Decode(s string) ([]byte, error) {
	var bi big.Int
	base := big.NewInt(62)
	for i := 0; i < len(s); i++ {
		index := big.NewInt(int64(strings.IndexByte(base62Alphabet, s[i])))
		if index.Sign() == -1 {
			return nil, fmt.Errorf("invalid character: %s", string(s[i]))
		}
		bi.Mul(&bi, base)
		bi.Add(&bi, index)
	}

	return bi.Bytes(), nil
}

// decodeAndDecrypt 使用 Base62 对编码的数据进行解码，然后使用 ChaCha20 算法进行解密。
// 它返回解密后的字符串，如果过程中有错误发生则返回错误。
func DecodeAndDecrypt(encodedStr string) (string, error) {
	const hexKey = "a5abeb36d6c0a9736264d4cc40a56acd81ef76fbe1ac27873cc0665dc8e531f4"
	const hexNonce = "58ea883fd20adf161ab89dcd"

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", fmt.Errorf("invalid key: %w", err)
	}
	nonce, err := hex.DecodeString(hexNonce)
	if err != nil {
		return "", fmt.Errorf("invalid nonce: %w", err)
	}

	ciphertext, err := Base62Decode(encodedStr)
	if err != nil {
		return "", err
	}

	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return "", err
	}

	plaintext := make([]byte, len(ciphertext))
	c.XORKeyStream(plaintext, ciphertext)

	return string(plaintext), nil
}
