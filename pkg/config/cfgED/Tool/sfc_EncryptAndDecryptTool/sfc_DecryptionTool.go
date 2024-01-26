package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/chacha20"
)

const base62AlphabetS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Base62DecodeS 解码 Base62 字符串为字节切片。
func Base62DecodeS(s string) ([]byte, error) {
	var result big.Int
	base := big.NewInt(62)

	for _, char := range s {
		idx := strings.IndexRune(base62AlphabetS, char)
		if idx == -1 {
			return nil, fmt.Errorf("invalid Base62 character: %c", char)
		}
		result.Mul(&result, base)
		result.Add(&result, big.NewInt(int64(idx)))
	}

	return result.Bytes(), nil
}

// decryptAndDecode 使用 ChaCha20 算法解密给定的字符串，然后使用 Base62 对解密后的数据进行解码。
// 它返回解码后的字节切片，如果过程中有错误发生则返回错误。
func decryptAndDecodeS(encodedStr string) ([]byte, error) {
	const hexKey = "a5abeb36d6c0a9736264d4cc40a56acd81ef76fbe1ac27873cc0665dc8e531f4"
	const hexNonce = "58ea883fd20adf161ab89dcd"

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	nonce, err := hex.DecodeString(hexNonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce: %w", err)
	}

	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}

	// 使用 Base62 对加密后的数据进行解码。
	ciphertext, err := Base62DecodeS(encodedStr)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	c.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func decryptAndDecodeFileS(inputFilePath string) error {
	// 1. 读取文件内容
	inputFile, err := os.Open(inputFilePath)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	// 读取输入文件内容
	fileContent, err := ioutil.ReadAll(inputFile)
	if err != nil {
		return fmt.Errorf("无法读取输入文件: %v", err)
	}

	encodedStr := string(fileContent)

	// 2. 创建输出文件
	outputFileName := "decrypted_" + filepath.Base(inputFilePath)
	outputFilePath := filepath.Join(filepath.Dir(inputFilePath), outputFileName)
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// 解密和解码文件内容
	plaintext, err := decryptAndDecodeS(encodedStr)
	if err != nil {
		return fmt.Errorf("解密文件出错: %v", err)
	}

	_, err = outputFile.Write(plaintext)
	if err != nil {
		return fmt.Errorf("无法写入文件: %v", err)
	}

	fmt.Printf("解密文件完成到 %s\n", outputFilePath)

	return nil
}

func main() {
	// 单文件
	if len(os.Args) == 1 {
		fmt.Println("请拖拽文件到程序窗口以解密或输入文件路径")
		var inputFilePath string
		fmt.Scanln(&inputFilePath)
		err := decryptAndDecodeFileS(inputFilePath)
		if err != nil {
			fmt.Printf("解密文件出错: %v\n", err)
		}
	} else {
		// 多文件
		for _, inputFilePath := range os.Args[1:] {
			err := decryptAndDecodeFileS(inputFilePath)
			if err != nil {
				fmt.Printf("解密文件出错: %v\n", err)
			}
		}
	}
}
