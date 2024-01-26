package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20"
)

const base62AlphabetS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Base62Encode 编码字节切片为 Base62 字符串。
func Base62EncodeS(b []byte) string {
	var bi big.Int
	bi.SetBytes(b)
	base := big.NewInt(62)
	mod := &big.Int{}
	var result []byte

	for bi.Sign() > 0 {
		bi.DivMod(&bi, base, mod)
		result = append(result, base62AlphabetS[mod.Int64()])
	}

	// 由于上面的循环产生了倒序的结果，需要反转它
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// encryptAndEncode 使用 ChaCha20 算法加密给定的字符串，然后使用 Base62 对加密后的数据进行编码。
// 它返回编码后的字符串，如果过程中有错误发生则返回错误。
func encryptAndEncodeS(inputFilePath string) error {

	// 1. 读取文件内容
	inputFile, err := os.Open(inputFilePath)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	// 读取输入文件内容
	fileContent, err := ioutil.ReadAll(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法读取输入文件: %v\n", err)
	}

	plaintext := string(fileContent)

	// 2. 创建输出文件
	outputFileName := "order_" + filepath.Base(inputFilePath)
	outputFilePath := filepath.Join(filepath.Dir(inputFilePath), outputFileName)
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	const hexKey = "a5abeb36d6c0a9736264d4cc40a56acd81ef76fbe1ac27873cc0665dc8e531f4"
	const hexNonce = "58ea883fd20adf161ab89dcd"

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Errorf("invalid key: %w", err)
	}
	nonce, err := hex.DecodeString(hexNonce)
	if err != nil {
		return fmt.Errorf("invalid nonce: %w", err)
	}

	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return err
	}

	plaintextBytes := []byte(plaintext)
	ciphertext := make([]byte, len(plaintextBytes))

	c.XORKeyStream(ciphertext, plaintextBytes)

	// 使用 Base62 对加密后的数据进行编码。
	encodedStr := Base62EncodeS(ciphertext)

	_, err = outputFile.WriteString(encodedStr)
	if err != nil {
		fmt.Println("无法写入文件:", err)
		return err
	}

	fmt.Printf("写入文件完成到 %s\n", outputFilePath)

	return nil

}

func main() {
	//单文件
	if len(os.Args) == 1 {
		fmt.Println("请拖拽文件到程序窗口以加密或输入文件路径")
		var inputFilePath string
		fmt.Scanln(&inputFilePath)
		err := encryptAndEncodeS(inputFilePath)
		if err != nil {
			fmt.Printf("加密文件出错: %v\n", err)
		}
	} else {
		//多文件
		for _, inputFilePath := range os.Args[1:] {
			err := encryptAndEncodeS(inputFilePath)
			if err != nil {
				fmt.Printf("加密文件出错: %v\n", err)
			}
		}
	}
}
