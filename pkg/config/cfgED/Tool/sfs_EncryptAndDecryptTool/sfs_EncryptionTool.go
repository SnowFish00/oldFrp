package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const key = "c24e17615c44b33c69573888bbb69eb550f4b7eb53fe907fe442a0d91cb60633" // 256位的密钥

func encryptFile(inputFilePath string, key string) error {
	// 1. 读取文件内容
	inputFile, err := os.Open(inputFilePath)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	// 2. 创建输出文件
	outputFileName := "encrypted_" + filepath.Base(inputFilePath)
	outputFilePath := filepath.Join(filepath.Dir(inputFilePath), outputFileName)
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// 3. 将密钥转换为字节数组
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return err
	}

	// 4. 创建AES加密块
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return err
	}

	// 5. 创建随机初始化向量
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	// 6. 写入初始化向量到输出文件
	if _, err := outputFile.Write(iv); err != nil {
		return err
	}

	// 7. 创建AES加密器
	stream := cipher.NewCFBEncrypter(block, iv)

	// 8. 加密并写入文件
	buffer := make([]byte, 1024)
	for {
		n, err := inputFile.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		stream.XORKeyStream(buffer[:n], buffer[:n])
		_, err = outputFile.Write(buffer[:n])
		if err != nil {
			return err
		}
	}

	fmt.Printf("文件已加密并保存为: %s\n", outputFilePath)
	return nil
}

func main() {
	//单文件
	if len(os.Args) == 1 {
		fmt.Println("请拖拽文件到程序窗口以加密或输入文件路径")
		var inputFilePath string
		fmt.Scanln(&inputFilePath)
		err := encryptFile(inputFilePath, key)
		if err != nil {
			fmt.Printf("加密文件出错: %v\n", err)
		}
	} else {
		//多文件
		for _, inputFilePath := range os.Args[1:] {
			err := encryptFile(inputFilePath, key)
			if err != nil {
				fmt.Printf("加密文件出错: %v\n", err)
			}
		}
	}
}
