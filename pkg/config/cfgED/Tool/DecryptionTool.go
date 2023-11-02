package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const key = "c24e17615c44b33c69573888bbb69eb550f4b7eb53fe907fe442a0d91cb60633" // 256位的密钥

func decryptFile(inputFilePath string, key string) error {
	// 1. 读取加密文件内容
	inputFile, err := os.Open(inputFilePath)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	// 2. 读取初始化向量
	iv := make([]byte, aes.BlockSize)
	if _, err := inputFile.Read(iv); err != nil {
		return err
	}

	// 3. 将密钥转换为字节数组
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return err
	}

	// 4. 创建AES解密块
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return err
	}

	// 5. 创建AES解密器
	stream := cipher.NewCFBDecrypter(block, iv)

	// 6. 创建输出文件
	outputFileName := "decrypted_" + filepath.Base(inputFilePath)
	outputFilePath := filepath.Join(filepath.Dir(inputFilePath), outputFileName)
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// 7. 解密并写入文件
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

	fmt.Printf("文件已解密并保存为: %s\n", outputFilePath)
	return nil
}

func main() {
	//单文件
	if len(os.Args) == 1 {
		fmt.Println("请拖拽要解密的文件到程序窗口或输入文件路径")
		var inputFilePath string
		fmt.Scanln(&inputFilePath)
		err := decryptFile(inputFilePath, key)
		if err != nil {
			fmt.Printf("解密文件出错: %v\n", err)
		}
	} else {
		//多文件
		for _, inputFilePath := range os.Args[1:] {
			err := decryptFile(inputFilePath, key)
			if err != nil {
				fmt.Printf("解密文件出错: %v\n", err)
			}
		}
	}
}
