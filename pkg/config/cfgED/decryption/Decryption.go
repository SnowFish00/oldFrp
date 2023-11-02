package decryption

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"io"
	"os"
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
