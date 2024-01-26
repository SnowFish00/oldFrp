package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var abbrMap = map[string]string{
	"serverAddr":            "a",
	"serverPort":            "p",
	"user":                  "u",
	"authentication_method": "m",
	"token":                 "t",
	"use_encryption":        "e",
	"use_compression":       "c",
	"type":                  "y",
	"local_ip":              "i",
	"local_port":            "l",
	"remote_port":           "r",
	"plugin":                "g",
	"plugin_user":           "n",
	"plugin_passwd":         "w",
	"tls_enable":            "s",
	"tls_cert_file":         "f",
	"tls_key_file":          "k",
	"tls_trusted_ca_file":   "tc",
	"tls_server_name":       "sn",
	"tls_only":              "to",
	// 其他不常用的配置项被省略
}

func main() {
	// 如果没有通过命令行参数提供文件，提示用户输入
	if len(os.Args) == 1 {
		fmt.Println("请拖拽文件到这个窗口，然后按回车键。")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')

		// 处理可能的引号和换行符
		input = strings.Replace(input, "\"", "", -1)
		input = strings.TrimSpace(input)

		// 分割输入中的所有文件路径
		files := strings.Fields(input)
		for _, filePath := range files {
			if filePath != "" {
				processFile(strings.TrimSpace(filePath))
			}
		}
	} else {
		// 处理通过命令行提供的所有文件
		for _, inputFilePath := range os.Args[1:] {
			processFile(inputFilePath)
		}
	}
}

func processFile(inputFilePath string) {
	// 生成与输入文件相关联的输出文件名
	outputFileName := "abbreviated_" + filepath.Base(inputFilePath)
	outputFilePath := filepath.Join(filepath.Dir(inputFilePath), outputFileName)

	// 读取并处理文件
	file, err := os.Open(inputFilePath)
	if err != nil {
		fmt.Printf("无法打开文件：%s，错误：%s\n", inputFilePath, err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var result strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		result.WriteString(line + "\n")
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("读取文件时出错：%s\n", err)
		return
	}

	// 使用 createAbbreviatedConfig 函数处理文件内容
	output := createAbbreviatedConfig(result.String())

	// 将缩写后的配置写入到新文件
	if err := os.WriteFile(outputFilePath, []byte(output), 0666); err != nil {
		fmt.Printf("写入输出文件时出错：%s\n", err)
		return
	}

	fmt.Printf("处理后的文件已保存为：%s\n", outputFilePath)
}

// createAbbreviatedConfig 函数处理配置文件内容，生成缩写的配置字符串
func createAbbreviatedConfig(config string) string {
	// 按行分割配置内容
	lines := strings.Split(config, "\n")
	var output strings.Builder
	var currentSection string

	// 遍历所有行
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 忽略空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 检测新的节(section)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			// 结束上一个节的配置字符串
			if currentSection != "" {
				output.WriteString("):")
			}
			// 提取节名称
			currentSection = line[1 : len(line)-1]
			// 将节名称添加到输出字符串中
			output.WriteString(currentSection + "(")
		} else {
			// 处理键值对
			kv := strings.SplitN(line, "=", 2)
			if len(kv) == 2 {
				key := strings.TrimSpace(kv[0])
				value := strings.TrimSpace(kv[1])
				// 获取键的缩写并添加到输出字符串中
				output.WriteString(getAbbreviation(key) + "=" + value + ",")
			}
		}
	}

	// 结束最后一个节的配置字符串
	if output.Len() > 0 {
		return strings.TrimRight(output.String(), ",:") + ")"
	}
	return ""
}

// getAbbreviation 函数根据键名获取对应的缩写
func getAbbreviation(key string) string {
	// 如果找到键的缩写，则返回缩写
	if abbr, exists := abbrMap[key]; exists {
		return abbr
	}
	// 如果没有找到对应的缩写，则返回原始键名
	return key
}
