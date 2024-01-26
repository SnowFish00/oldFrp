package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var reverseAbbrMap = map[string]string{
	"a":  "serverAddr",
	"p":  "serverPort",
	"u":  "user",
	"m":  "authentication_method",
	"t":  "token",
	"e":  "use_encryption",
	"c":  "use_compression",
	"y":  "type",
	"i":  "local_ip",
	"l":  "local_port",
	"r":  "remote_port",
	"g":  "plugin",
	"n":  "plugin_user",
	"w":  "plugin_passwd",
	"s":  "tls_enable",
	"f":  "tls_cert_file",
	"k":  "tls_key_file",
	"tc": "tls_trusted_ca_file",
	"sn": "tls_server_name",
	"to": "tls_only",
	// 其他不常用的配置项如果有的话也应该包含在反映射表中
}

func main() {
	// 如果没有通过命令行参数提供文件，提示用户输入
	if len(os.Args) == 1 {
		fmt.Println("请拖拽文件到这个窗口，然后按回车键。")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.Replace(input, "\"", "", -1)
		input = strings.TrimSpace(input)
		files := strings.Fields(input)
		for _, filePath := range files {
			if filePath != "" {
				processFile(strings.TrimSpace(filePath))
			}
		}
	} else {
		for _, inputFilePath := range os.Args[1:] {
			processFile(inputFilePath)
		}
	}
}

func processFile(inputFilePath string) {
	outputFileName := "expanded_" + filepath.Base(inputFilePath)
	outputFilePath := filepath.Join(filepath.Dir(inputFilePath), outputFileName)

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

	output := expandAbbreviatedConfig(result.String())

	if err := os.WriteFile(outputFilePath, []byte(output), 0666); err != nil {
		fmt.Printf("写入输出文件时出错：%s\n", err)
		return
	}

	fmt.Printf("扩展后的文件已保存为：%s\n", outputFilePath)
}

func expandAbbreviatedConfig(abbreviated string) string {
	sectionRegex := regexp.MustCompile(`(\w+)\((.*?)\)`)
	kvRegex := regexp.MustCompile(`(\w+)=([^,]+)`)

	var expandedConfig strings.Builder

	sections := sectionRegex.FindAllStringSubmatch(abbreviated, -1)
	for _, section := range sections {
		expandedConfig.WriteString("[" + section[1] + "]\n")
		kvs := kvRegex.FindAllStringSubmatch(section[2], -1)
		for _, kv := range kvs {
			fullKey, ok := reverseAbbrMap[kv[1]]
			if !ok {
				fullKey = kv[1]
			}
			expandedConfig.WriteString(fullKey + " = " + kv[2] + "\n")
		}
		expandedConfig.WriteString("\n")
	}

	return expandedConfig.String()
}
