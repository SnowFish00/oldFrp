package decryption

import (
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

func ExpandAbbreviatedConfig(abbreviated string) string {
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
