package decryption

import (
	"regexp"
	"strings"
)

var abbrMap = map[string]string{
	"sA":    "server_addr",
	"sP":    "server_port",
	"dsT":   "dial_server_timeout",
	"dsK":   "dial_server_keepalive",
	"hPy":   "http_proxy",
	"lF":    "log_file",
	"lL":    "log_level",
	"lMD":   "log_max_days",
	"dlC":   "disable_log_color",
	"aH":    "authenticate_heartbeats",
	"aNW":   "authenticate_new_work_conns",
	"tk":    "token",
	"aM":    "authentication_method",
	"oCI":   "oidc_client_id",
	"oCS":   "oidc_client_secret",
	"oA":    "oidc_audience",
	"oS":    "oidc_scope",
	"oTE":   "oidc_token_endpoint_url",
	"oAA":   "oidc_additional_audience",
	"oAV":   "oidc_additional_var1",
	"adA":   "admin_addr",
	"adP":   "admin_port",
	"adU":   "admin_user",
	"adPW":  "admin_pwd",
	"asD":   "assets_dir",
	"pC":    "pool_count",
	"tM":    "tcp_mux",
	"tMKI":  "tcp_mux_keepalive_interval",
	"u":     "user",
	"lFE":   "login_fail_exit",
	"pr":    "protocol",
	"cSLI":  "connect_server_local_ip",
	"tE":    "tls_enable",
	"tCF":   "tls_cert_file",
	"tKF":   "tls_key_file",
	"tTC":   "tls_trusted_ca_file",
	"tSN":   "tls_server_name",
	"dS":    "dns_server",
	"st":    "start",
	"hI":    "heartbeat_interval",
	"hT":    "heartbeat_timeout",
	"mV1":   "meta_var1",
	"mV2":   "meta_var2",
	"uPS":   "udp_packet_size",
	"inc":   "includes",
	"dCTFB": "disable_custom_tls_first_byte",
	"pE":    "pprof_enable",
	"ty":    "type",
	"lIP":   "local_ip",
	"lP":    "local_port",
	"rP":    "remote_port",
	"bL":    "bandwidth_limit",
	"bLM":   "bandwidth_limit_mode",
	"uE":    "use_encryption",
	"uC":    "use_compression",
	"g":     "group",
	"gK":    "group_key",
	"hCT":   "health_check_type",
	"hCTS":  "health_check_timeout_s",
	"hCMF":  "health_check_max_failed",
	"hCIS":  "health_check_interval_s",
	"sk":    "sk",
	"rl":    "role",
	"sN":    "server_name",
	"bA":    "bind_addr",
	"bP":    "bind_port",
	"mux":   "multiplexer",
	"cD":    "custom_domains",
	"hU":    "http_user",
	"hPp":   "http_pwd",
	"sd":    "subdomain",
	"loc":   "locations",
	"hHR":   "host_header_rewrite",
	"hXF":   "header_X-From-Where",
	"hCU":   "health_check_url",
	"pPV":   "proxy_protocol_version",
	"pl":    "plugin",
	"pUP":   "plugin_unix_path",
	"pHU":   "plugin_http_user",
	"pHP":   "plugin_http_passwd",
	"pU":    "plugin_user",
	"pP":    "plugin_passwd",
	"pLP":   "plugin_local_path",
	"pSP":   "plugin_strip_prefix",
	"pLA":   "plugin_local_addr",
	"pCP":   "plugin_crt_path",
	"pKP":   "plugin_key_path",
	// 确保添加了所有其他项
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
			fullKey, ok := abbrMap[kv[1]]
			if !ok {
				fullKey = kv[1]
			}
			expandedConfig.WriteString(fullKey + " = " + kv[2] + "\n")
		}
		expandedConfig.WriteString("\n")
	}

	return expandedConfig.String()
}
