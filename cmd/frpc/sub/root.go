// Copyright 2018 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sub

import (
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/auth"
	"github.com/fatedier/frp/pkg/config"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/version"
)

const (
	CfgFileTypeIni = iota
	CfgFileTypeCmd
)

var (
	cfgFile     string
	cfgOrder    string
	cfgDir      string
	showVersion bool

	serverAddr      string
	user            string
	protocol        string
	token           string
	logLevel        string
	logFile         string
	logMaxDays      int
	disableLogColor bool

	proxyName          string
	localIP            string
	localPort          int
	remotePort         int
	useEncryption      bool
	useCompression     bool
	bandwidthLimit     string
	bandwidthLimitMode string
	customDomains      string
	subDomain          string
	httpUser           string
	httpPwd            string
	locations          string
	hostHeaderRewrite  string
	role               string
	sk                 string
	multiplexer        string
	serverName         string
	bindAddr           string
	bindPort           int

	tlsEnable bool
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "./frpc.ini", "config file of frpc")
	rootCmd.PersistentFlags().StringVarP(&cfgOrder, "order", "o", "", "read config from order")
	rootCmd.PersistentFlags().StringVarP(&cfgDir, "config_dir", "", "", "config directory, run one frpc service for each file in config directory")
	rootCmd.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "version of frpc")
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		// 这里不执行任何操作，或者输出自定义的错误信息
	})
}

// 1. 注册命令行标志
func RegisterCommonFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&serverAddr, "server_addr", "s", "127.0.0.1:7000", "frp server's address")
	cmd.PersistentFlags().StringVarP(&user, "user", "u", "", "user")
	cmd.PersistentFlags().StringVarP(&protocol, "protocol", "p", "tcp", "tcp or kcp or websocket")
	cmd.PersistentFlags().StringVarP(&token, "token", "t", "", "auth token")
	cmd.PersistentFlags().StringVarP(&logLevel, "log_level", "", "info", "log level")
	cmd.PersistentFlags().StringVarP(&logFile, "log_file", "", "console", "console or file path")
	cmd.PersistentFlags().IntVarP(&logMaxDays, "log_max_days", "", 3, "log file reversed days")
	cmd.PersistentFlags().BoolVarP(&disableLogColor, "disable_log_color", "", false, "disable log color in console")
	cmd.PersistentFlags().BoolVarP(&tlsEnable, "tls_enable", "", false, "enable frpc tls")
}

// 2. 根命令
var rootCmd = &cobra.Command{
	Use:   "frpc",
	Short: "frpc is the client of frp (https://github.com/fatedier/frp)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if showVersion {
			fmt.Println(version.Full())
			return nil
		}

		// If cfgDir is not empty, run multiple frpc service for each config file in cfgDir.
		// Note that it's only designed for testing. It's not guaranteed to be stable.
		if cfgDir != "" {
			var wg sync.WaitGroup
			_ = filepath.WalkDir(cfgDir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					return nil
				}
				wg.Add(1)
				time.Sleep(time.Millisecond)
				go func() {
					defer wg.Done()
					err := runClient(path)
					if err != nil {
						fmt.Printf("frpc service error for config file [%s]\n", path)
					}
				}()
				return nil
			})
			wg.Wait()
			return nil
		}

		// Do not show command usage here.
		if cfgOrder == "" {
			//配置文件载入
			err := runClient(cfgFile)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			return nil
		} else {
			//配置文件不落地载入
			err := runClient(cfgOrder)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			return nil
		}

	},
}

// 主函数
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// 用于处理信号，包括SIGINT和SIGTERM，以实现优雅关闭
func handleSignal(svr *client.Service, doneCh chan struct{}) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	svr.GracefulClose(500 * time.Millisecond)
	close(doneCh)
}

// 4. 从命令行参数解析客户端通用配置
func parseClientCommonCfgFromCmd() (cfg config.ClientCommonConf, err error) {
	cfg = config.GetDefaultClientConf()

	ipStr, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		err = fmt.Errorf("invalid server_addr: %v", err)
		return
	}

	cfg.ServerAddr = ipStr
	cfg.ServerPort, err = strconv.Atoi(portStr)
	if err != nil {
		err = fmt.Errorf("invalid server_addr: %v", err)
		return
	}

	cfg.User = user
	cfg.Protocol = protocol
	cfg.LogLevel = logLevel
	cfg.LogFile = logFile
	cfg.LogMaxDays = int64(logMaxDays)
	cfg.DisableLogColor = disableLogColor

	// Only token authentication is supported in cmd mode
	cfg.ClientConfig = auth.GetDefaultClientConf()
	cfg.Token = token
	cfg.TLSEnable = tlsEnable

	cfg.Complete()
	if err = cfg.Validate(); err != nil {
		err = fmt.Errorf("parse config error: %v", err)
		return
	}
	return
}

// 5. 运行frp客户端
func runClient(focfg string) error {
	var cfg config.ClientCommonConf
	var pxyCfgs map[string]config.ProxyConf
	var visitorCfgs map[string]config.VisitorConf
	var err error
	//判断传参方式
	if cfgOrder == "" {
		cfg, pxyCfgs, visitorCfgs, err = config.ParseClientConfig(focfg)
		if err != nil {
			return err
		}
		return startService(cfg, pxyCfgs, visitorCfgs, focfg)

	} else {
		cfg, pxyCfgs, visitorCfgs, err = config.ParseClientConfigOrder(focfg)
		if err != nil {
			return err
		}
		return startService(cfg, pxyCfgs, visitorCfgs, "")
	}

}

// 6. 启动frp客户端服务
func startService(
	cfg config.ClientCommonConf, // 客户端通用配置
	pxyCfgs map[string]config.ProxyConf, // 代理配置
	visitorCfgs map[string]config.VisitorConf, // 访问配置
	cfgFile string, // 配置文件路径
) (err error) {
	log.InitLog(cfg.LogWay, cfg.LogFile, cfg.LogLevel,
		cfg.LogMaxDays, cfg.DisableLogColor)

	if cfgFile != "" {
		log.Trace("start frpc service for config file [%s]", cfgFile)
		defer log.Trace("frpc service for config file [%s] stopped", cfgFile)
	}
	// 创建frp客户端服务
	svr, errRet := client.NewService(cfg, pxyCfgs, visitorCfgs, cfgFile)
	if errRet != nil {
		err = errRet
		return
	}

	closedDoneCh := make(chan struct{})
	shouldGracefulClose := cfg.Protocol == "kcp" || cfg.Protocol == "quic"
	// Capture the exit signal if we use kcp or quic.
	// 如果使用kcp或quic协议，捕获退出信号以进行优雅关闭
	if shouldGracefulClose {
		go handleSignal(svr, closedDoneCh)
	}

	err = svr.Run()
	// 如果没有错误且使用了kcp或quic协议，等待服务关闭完成
	if err == nil && shouldGracefulClose {
		<-closedDoneCh
	}
	return
}
