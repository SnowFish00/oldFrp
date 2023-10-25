// Copyright 2017 fatedier, fatedier@gmail.com
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

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/fatedier/golib/net/mux"
	fmux "github.com/hashicorp/yamux"
	quic "github.com/quic-go/quic-go"

	"github.com/fatedier/frp/assets"
	"github.com/fatedier/frp/pkg/auth"
	"github.com/fatedier/frp/pkg/config"
	modelmetrics "github.com/fatedier/frp/pkg/metrics"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/nathole"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/fatedier/frp/pkg/robot"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/fatedier/frp/pkg/util/log"
	frpNet "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/tcpmux"
	"github.com/fatedier/frp/pkg/util/util"
	"github.com/fatedier/frp/pkg/util/version"
	"github.com/fatedier/frp/pkg/util/vhost"
	"github.com/fatedier/frp/pkg/util/xlog"
	"github.com/fatedier/frp/server/controller"
	"github.com/fatedier/frp/server/group"
	"github.com/fatedier/frp/server/metrics"
	"github.com/fatedier/frp/server/ports"
	"github.com/fatedier/frp/server/proxy"
	"github.com/fatedier/frp/server/visitor"
)

const (
	connReadTimeout       time.Duration = 10 * time.Second
	vhostReadWriteTimeout time.Duration = 30 * time.Second
)

// Server service
type Service struct {
	// Dispatch connections to different handlers listen on same port
	muxer *mux.Mux

	// Accept connections from client
	listener net.Listener

	// Accept connections using kcp
	kcpListener net.Listener

	// Accept connections using quic
	quicListener quic.Listener

	// Accept connections using websocket
	websocketListener net.Listener

	// Accept frp tls connections
	tlsListener net.Listener

	// Manage all controllers
	ctlManager *ControlManager

	// Manage all proxies
	pxyManager *proxy.Manager

	// Manage all plugins
	pluginManager *plugin.Manager

	// HTTP vhost router
	httpVhostRouter *vhost.Routers

	// All resource managers and controllers
	rc *controller.ResourceController

	// Verifies authentication based on selected method
	authVerifier auth.Verifier

	tlsConfig *tls.Config

	cfg config.ServerCommonConf
}

// 创建和初始化 frps 服务
func NewService(cfg config.ServerCommonConf) (svr *Service, err error) {
	// 创建 TLS 配置实例
	tlsConfig, err := transport.NewServerTLSConfig(
		cfg.TLSCertFile,
		cfg.TLSKeyFile,
		cfg.TLSTrustedCaFile)
	if err != nil {
		return
	}

	// 创建一个名为 svr 的 Service 实例，用于运行 frps 服务器。
	svr = &Service{
		// 控制管理器，处理控制通信，负责与 frpc 通信的控制信息的接收和处理。
		ctlManager: NewControlManager(),

		// 代理管理器，负责管理代理的启动和关闭。
		pxyManager: proxy.NewManager(),

		// 插件管理器，负责加载和管理各种插件。
		pluginManager: plugin.NewManager(),

		// 资源控制器，管理资源如访问者、TCP和UDP端口等。
		rc: &controller.ResourceController{
			// 访问者管理器，用于管理与客户端的连接。
			VisitorManager: visitor.NewManager(),

			// TCP端口管理器，管理TCP端口的分配和释放。
			TCPPortManager: ports.NewManager("tcp", cfg.ProxyBindAddr, cfg.AllowPorts),

			// UDP端口管理器，管理UDP端口的分配和释放。
			UDPPortManager: ports.NewManager("udp", cfg.ProxyBindAddr, cfg.AllowPorts),
		},

		// 虚拟主机路由器，用于路由HTTP请求到不同的虚拟主机。
		httpVhostRouter: vhost.NewRouters(),

		// 认证验证器，用于验证客户端的身份。
		authVerifier: auth.NewAuthVerifier(cfg.ServerConfig),

		// TLS配置，用于安全通信。
		tlsConfig: tlsConfig,

		// 配置信息，包含 frps 服务器的配置选项。
		cfg: cfg,
	}

	// 创建 TCPMux HTTP Connect 多路复用器。
	if cfg.TCPMuxHTTPConnectPort > 0 {
		// 创建一个 TCP 监听器以监听连接。
		var l net.Listener
		address := net.JoinHostPort(cfg.ProxyBindAddr, strconv.Itoa(cfg.TCPMuxHTTPConnectPort))
		l, err = net.Listen("tcp", address)
		if err != nil {
			// 如果创建监听器时出现错误，将返回一个包含错误信息的错误。
			err = fmt.Errorf("create server listener error, %v", err)
			return
		}

		// 创建 TCPMux HTTP Connect 多路复用器，用于处理多个 HTTP Connect 请求。
		svr.rc.TCPMuxHTTPConnectMuxer, err = tcpmux.NewHTTPConnectTCPMuxer(l, cfg.TCPMuxPassthrough, vhostReadWriteTimeout)
		if err != nil {
			// 如果创建多路复用器时出现错误，将返回一个包含错误信息的错误。
			err = fmt.Errorf("create vhost tcpMuxer error, %v", err)
			return
		}

		// 记录日志，表示 TCPMux HTTP Connect 多路复用器已经在指定地址监听，并是否启用了透传。
		log.Info("tcpmux httpconnect multiplexer listen on %s, passthough: %v", address, cfg.TCPMuxPassthrough)
	}

	// 初始化所有插件
	pluginNames := make([]string, 0, len(cfg.HTTPPlugins))
	for n := range cfg.HTTPPlugins {
		pluginNames = append(pluginNames, n)
	}
	sort.Strings(pluginNames)

	for _, name := range pluginNames {
		// 为每个插件名称创建 HTTP 插件选项并将其注册到插件管理器中。
		svr.pluginManager.Register(plugin.NewHTTPPluginOptions(cfg.HTTPPlugins[name]))
		// 记录日志，表示已经注册了一个插件。
		log.Info("plugin [%s] has been registered", name)
	}

	// 将插件管理器设置为资源控制器的插件管理器。
	svr.rc.PluginManager = svr.pluginManager

	// 初始化TCP组控制器 用于处理TCP请求的分组。
	svr.rc.TCPGroupCtl = group.NewTCPGroupCtl(svr.rc.TCPPortManager)

	// 初始化HTTP组控制器 用于处理HTTP请求的分组
	svr.rc.HTTPGroupCtl = group.NewHTTPGroupController(svr.httpVhostRouter)

	// 初始化TCP多路复用（Mux）组控制器 用于处理多路复用的TCP请求的分组
	svr.rc.TCPMuxGroupCtl = group.NewTCPMuxGroupCtl(svr.rc.TCPMuxHTTPConnectMuxer)

	// 初始化404未找到页面路径
	vhost.NotFoundPagePath = cfg.Custom404Page

	var (
		httpMuxOn  bool // 表示是否启用HTTP的多路复用功能
		httpsMuxOn bool // 表示是否启用HTTPS的多路复用功能
	)

	// 检查绑定地址是否相同
	if cfg.BindAddr == cfg.ProxyBindAddr {
		// 如果绑定端口等于HTTP端口，启用HTTP多路复用
		if cfg.BindPort == cfg.VhostHTTPPort {
			httpMuxOn = true
		}
		// 如果绑定端口等于HTTPS端口，启用HTTPS多路复用
		if cfg.BindPort == cfg.VhostHTTPSPort {
			httpsMuxOn = true
		}
	}

	// 监听以接受来自客户端的连接。
	address := net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.BindPort))
	ln, err := net.Listen("tcp", address)
	if err != nil {
		err = fmt.Errorf("create server listener error, %v", err)
		return
	}

	// 创建一个新的 Mux（多路复用器）以处理连接。
	svr.muxer = mux.NewMux(ln)
	svr.muxer.SetKeepAlive(time.Duration(cfg.TCPKeepAlive) * time.Second)
	// 启动一个协程，用于处理 Mux（多路复用器）的服务。
	go func() {
		_ = svr.muxer.Serve()
	}()
	// 更新监听器以使用 Mux（多路复用器）的默认监听器。
	ln = svr.muxer.DefaultListener()

	// 将监听器赋值给服务，表示 frps 正在监听指定地址的 TCP 连接。
	svr.listener = ln
	log.Info("frps tcp listen on %s", address)

	// 用KCP协议监听客户端连接。
	if cfg.KCPBindPort > 0 {
		// 如果配置文件中指定了KCP绑定端口，则执行以下操作。

		address := net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.KCPBindPort))
		// 拼接主机地址和端口以创建完整的地址。

		svr.kcpListener, err = frpNet.ListenKcp(address)
		// 使用KCP协议创建监听器，并将其赋值给svr.kcpListener。

		if err != nil {
			err = fmt.Errorf("listen on kcp udp address %s error: %v", address, err)
			return
		}
		// 如果创建监听器时出现错误，将记录错误信息并返回。

		log.Info("frps kcp listen on udp %s", address)
		// 记录日志，表示frps正在监听指定的KCP协议UDP地址。
	}

	// 用QUIC协议监听客户端连接。
	if cfg.QUICBindPort > 0 {
		// 如果配置文件中指定了QUIC绑定端口，则执行以下操作。

		address := net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.QUICBindPort))
		// 拼接主机地址和端口以创建完整的地址。

		quicTLSCfg := tlsConfig.Clone()
		quicTLSCfg.NextProtos = []string{"frp"}
		// 创建基于TLS的QUIC配置。

		svr.quicListener, err = quic.ListenAddr(address, quicTLSCfg, &quic.Config{
			MaxIdleTimeout:     time.Duration(cfg.QUICMaxIdleTimeout) * time.Second,
			MaxIncomingStreams: int64(cfg.QUICMaxIncomingStreams),
			KeepAlivePeriod:    time.Duration(cfg.QUICKeepalivePeriod) * time.Second,
		})
		// 使用QUIC协议创建监听器，并将其赋值给svr.quicListener。

		if err != nil {
			err = fmt.Errorf("listen on quic udp address %s error: %v", address, err)
			return
		}
		// 如果创建监听器时出现错误，将记录错误信息并返回。

		log.Info("frps quic listen on quic %s", address)
		// 记录日志，表示frps正在监听指定的QUIC协议地址。
	}

	// Listen for accepting connections from client using websocket protocol.
	// 监听客户端使用WebSocket协议的连接。

	// Define the prefix for WebSocket handshake requests.
	// 定义WebSocket握手请求的前缀。
	websocketPrefix := []byte("GET " + frpNet.FrpWebsocketPath)

	// Create a listener for WebSocket connections and associate it with the Mux.
	// 创建用于WebSocket连接的监听器，并将其与Mux（多路复用器）关联。
	websocketLn := svr.muxer.Listen(0, uint32(len(websocketPrefix)), func(data []byte) bool {
		return bytes.Equal(data, websocketPrefix)
	})

	// Create a WebSocket listener and associate it with the WebSocket listener created above.
	// 创建WebSocket监听器并将其与上面创建的WebSocket监听器关联。
	svr.websocketListener = frpNet.NewWebsocketListener(websocketLn)

	// 如果已经配置了HTTP虚拟主机端口（cfg.VhostHTTPPort > 0），则创建HTTP虚拟主机反向代理。
	if cfg.VhostHTTPPort > 0 {
		// 创建HTTP反向代理对象（rp），用于处理HTTP虚拟主机请求。
		rp := vhost.NewHTTPReverseProxy(vhost.HTTPReverseProxyOptions{
			ResponseHeaderTimeoutS: cfg.VhostHTTPTimeout,
		}, svr.httpVhostRouter)
		svr.rc.HTTPReverseProxy = rp

		// 构建监听地址，使用主机和端口号。
		address := net.JoinHostPort(cfg.ProxyBindAddr, strconv.Itoa(cfg.VhostHTTPPort))

		// 创建HTTP服务器对象（server），指定地址和处理程序（Handler）为rp，即反向代理。
		server := &http.Server{
			Addr:    address,
			Handler: rp,
		}

		var l net.Listener
		if httpMuxOn {
			// 如果启用了HTTP多路复用（httpMuxOn），则使用多路复用监听器。
			l = svr.muxer.ListenHttp(1)
		} else {
			// 否则，创建TCP监听器并检查错误。
			l, err = net.Listen("tcp", address)
			if err != nil {
				// 如果出现错误，返回错误消息。
				err = fmt.Errorf("create vhost http listener error, %v", err)
				return
			}
		}

		// 启动HTTP服务器协程，开始监听HTTP请求。
		go func() {
			_ = server.Serve(l)
		}()

		// 输出日志消息，指示HTTP服务已开始监听。
		log.Info("http service listen on %s", address)
	}

	// 如果已经配置了HTTPS虚拟主机端口（cfg.VhostHTTPSPort > 0），则创建HTTPS虚拟主机多路复用器。
	if cfg.VhostHTTPSPort > 0 {
		// 声明一个网络监听器。
		var l net.Listener

		if httpsMuxOn {
			// 如果启用了HTTPS多路复用（httpsMuxOn），则使用多路复用监听器。
			l = svr.muxer.ListenHttps(1)
		} else {
			// 否则，创建TCP监听器，并在发生错误时返回错误消息。
			address := net.JoinHostPort(cfg.ProxyBindAddr, strconv.Itoa(cfg.VhostHTTPSPort))
			l, err = net.Listen("tcp", address)
			if err != nil {
				err = fmt.Errorf("create server listener error, %v", err)
				return
			}
			// 输出日志消息，指示HTTPS服务已开始监听。
			log.Info("https service listen on %s", address)
		}

		// 创建HTTPS虚拟主机多路复用器（vhost.NewHTTPSMuxer）。
		svr.rc.VhostHTTPSMuxer, err = vhost.NewHTTPSMuxer(l, vhostReadWriteTimeout)
		if err != nil {
			// 如果出现错误，返回错误消息。
			err = fmt.Errorf("create vhost httpsMuxer error, %v", err)
			return
		}
	}

	// Create a TLS listener for frp.
	// 为frp创建一个TLS监听器。

	// Use the Mux to create a listener for TLS connections, which will check the initial data.
	// 使用Mux（多路复用器）创建一个用于TLS连接的监听器，该监听器将检查初始数据。

	// It checks if the first byte of data matches the frp TLS header or 0x16 to determine if it's a TLS connection.
	// 它检查数据的第一个字节是否与frp的TLS头部匹配，或者是否等于0x16，以确定是否为TLS连接。
	svr.tlsListener = svr.muxer.Listen(2, 1, func(data []byte) bool {
		return int(data[0]) == frpNet.FRPTLSHeadByte || int(data[0]) == 0x16
	})

	// Create a NAT hole controller if a UDP port is configured.
	// 如果配置了UDP端口，则创建一个NAT穿透控制器。

	// Check if a UDP port is configured in the server's configuration.
	// 检查服务器配置中是否配置了UDP端口。
	if cfg.BindUDPPort > 0 {
		// Define a variable to hold the NAT hole controller.
		// 定义一个变量用于保存NAT穿透控制器。
		var nc *nathole.Controller

		// Create a listener address by combining the server's bind address and UDP port.
		// 通过将服务器的绑定地址和UDP端口组合，创建一个监听地址。
		address := net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.BindUDPPort))

		// Create a new NAT hole controller using the listener address.
		// 使用监听地址创建一个新的NAT穿透控制器。
		nc, err = nathole.NewController(address)

		// Check if there was an error while creating the NAT hole controller.
		// 检查是否在创建NAT穿透控制器时出现错误。
		if err != nil {
			err = fmt.Errorf("create nat hole controller error, %v", err)
			return
		}

		// Assign the NAT hole controller to the server's ResourceController.
		// 将NAT穿透控制器分配给服务器的ResourceController。
		svr.rc.NatHoleController = nc

		// Log that the NAT hole UDP service is listening on the specified address.
		// 记录NAT穿透UDP服务正在侦听指定的地址。
		log.Info("nat hole udp service listen on %s", address)
	}

	var statsEnable bool
	// Create a dashboard web server if a dashboard port is configured.
	// 如果配置了仪表板端口，则创建一个仪表板Web服务器。

	// Check if a dashboard port is configured in the server's configuration.
	// 检查服务器配置中是否配置了仪表板端口。
	if cfg.DashboardPort > 0 {
		// Initialize dashboard assets.
		// 初始化仪表板资源。
		assets.Load(cfg.AssetsDir)

		// Create an address for the dashboard web server by combining the dashboard address and port.
		// 通过组合仪表板地址和端口，创建仪表板Web服务器的地址。
		address := net.JoinHostPort(cfg.DashboardAddr, strconv.Itoa(cfg.DashboardPort))

		// Run the dashboard web server using the created address.
		// 使用创建的地址运行仪表板Web服务器。
		err = svr.RunDashboardServer(address)

		// Check if there was an error while creating the dashboard web server.
		// 检查是否在创建仪表板Web服务器时出现错误。
		if err != nil {
			err = fmt.Errorf("create dashboard web server error, %v", err)
			return
		}

		// Log that the dashboard is listening on the specified address.
		// 记录仪表板正在侦听指定的地址。
		log.Info("Dashboard listen on %s", address)

		// Set the 'statsEnable' variable to true.
		// 将变量'statsEnable'设置为true。
		statsEnable = true
	}

	// If the 'statsEnable' variable is true, enable memory statistics and Prometheus metrics.
	// 如果'statsEnable'变量为true，则启用内存统计和Prometheus指标。
	if statsEnable {
		modelmetrics.EnableMem()
		if cfg.EnablePrometheus {
			modelmetrics.EnablePrometheus()
		}
	}

	return
}

// Run starts the frps service, handling various listeners and controllers.
// Run启动frps服务，处理各种侦听器和控制器。
func (svr *Service) Run() {
	// If there is a NatHoleController, run it in a separate goroutine.
	// 如果存在NatHoleController，则在单独的goroutine中运行它。
	if svr.rc.NatHoleController != nil {
		go svr.rc.NatHoleController.Run()
	}

	// If there is a kcpListener, handle it in a separate goroutine.
	// 如果存在kcpListener，将在单独的goroutine中处理它。
	if svr.kcpListener != nil {
		go svr.HandleListener(svr.kcpListener)
	}

	// If there is a quicListener, handle it in a separate goroutine.
	// 如果存在quicListener，将在单独的goroutine中处理它。
	if svr.quicListener != nil {
		go svr.HandleQUICListener(svr.quicListener)
	}

	// Handle websocketListener in a goroutine.
	// 在一个goroutine中处理websocketListener。
	go svr.HandleListener(svr.websocketListener)

	// Handle tlsListener without a separate goroutine.
	// 处理tlsListener，不使用单独的goroutine。
	go svr.HandleListener(svr.tlsListener)

	// Handle the main listener for accepting client connections without a separate goroutine.
	// 处理用于接受客户端连接的主要监听器，不使用单独的goroutine。
	svr.HandleListener(svr.listener)
}

// handleConnection 负责根据消息类型处理传入连接。
func (svr *Service) handleConnection(ctx context.Context, conn net.Conn) {
	xl := xlog.FromContextSafe(ctx)

	var (
		rawMsg msg.Message
		err    error
	)

	// 设置读取超时以防止无限期地阻塞。
	_ = conn.SetReadDeadline(time.Now().Add(connReadTimeout))

	// 从连接中读取初始消息。
	if rawMsg, err = msg.ReadMsg(conn); err != nil {
		log.Trace("Failed to read message: %v", err)
		conn.Close()
		return
	}

	// 清除读取超时。
	_ = conn.SetReadDeadline(time.Time{})

	switch m := rawMsg.(type) {
	case *msg.Login:
		// 处理来自客户端的登录消息。

		// server plugin hook
		// 服务器插件挂钩：允许插件修改登录过程。
		content := &plugin.LoginContent{
			Login:         *m,
			ClientAddress: conn.RemoteAddr().String(),
		}
		retContent, err := svr.pluginManager.Login(content)
		if err == nil {
			m = &retContent.Login
			err = svr.RegisterControl(conn, m)
		}

		//wscoket 客户端注册信息回显
		if err == nil {
			if svr.cfg.WsAddr != "" {
				postMsg := msg.ScLogin(m.RunID, msg.TimeToString(m.Timestamp), conn.RemoteAddr().String(), m.User, m.PrivilegeKey, msg.Login_status_t)
				robot.PostJson(svr.cfg.WsAddr, []byte(postMsg))
			}
		}

		// If login failed, send error message there.
		// Otherwise send success message in control's work goroutine.
		// 如果登录失败，向客户端发送错误消息。
		// 否则，在控制工作协程中发送成功消息。
		if err != nil {
			xl.Warn("register control error: %v", err)
			_ = msg.WriteMsg(conn, &msg.LoginResp{
				Version: version.Full(),
				Error:   util.GenerateResponseErrorString("register control error", err, svr.cfg.DetailedErrorsToClient),
			})
			conn.Close()
		}
	case *msg.NewWorkConn:
		if err := svr.RegisterWorkConn(conn, m); err != nil {
			conn.Close()
		}
	case *msg.NewVisitorConn:
		if err = svr.RegisterVisitorConn(conn, m); err != nil {
			xl.Warn("register visitor conn error: %v", err)
			_ = msg.WriteMsg(conn, &msg.NewVisitorConnResp{
				ProxyName: m.ProxyName,
				Error:     util.GenerateResponseErrorString("register visitor conn error", err, svr.cfg.DetailedErrorsToClient),
			})
			conn.Close()
		} else {
			_ = msg.WriteMsg(conn, &msg.NewVisitorConnResp{
				ProxyName: m.ProxyName,
				Error:     "",
			})
		}
	default:
		log.Warn("Error message type for the new connection [%s]", conn.RemoteAddr().String())
		conn.Close()
	}
}

// HandleListener在提供的侦听器上处理来自客户端的传入连接。
func (svr *Service) HandleListener(l net.Listener) {
	// Listen for incoming connections from client.
	for {
		c, err := l.Accept()
		if err != nil {
			log.Warn("Listener for incoming connections from client closed")
			return
		}
		// inject xlog object into net.Conn context
		// 在net.Conn上注入xlog对象到上下文。
		xl := xlog.New()
		ctx := context.Background()

		c = frpNet.NewContextConn(xlog.NewContext(ctx, xl), c)

		log.Trace("start check TLS connection...")
		originConn := c
		// Check if the connection should use TLS and handle custom settings.
		// 检查连接是否需要使用TLS并处理自定义设置。
		var isTLS, custom bool
		c, isTLS, custom, err = frpNet.CheckAndEnableTLSServerConnWithTimeout(c, svr.tlsConfig, svr.cfg.TLSOnly, connReadTimeout)
		if err != nil {
			log.Warn("CheckAndEnableTLSServerConnWithTimeout error: %v", err)
			originConn.Close()
			continue
		}
		log.Trace("check TLS connection success, isTLS: %v custom: %v", isTLS, custom)

		// Start a new goroutine to handle the connection.
		// 启动一个新的goroutine来处理连接。
		go func(ctx context.Context, frpConn net.Conn) {
			// If TCPMux is enabled, create an fmux session for handling multiple streams.
			// 如果启用了TCPMux，创建一个fmux会话以处理多个流。
			if svr.cfg.TCPMux {
				fmuxCfg := fmux.DefaultConfig()
				fmuxCfg.KeepAliveInterval = time.Duration(svr.cfg.TCPMuxKeepaliveInterval) * time.Second
				fmuxCfg.LogOutput = io.Discard
				session, err := fmux.Server(frpConn, fmuxCfg)
				if err != nil {
					log.Warn("Failed to create mux connection: %v", err)
					frpConn.Close()
					return
				}

				// Accept and handle each stream within the fmux session.
				// 接受并处理fmux会话中的每个流。
				for {
					stream, err := session.AcceptStream()
					if err != nil {
						log.Debug("Accept new mux stream error: %v", err)
						session.Close()
						return
					}
					go svr.handleConnection(ctx, stream)
				}
			} else {
				// Handle the connection without multiplexing if TCPMux is not enabled.
				// 如果未启用TCPMux，则不使用多路复用来处理连接。
				svr.handleConnection(ctx, frpConn)
			}
		}(ctx, c)
	}
}

func (svr *Service) HandleQUICListener(l quic.Listener) {
	// Listen for incoming connections from client.
	for {
		c, err := l.Accept(context.Background())
		if err != nil {
			log.Warn("QUICListener for incoming connections from client closed")
			return
		}
		// Start a new goroutine to handle connection.
		go func(ctx context.Context, frpConn quic.Connection) {
			for {
				stream, err := frpConn.AcceptStream(context.Background())
				if err != nil {
					log.Debug("Accept new quic mux stream error: %v", err)
					_ = frpConn.CloseWithError(0, "")
					return
				}
				go svr.handleConnection(ctx, frpNet.QuicStreamToNetConn(stream, frpConn))
			}
		}(context.Background(), c)
	}
}

func (svr *Service) RegisterControl(ctlConn net.Conn, loginMsg *msg.Login) (err error) {
	// If client's RunID is empty, it's a new client, we just create a new controller.
	// Otherwise, we check if there is one controller has the same run id. If so, we release previous controller and start new one.
	// 如果客户端的 RunID 为空，表示一个新客户端，我们只需创建一个新的控制器。
	// 否则，我们检查是否有一个具有相同运行ID的控制器。如果是这样，我们会释放之前的控制器并启动新的控制器。
	if loginMsg.RunID == "" {
		loginMsg.RunID, err = util.RandID()
		if err != nil {
			return
		}
	}

	ctx := frpNet.NewContextFromConn(ctlConn)
	xl := xlog.FromContextSafe(ctx)
	xl.AppendPrefix(loginMsg.RunID)
	ctx = xlog.NewContext(ctx, xl)
	xl.Info("client login info: ip [%s] version [%s] hostname [%s] os [%s] arch [%s]",
		ctlConn.RemoteAddr().String(), loginMsg.Version, loginMsg.Hostname, loginMsg.Os, loginMsg.Arch)

	// Check client version.
	// 检查客户端版本。
	if ok, msg := version.Compat(loginMsg.Version); !ok {
		err = fmt.Errorf("%s", msg)
		return
	}

	// Check auth.
	// 检查认证。
	if err = svr.authVerifier.VerifyLogin(loginMsg); err != nil {
		return
	}

	ctl := NewControl(ctx, svr.rc, svr.pxyManager, svr.pluginManager, svr.authVerifier, ctlConn, loginMsg, svr.cfg)
	if oldCtl := svr.ctlManager.Add(loginMsg.RunID, ctl); oldCtl != nil {
		oldCtl.allShutdown.WaitDone()
	}

	//开启login的所有读写等进程
	ctl.Start()

	// for statistics
	// 用于统计
	metrics.Server.NewClient()

	go func() {
		// block until control closed
		// 阻塞直到控制器关闭
		ctl.WaitClosed()
		svr.ctlManager.Del(loginMsg.RunID, ctl)
	}()
	return
}

// RegisterWorkConn register a new work connection to control and proxies need it.
func (svr *Service) RegisterWorkConn(workConn net.Conn, newMsg *msg.NewWorkConn) error {
	xl := frpNet.NewLogFromConn(workConn)
	ctl, exist := svr.ctlManager.GetByID(newMsg.RunID)
	if !exist {
		xl.Warn("No client control found for run id [%s]", newMsg.RunID)
		return fmt.Errorf("no client control found for run id [%s]", newMsg.RunID)
	}
	// server plugin hook
	content := &plugin.NewWorkConnContent{
		User: plugin.UserInfo{
			User:  ctl.loginMsg.User,
			Metas: ctl.loginMsg.Metas,
			RunID: ctl.loginMsg.RunID,
		},
		NewWorkConn: *newMsg,
	}
	retContent, err := svr.pluginManager.NewWorkConn(content)
	if err == nil {
		newMsg = &retContent.NewWorkConn
		// Check auth.
		err = svr.authVerifier.VerifyNewWorkConn(newMsg)
	}
	if err != nil {
		xl.Warn("invalid NewWorkConn with run id [%s]", newMsg.RunID)
		_ = msg.WriteMsg(workConn, &msg.StartWorkConn{
			Error: util.GenerateResponseErrorString("invalid NewWorkConn", err, ctl.serverCfg.DetailedErrorsToClient),
		})
		return fmt.Errorf("invalid NewWorkConn with run id [%s]", newMsg.RunID)
	}
	return ctl.RegisterWorkConn(workConn)
}

func (svr *Service) RegisterVisitorConn(visitorConn net.Conn, newMsg *msg.NewVisitorConn) error {
	return svr.rc.VisitorManager.NewConn(newMsg.ProxyName, visitorConn, newMsg.Timestamp, newMsg.SignKey,
		newMsg.UseEncryption, newMsg.UseCompression)
}
