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

package client

import (
	"context"
	"io"
	"net"
	"runtime/debug"
	"time"

	"github.com/fatedier/golib/control/shutdown"
	"github.com/fatedier/golib/crypto"

	"github.com/fatedier/frp/client/proxy"
	"github.com/fatedier/frp/pkg/auth"
	"github.com/fatedier/frp/pkg/config"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/xlog"
)

type Control struct {
	// uniq id got from frps, attach it in loginMsg
	runID string

	// manage all proxies
	pxyCfgs map[string]config.ProxyConf
	pm      *proxy.Manager

	// manage all visitors
	vm *VisitorManager

	// control connection
	conn net.Conn

	cm *ConnectionManager

	// put a message in this channel to send it over control connection to server
	sendCh chan (msg.Message)

	// read from this channel to get the next message sent by server
	readCh chan (msg.Message)

	// goroutines can block by reading from this channel, it will be closed only in reader() when control connection is closed
	closedCh chan struct{}

	closedDoneCh chan struct{}

	// last time got the Pong message
	lastPong time.Time

	// The client configuration
	clientCfg config.ClientCommonConf

	readerShutdown     *shutdown.Shutdown
	writerShutdown     *shutdown.Shutdown
	msgHandlerShutdown *shutdown.Shutdown

	// The UDP port that the server is listening on
	serverUDPPort int

	xl *xlog.Logger

	// service context
	ctx context.Context

	// sets authentication based on selected method
	authSetter auth.Setter
}

// NewControl 创建一个新的 Control 实例，用于管理与服务器的通信、代理配置和访客配置。
func NewControl(
	ctx context.Context, runID string, conn net.Conn, cm *ConnectionManager,
	clientCfg config.ClientCommonConf,
	pxyCfgs map[string]config.ProxyConf,
	visitorCfgs map[string]config.VisitorConf,
	serverUDPPort int,
	authSetter auth.Setter,
) *Control {
	// 创建一个新的 xlog 实例用于日志记录
	ctl := &Control{
		runID:              runID,                       // 运行ID，用于标识连接
		conn:               conn,                        // 与服务器的连接
		cm:                 cm,                          // 连接管理器，用于处理连接
		pxyCfgs:            pxyCfgs,                     // 代理配置
		sendCh:             make(chan msg.Message, 100), // 发送消息的通道
		readCh:             make(chan msg.Message, 100), // 接收消息的通道
		closedCh:           make(chan struct{}),         // 关闭通道
		closedDoneCh:       make(chan struct{}),         // 关闭完成通道
		clientCfg:          clientCfg,                   // 客户端配置
		readerShutdown:     shutdown.New(),              // 读取器关闭控制
		writerShutdown:     shutdown.New(),              // 写入器关闭控制
		msgHandlerShutdown: shutdown.New(),              // 消息处理器关闭控制
		serverUDPPort:      serverUDPPort,               // 服务器UDP端口
		xl:                 xlog.FromContextSafe(ctx),   // xlog 日志实例
		ctx:                ctx,                         // 上下文
		authSetter:         authSetter,                  // 认证设置
	}

	// 创建代理管理器，用于管理代理配置和状态
	ctl.pm = proxy.NewManager(ctl.ctx, ctl.sendCh, clientCfg, serverUDPPort)

	// 创建访客管理器，用于管理访客配置和状态，并加载访客配置
	ctl.vm = NewVisitorManager(ctl.ctx, ctl)
	ctl.vm.Reload(visitorCfgs)

	return ctl
}

// Run 启动控制器的主要运行逻辑。
func (ctl *Control) Run() {
	// 启动控制器的 worker
	go ctl.worker()

	// 启动所有代理配置
	ctl.pm.Reload(ctl.pxyCfgs)

	// 启动所有访客配置
	go ctl.vm.Run()
}

// HandleReqWorkConn 函数用于处理 msg.ReqWorkConn 消息
func (ctl *Control) HandleReqWorkConn(inMsg *msg.ReqWorkConn) {
	// 获取与控制器相关联的日志记录器（xl）
	xl := ctl.xl

	// 尝试与服务器建立新的连接
	workConn, err := ctl.connectServer()
	if err != nil {
		xl.Warn("start new connection to server error: %v", err)
		return
	}

	// 创建一个 NewWorkConn 消息，用于与服务器进行新工作连接的验证
	m := &msg.NewWorkConn{
		RunID: ctl.runID,
	}

	// 设置 NewWorkConn 消息的验证信息
	if err = ctl.authSetter.SetNewWorkConn(m); err != nil {
		xl.Warn("error during NewWorkConn authentication: %v", err)
		return
	}

	// 将 NewWorkConn 消息写入与服务器的工作连接
	if err = msg.WriteMsg(workConn, m); err != nil {
		xl.Warn("work connection write to server error: %v", err)
		workConn.Close()
		return
	}

	// 从服务器接收 StartWorkConn 消息，用于启动工作连接
	var startMsg msg.StartWorkConn
	if err = msg.ReadMsgInto(workConn, &startMsg); err != nil {
		xl.Trace("work connection closed before response StartWorkConn message: %v", err)
		workConn.Close()
		return
	}

	// 如果 StartWorkConn 消息中包含错误信息，记录错误并关闭连接
	if startMsg.Error != "" {
		xl.Error("StartWorkConn contains error: %s", startMsg.Error)
		workConn.Close()
		return
	}

	// 将工作连接分发给相关的代理进行处理
	ctl.pm.HandleWorkConn(startMsg.ProxyName, workConn, &startMsg)
}

// HandleNewProxyResp 函数用于处理 msg.NewProxyResp 消息
func (ctl *Control) HandleNewProxyResp(inMsg *msg.NewProxyResp) {
	// 获取与控制器相关联的日志记录器（xl）
	xl := ctl.xl

	// 服务器将返回 NewProxyResp 消息作为每个 NewProxy 消息的响应。
	// 如果没有错误，启动一个新的代理处理程序
	err := ctl.pm.StartProxy(inMsg.ProxyName, inMsg.RemoteAddr, inMsg.Error)

	// 如果启动代理时发生错误，记录警告信息
	if err != nil {
		xl.Warn("[%s] start error: %v", inMsg.ProxyName, err)
	} else {
		// 否则，代理成功启动，记录信息
		xl.Info("[%s] start proxy success", inMsg.ProxyName)
	}
}

func (ctl *Control) Close() error {
	return ctl.GracefulClose(0)
}

func (ctl *Control) GracefulClose(d time.Duration) error {
	ctl.pm.Close()
	ctl.vm.Close()

	time.Sleep(d)

	ctl.conn.Close()
	ctl.cm.Close()
	return nil
}

// ClosedDoneCh returns a channel which will be closed after all resources are released
func (ctl *Control) ClosedDoneCh() <-chan struct{} {
	return ctl.closedDoneCh
}

// connectServer return a new connection to frps
func (ctl *Control) connectServer() (conn net.Conn, err error) {
	return ctl.cm.Connect()
}

// reader 函数从 frps 读取所有消息并将其发送到 readCh 通道
func (ctl *Control) reader() {
	// 获取与控制器相关联的日志记录器（xl）
	xl := ctl.xl
	defer func() {
		if err := recover(); err != nil {
			xl.Error("panic error: %v", err)
			xl.Error(string(debug.Stack()))
		}
	}()
	defer ctl.readerShutdown.Done()
	defer close(ctl.closedCh)

	// 创建一个加密的读取器，用于解密从连接中读取的消息
	encReader := crypto.NewReader(ctl.conn, []byte(ctl.clientCfg.Token))

	for {
		// 从连接中读取消息
		m, err := msg.ReadMsg(encReader)

		// 检查是否发生了错误
		if err != nil {
			// 如果是 EOF 错误，表示读取结束，退出循环
			if err == io.EOF {
				xl.Debug("read from control connection EOF")
				return
			}

			// 否则，记录读取错误，并关闭连接
			xl.Warn("read error: %v", err)
			ctl.conn.Close()
			return
		}

		// 将读取到的消息发送到 readCh 通道
		ctl.readCh <- m
	}
}

// writer 函数将从 sendCh 通道获取的消息写入 frps
func (ctl *Control) writer() {
	// 获取与控制器相关联的日志记录器（xl）
	xl := ctl.xl
	defer ctl.writerShutdown.Done()

	// 创建一个加密写入器，用于加密消息并写入连接
	encWriter, err := crypto.NewWriter(ctl.conn, []byte(ctl.clientCfg.Token))

	// 检查是否创建加密写入器时发生错误
	if err != nil {
		xl.Error("crypto new writer error: %v", err)
		ctl.conn.Close()
		return
	}

	for {
		// 从 sendCh 通道中获取消息
		m, ok := <-ctl.sendCh

		// 检查通道是否已关闭，如果已关闭，writer 函数结束
		if !ok {
			xl.Info("control writer is closing")
			return
		}

		// 将消息通过加密写入器写入到连接中
		if err := msg.WriteMsg(encWriter, m); err != nil {
			xl.Warn("write message to control connection error: %v", err)
			return
		}
	}
}

// msgHandler函数用于处理控制器的各种通道事件
func (ctl *Control) msgHandler() {
	// 获取与控制器相关联的日志记录器（xl）
	xl := ctl.xl

	// 在函数结束时执行清理和恢复工作
	defer func() {
		// 恢复并处理恢复的错误，如果有的话
		if err := recover(); err != nil {
			// 记录错误信息到日志
			xl.Error("panic error: %v", err)
			// 打印调用栈信息
			xl.Error(string(debug.Stack()))
		}
	}()

	// 在函数结束时标记消息处理完成
	defer ctl.msgHandlerShutdown.Done()

	var hbSendCh <-chan time.Time
	// 如果心跳间隔大于0，则创建心跳发送通道
	if ctl.clientCfg.HeartbeatInterval > 0 {
		hbSend := time.NewTicker(time.Duration(ctl.clientCfg.HeartbeatInterval) * time.Second)
		defer hbSend.Stop()
		hbSendCh = hbSend.C
	}

	var hbCheckCh <-chan time.Time
	// 只有在TCPMux未启用且用户未禁用心跳功能时，才检查心跳超时
	if ctl.clientCfg.HeartbeatInterval > 0 && ctl.clientCfg.HeartbeatTimeout > 0 && !ctl.clientCfg.TCPMux {
		hbCheck := time.NewTicker(time.Second)
		defer hbCheck.Stop()
		hbCheckCh = hbCheck.C
	}

	// 记录上次接收到心跳消息的时间
	ctl.lastPong = time.Now()

	// 进入无限循环，处理不同的事件
	for {
		select {
		case <-hbSendCh:
			// 发送心跳消息到服务器
			xl.Debug("send heartbeat to server")
			pingMsg := &msg.Ping{}

			// 设置心跳消息的验证信息
			if err := ctl.authSetter.SetPing(pingMsg); err != nil {
				xl.Warn("error during ping authentication: %v", err)
				return
			}

			// 将心跳消息发送到控制器的发送通道
			ctl.sendCh <- pingMsg

		case <-hbCheckCh:
			// 如果超过心跳超时时间，记录错误并关闭连接，让reader()停止
			if time.Since(ctl.lastPong) > time.Duration(ctl.clientCfg.HeartbeatTimeout)*time.Second {
				xl.Warn("heartbeat timeout")
				ctl.conn.Close()
				return
			}

		case rawMsg, ok := <-ctl.readCh:
			if !ok {
				return
			}

			// 根据不同类型的消息执行不同的操作
			switch m := rawMsg.(type) {
			case *msg.ReqWorkConn:
				// 处理请求工作连接消息
				go ctl.HandleReqWorkConn(m)

			case *msg.NewProxyResp:
				// 处理新代理响应消息
				ctl.HandleNewProxyResp(m)

			case *msg.Pong:
				// 处理Pong消息，这是心跳的响应消息
				if m.Error != "" {
					xl.Error("Pong contains error: %s", m.Error)
					ctl.conn.Close()
					return
				}
				// 更新上次接收到心跳消息的时间
				ctl.lastPong = time.Now()
				xl.Debug("receive heartbeat from server")
			}
		}
	}
}

// 如果控制器通过 closedCh 被通知，读取、写入和处理程序将退出
// worker 是 Control 的主要工作函数。
func (ctl *Control) worker() {
	// 启动消息处理、读取和写入协程以并行执行。
	go ctl.msgHandler()
	go ctl.reader()
	go ctl.writer()

	// 等待 closedCh 信号。当 closedCh 被关闭时，表示控制器要退出。

	<-ctl.closedCh

	// 关闭 readCh 通道，通知读取协程停止读取数据。
	close(ctl.readCh)
	ctl.readerShutdown.WaitDone() // 等待读取协程完成。
	ctl.msgHandlerShutdown.WaitDone()
	// 关闭 sendCh 通道，通知写入协程停止写入数据。
	close(ctl.sendCh)
	ctl.writerShutdown.WaitDone() // 等待写入协程完成。

	// 通过关闭 pm 和 vm 关闭代理和访问服务。
	ctl.pm.Close()
	ctl.vm.Close()

	// 关闭 closedDoneCh 通道，表示控制器已完成所有工作。

	close(ctl.closedDoneCh)

	// 关闭连接管理器（cm）以结束控制器的运行。
	ctl.cm.Close()
}

func (ctl *Control) ReloadConf(pxyCfgs map[string]config.ProxyConf, visitorCfgs map[string]config.VisitorConf) error {
	ctl.vm.Reload(visitorCfgs)
	ctl.pm.Reload(pxyCfgs)
	return nil
}
