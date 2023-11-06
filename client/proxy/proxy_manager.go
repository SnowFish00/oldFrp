package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/fatedier/golib/errors"

	"github.com/fatedier/frp/client/event"
	"github.com/fatedier/frp/pkg/config"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/xlog"
)

type Manager struct {
	sendCh  chan (msg.Message)
	proxies map[string]*Wrapper

	closed bool
	mu     sync.RWMutex

	clientCfg config.ClientCommonConf

	// The UDP port that the server is listening on
	serverUDPPort int

	ctx context.Context
}

func NewManager(ctx context.Context, msgSendCh chan (msg.Message), clientCfg config.ClientCommonConf, serverUDPPort int) *Manager {
	return &Manager{
		sendCh:        msgSendCh,
		proxies:       make(map[string]*Wrapper),
		closed:        false,
		clientCfg:     clientCfg,
		serverUDPPort: serverUDPPort,
		ctx:           ctx,
	}
}

func (pm *Manager) StartProxy(name string, remoteAddr string, serverRespErr string) error {
	pm.mu.RLock()
	pxy, ok := pm.proxies[name]
	pm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("proxy [%s] not found", name)
	}

	err := pxy.SetRunningStatus(remoteAddr, serverRespErr)
	if err != nil {
		return err
	}
	return nil
}

func (pm *Manager) Close() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for _, pxy := range pm.proxies {
		pxy.Stop()
	}
	pm.proxies = make(map[string]*Wrapper)
}

func (pm *Manager) HandleWorkConn(name string, workConn net.Conn, m *msg.StartWorkConn) {
	pm.mu.RLock()
	pw, ok := pm.proxies[name]
	pm.mu.RUnlock()
	if ok {
		pw.InWorkConn(workConn, m)
	} else {
		workConn.Close()
	}
}

func (pm *Manager) HandleEvent(payload interface{}) error {
	var m msg.Message
	switch e := payload.(type) {
	case *event.StartProxyPayload:
		m = e.NewProxyMsg
	case *event.CloseProxyPayload:
		m = e.CloseProxyMsg
	default:
		return event.ErrPayloadType
	}

	err := errors.PanicToError(func() {
		pm.sendCh <- m
	})
	return err
}

func (pm *Manager) GetAllProxyStatus() []*WorkingStatus {
	ps := make([]*WorkingStatus, 0)
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for _, pxy := range pm.proxies {
		ps = append(ps, pxy.GetStatus())
	}
	return ps
}

func (pm *Manager) Reload(pxyCfgs map[string]config.ProxyConf) {
	xl := xlog.FromContextSafe(pm.ctx)
	pm.mu.Lock()         // 锁定代理管理器，以确保同一时刻只有一个线程可以进行配置更新
	defer pm.mu.Unlock() // 在函数返回时释放锁资源

	delPxyNames := make([]string, 0) // 存储需要删除的代理名称列表
	for name, pxy := range pm.proxies {
		del := false
		cfg, ok := pxyCfgs[name] // 获取新配置中是否存在相同名称的代理配置
		if !ok {                 // 如果新配置中不存在同名代理，则需要删除该代理
			del = true
		} else if !pxy.Cfg.Compare(cfg) { // 如果代理的配置与新配置不同，也需要删除该代理
			del = true
		}

		if del { // 如果需要删除该代理
			delPxyNames = append(delPxyNames, name) // 记录需要删除的代理名称
			delete(pm.proxies, name)                // 从代理管理器中移除该代理

			pxy.Stop() // 停止代理服务
		}
	}
	if len(delPxyNames) > 0 {
		xl.Info("proxy removed: %v", delPxyNames) // 记录被删除的代理信息
	}

	addPxyNames := make([]string, 0) // 存储需要添加的代理名称列表
	for name, cfg := range pxyCfgs {
		if _, ok := pm.proxies[name]; !ok { // 如果代理管理器中不存在同名代理，说明是新代理
			pxy := NewWrapper(pm.ctx, cfg, pm.clientCfg, pm.HandleEvent, pm.serverUDPPort) // 创建新代理实例
			pm.proxies[name] = pxy                                                         // 将新代理添加到代理管理器中
			addPxyNames = append(addPxyNames, name)                                        // 记录需要添加的代理名称

			pxy.Start() // 启动新代理服务
		}
	}
	if len(addPxyNames) > 0 {
		//删除回显
		// xl.Info("proxy added: %v", addPxyNames) // 记录被添加的代理信息
	}
}
