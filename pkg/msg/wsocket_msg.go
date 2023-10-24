package msg

import (
	"fmt"
	"time"
)

const (
	Login_status_t     string = "200:客户端注册上线请求"
	Proxy_status_t     string = "200:客户端代理上线请求"
	PingConn_status_f  string = "500:客户端连接下线"
	PingProxy_status_f string = "500:客户端代理下线"
)

func ScLogin(RunID string, Timestamp string, ClientAddress string, User string, PrivilegeKey string, status string) string {
	return fmt.Sprintf(`
	{
		"msgtype": "markdown",
		"markdown": {
			"content": "消息提醒<font color=\"warning\">客户端注册信息</font>\n
			 >RunID:<font color=\"comment\">%s</font>
			 >时间:<font color=\"comment\">%s</font>
			 >客户端地址:<font color=\"comment\">%s</font>"
			 >用户:<font color=\"comment\">%s</font>"
			 >用户密码:<font color=\"comment\">%s</font>"
			 >当前状态:<font color=\"comment\">%s</font>"
		}
	}`, RunID, Timestamp, ClientAddress, User, PrivilegeKey, status)
}

func ScProxy(RunID string, ProxyType string, ProxyName string, SubDomain string, Port int, HttpUser string, HttpPwd string, status string) string {

	return fmt.Sprintf(`
	{
		"msgtype": "markdown",
		"markdown": {
			"content": "消息提醒<font color=\"warning\">客户端代理信息</font>\n
			 >RunID:<font color=\"comment\">%s</font>
			 >代理类型:<font color=\"comment\">%s</font>
			 >代理名:<font color=\"comment\">%s</font>"
			 >SubDomain:<font color=\"comment\">%s</font>"
			 >Port:<font color=\"comment\">%d</font>"
			 >HttpUser:<font color=\"comment\">%s</font>"
			 >HttpPwd:<font color=\"comment\">%s</font>"
			 >当前状态:<font color=\"comment\">%s</font>"
		}
	}`, RunID, ProxyType, ProxyName, SubDomain, Port, HttpUser, HttpPwd, status)

}

func ScConnDisconnect(RunID string, ClientAddress string, status string) string {

	return fmt.Sprintf(`
	{
		"msgtype": "markdown",
		"markdown": {
			"content": "消息提醒<font color=\"warning\">Ping连接下线</font>\n
			 >RunID:<font color=\"comment\">%s</font>
			 >客户端地址:<font color=\"comment\">%s</font>"
			 >当前状态:<font color=\"comment\">%s</font>"
		}
	}`, RunID, ClientAddress, status)

}

func ScProxyDisconnect(RunID string, ClientAddress string, status string) string {

	return fmt.Sprintf(`
	{
		"msgtype": "markdown",
		"markdown": {
			"content": "消息提醒<font color=\"warning\">Ping代理下线</font>\n
			 >RunID:<font color=\"comment\">%s</font>
			 >客户端地址:<font color=\"comment\">%s</font>"
			 >当前状态:<font color=\"comment\">%s</font>"
		}
	}`, RunID, ClientAddress, status)

}

func TimeToString(Timestamp int64) string {
	t := time.Unix(Timestamp, 0)
	timeString := t.Format("2006-01-02 15:04:05")
	return timeString
}
