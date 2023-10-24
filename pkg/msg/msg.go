// Copyright 2016 fatedier, fatedier@gmail.com
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

package msg

import (
	"net"
)

const (
	TypeLogin                 = 'o'
	TypeLoginResp             = '1'
	TypeNewProxy              = 'p'
	TypeNewProxyResp          = '2'
	TypeCloseProxy            = 'c'
	TypeNewWorkConn           = 'w'
	TypeReqWorkConn           = 'r'
	TypeStartWorkConn         = 's'
	TypeNewVisitorConn        = 'v'
	TypeNewVisitorConnResp    = '3'
	TypePing                  = 'h'
	TypePong                  = '4'
	TypeUDPPacket             = 'u'
	TypeNatHoleVisitor        = 'i'
	TypeNatHoleClient         = 'n'
	TypeNatHoleResp           = 'm'
	TypeNatHoleClientDetectOK = 'd'
	TypeNatHoleSid            = '5'
)

var msgTypeMap = map[byte]interface{}{
	TypeLogin:                 Login{},
	TypeLoginResp:             LoginResp{},
	TypeNewProxy:              NewProxy{},
	TypeNewProxyResp:          NewProxyResp{},
	TypeCloseProxy:            CloseProxy{},
	TypeNewWorkConn:           NewWorkConn{},
	TypeReqWorkConn:           ReqWorkConn{},
	TypeStartWorkConn:         StartWorkConn{},
	TypeNewVisitorConn:        NewVisitorConn{},
	TypeNewVisitorConnResp:    NewVisitorConnResp{},
	TypePing:                  Ping{},
	TypePong:                  Pong{},
	TypeUDPPacket:             UDPPacket{},
	TypeNatHoleVisitor:        NatHoleVisitor{},
	TypeNatHoleClient:         NatHoleClient{},
	TypeNatHoleResp:           NatHoleResp{},
	TypeNatHoleClientDetectOK: NatHoleClientDetectOK{},
	TypeNatHoleSid:            NatHoleSid{},
}

// When frpc start, client send this message to login to server.
type Login struct {
	Version      string            `json:"sfv,omitempty"`
	Hostname     string            `json:"sfh,omitempty"`
	Os           string            `json:"sfo,omitempty"`
	Arch         string            `json:"sfa,omitempty"`
	User         string            `json:"sfu,omitempty"`
	PrivilegeKey string            `json:"sfpk,omitempty"`
	Timestamp    int64             `json:"sft,omitempty"`
	RunID        string            `json:"sfr,omitempty"`
	Metas        map[string]string `json:"sfm,omitempty"`

	// Some global configures.
	PoolCount int `json:"sfpc,omitempty"`
}

type LoginResp struct {
	Version       string `json:"sfv,omitempty"`
	RunID         string `json:"sfri,omitempty"`
	ServerUDPPort int    `json:"sfsu,omitempty"`
	Error         string `json:"sfe,omitempty"`
}

// When frpc login success, send this message to frps for running a new proxy.
type NewProxy struct {
	ProxyName          string            `json:"sfpn,omitempty"`
	ProxyType          string            `json:"sfpt,omitempty"`
	UseEncryption      bool              `json:"sfue,omitempty"`
	UseCompression     bool              `json:"sfuc,omitempty"`
	BandwidthLimit     string            `json:"sfbl,omitempty"`
	BandwidthLimitMode string            `json:"sfblm,omitempty"`
	Group              string            `json:"sfgp,omitempty"`
	GroupKey           string            `json:"sfgpk,omitempty"`
	Metas              map[string]string `json:"sfm,omitempty"`

	// tcp and udp only
	RemotePort int `json:"sfrp,omitempty"`

	// http and https only
	CustomDomains     []string          `json:"sfcd,omitempty"`
	SubDomain         string            `json:"sfsd,omitempty"`
	Locations         []string          `json:"sfl,omitempty"`
	HTTPUser          string            `json:"sfhu,omitempty"`
	HTTPPwd           string            `json:"sfhp,omitempty"`
	HostHeaderRewrite string            `json:"sfhhr,omitempty"`
	Headers           map[string]string `json:"sfh,omitempty"`
	RouteByHTTPUser   string            `json:"sfrbh,omitempty"`

	// stcp
	Sk string `json:"sfsk,omitempty"`

	// tcpmux
	Multiplexer string `json:"sfmp,omitempty"`
}

type NewProxyResp struct {
	ProxyName  string `json:"sfpn,omitempty"`
	RemoteAddr string `json:"sfra,omitempty"`
	Error      string `json:"sfe,omitempty"`
}

type CloseProxy struct {
	ProxyName string `json:"sfpn,omitempty"`
}

type NewWorkConn struct {
	RunID        string `json:"sfri,omitempty"`
	PrivilegeKey string `json:"sfpk,omitempty"`
	Timestamp    int64  `json:"sft,omitempty"`
}

type ReqWorkConn struct{}

type StartWorkConn struct {
	ProxyName string `json:"sfpn,omitempty"`
	SrcAddr   string `json:"sfsa,omitempty"`
	DstAddr   string `json:"sfda,omitempty"`
	SrcPort   uint16 `json:"sfsp,omitempty"`
	DstPort   uint16 `json:"sfdp,omitempty"`
	Error     string `json:"sfe,omitempty"`
}

type NewVisitorConn struct {
	ProxyName      string `json:"sfpn,omitempty"`
	SignKey        string `json:"sfsk,omitempty"`
	Timestamp      int64  `json:"sft,omitempty"`
	UseEncryption  bool   `json:"sfue,omitempty"`
	UseCompression bool   `json:"sfuc,omitempty"`
}

type NewVisitorConnResp struct {
	ProxyName string `json:"sfpn,omitempty"`
	Error     string `json:"sfe,omitempty"`
}

type Ping struct {
	PrivilegeKey string `json:"sfpk,omitempty"`
	Timestamp    int64  `json:"sft,omitempty"`
}

type Pong struct {
	Error string `json:"sfe,omitempty"`
}

type UDPPacket struct {
	Content    string       `json:"c,omitempty"`
	LocalAddr  *net.UDPAddr `json:"l,omitempty"`
	RemoteAddr *net.UDPAddr `json:"r,omitempty"`
}

type NatHoleVisitor struct {
	ProxyName string `json:"sfpn,omitempty"`
	SignKey   string `json:"sfsk,omitempty"`
	Timestamp int64  `json:"spt,omitempty"`
}

type NatHoleClient struct {
	ProxyName string `json:"sfpn,omitempty"`
	Sid       string `json:"sfsid,omitempty"`
}

type NatHoleResp struct {
	Sid         string `json:"sfsid,omitempty"`
	VisitorAddr string `json:"sfva,omitempty"`
	ClientAddr  string `json:"sfca,omitempty"`
	Error       string `json:"sfe,omitempty"`
}

type NatHoleClientDetectOK struct{}

type NatHoleSid struct {
	Sid string `json:"sfsid,omitempty"`
}
