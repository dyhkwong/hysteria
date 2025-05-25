package server

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/international/congestion"
	"github.com/apernet/hysteria/core/v2/international/utils"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

const (
	defaultStreamReceiveWindow = 8388608                            // 8MB
	defaultConnReceiveWindow   = defaultStreamReceiveWindow * 5 / 2 // 20MB
	defaultMaxIdleTimeout      = 30 * time.Second
	defaultMaxIncomingStreams  = 1024
	defaultUDPIdleTimeout      = 60 * time.Second
)

type Config struct {
	TLSConfig             *tls.Config
	QUICConfig            *quic.Config
	Conn                  net.PacketConn
	Outbound              Outbound
	CongestionConfig      CongestionConfig
	BandwidthConfig       BandwidthConfig
	IgnoreClientBandwidth bool
	DisableUDP            bool
	UDPIdleTimeout        time.Duration
	Authenticator         Authenticator
	MasqHandler           http.Handler

	StreamHijacker     func(http3.FrameType, *quic.Conn, *utils.QStream, error) (hijacked bool, err error)
	UdpSessionHijacker func(*UdpSessionEntry, string)
}

// fill fills the fields that are not set by the user with default values when possible,
// and returns an error if the user has not set a required field, or if a field is invalid.
func (c *Config) fill() error {
	var err error
	c.CongestionConfig.Type, err = congestion.NormalizeType(c.CongestionConfig.Type)
	if err != nil {
		return errors.ConfigError{Field: "CongestionConfig.Type", Reason: err.Error()}
	}
	if c.CongestionConfig.Type == congestion.TypeBBR {
		c.CongestionConfig.BBRProfile, err = congestion.NormalizeBBRProfile(c.CongestionConfig.BBRProfile)
		if err != nil {
			return errors.ConfigError{Field: "CongestionConfig.BBRProfile", Reason: err.Error()}
		}
	}
	if c.Conn == nil {
		return errors.ConfigError{Field: "Conn", Reason: "must be set"}
	}
	if c.Outbound == nil {
		c.Outbound = &defaultOutbound{}
	}
	if c.BandwidthConfig.MaxTx != 0 && c.BandwidthConfig.MaxTx < 65536 {
		return errors.ConfigError{Field: "BandwidthConfig.MaxTx", Reason: "must be at least 65536"}
	}
	if c.BandwidthConfig.MaxRx != 0 && c.BandwidthConfig.MaxRx < 65536 {
		return errors.ConfigError{Field: "BandwidthConfig.MaxRx", Reason: "must be at least 65536"}
	}
	if c.UDPIdleTimeout == 0 {
		c.UDPIdleTimeout = defaultUDPIdleTimeout
	} else if c.UDPIdleTimeout < 2*time.Second || c.UDPIdleTimeout > 600*time.Second {
		return errors.ConfigError{Field: "UDPIdleTimeout", Reason: "must be between 2s and 600s"}
	}
	if c.Authenticator == nil {
		return errors.ConfigError{Field: "Authenticator", Reason: "must be set"}
	}
	return nil
}

type CongestionConfig struct {
	Type       string
	BBRProfile string
}

// Outbound provides the implementation of how the server should connect to remote servers.
// Although UDP includes a reqAddr, the implementation does not necessarily have to use it
// to make a "connected" UDP connection that does not accept packets from other addresses.
// In fact, the default implementation simply uses net.ListenUDP for a "full-cone" behavior.
type Outbound interface {
	TCP(reqAddr string) (net.Conn, error)
	UDP(reqAddr string) (UDPConn, error)
}

// UDPConn is like net.PacketConn, but uses string for addresses.
type UDPConn interface {
	ReadFrom(b []byte) (int, string, error)
	WriteTo(b []byte, addr string) (int, error)
	Close() error
}

type defaultOutbound struct{}

var defaultOutboundDialer = net.Dialer{
	Timeout: 10 * time.Second,
}

func (o *defaultOutbound) TCP(reqAddr string) (net.Conn, error) {
	return defaultOutboundDialer.Dial("tcp", reqAddr)
}

func (o *defaultOutbound) UDP(reqAddr string) (UDPConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &defaultUDPConn{conn}, nil
}

type defaultUDPConn struct {
	*net.UDPConn
}

func (c *defaultUDPConn) ReadFrom(b []byte) (int, string, error) {
	n, addr, err := c.UDPConn.ReadFrom(b)
	if addr != nil {
		return n, addr.String(), err
	} else {
		return n, "", err
	}
}

func (c *defaultUDPConn) WriteTo(b []byte, addr string) (int, error) {
	uAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, err
	}
	return c.UDPConn.WriteTo(b, uAddr)
}

// BandwidthConfig describes the maximum bandwidth that the server can use, in bytes per second.
type BandwidthConfig struct {
	MaxTx uint64
	MaxRx uint64
}

// Authenticator is an interface that provides authentication logic.
type Authenticator interface {
	Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string)
}
