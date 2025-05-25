package client

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/international/congestion"
	"github.com/apernet/quic-go"
)

const (
	defaultStreamReceiveWindow = 8388608                            // 8MB
	defaultConnReceiveWindow   = defaultStreamReceiveWindow * 5 / 2 // 20MB
	defaultMaxIdleTimeout      = 30 * time.Second
	defaultKeepAlivePeriod     = 10 * time.Second
)

type Config struct {
	ConnFactory      ConnFactory
	ServerAddr       net.Addr
	Auth             string
	TLSConfig        *tls.Config
	QUICConfig       *quic.Config
	CongestionConfig CongestionConfig
	BandwidthConfig  BandwidthConfig
	FastOpen         bool

	filled bool // whether the fields have been verified and filled
}

// verifyAndFill fills the fields that are not set by the user with default values when possible,
// and returns an error if the user has not set a required field or has set an invalid value.
func (c *Config) verifyAndFill() error {
	if c.filled {
		return nil
	}
	if c.ConnFactory == nil {
		c.ConnFactory = &udpConnFactory{}
	}
	if c.ServerAddr == nil {
		return errors.ConfigError{Field: "ServerAddr", Reason: "must be set"}
	}
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

	c.filled = true
	return nil
}

type ConnFactory interface {
	New(net.Addr) (net.PacketConn, error)
}

type udpConnFactory struct{}

func (f *udpConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	return net.ListenUDP("udp", nil)
}

type CongestionConfig struct {
	Type       string
	BBRProfile string
}

// BandwidthConfig describes the maximum bandwidth that the server can use, in bytes per second.
type BandwidthConfig struct {
	MaxTx uint64
	MaxRx uint64
}
