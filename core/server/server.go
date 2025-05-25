package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"sync"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"

	"github.com/apernet/hysteria/core/v2/internal/congestion"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/internal/utils"
)

const (
	closeErrCodeOK = 0x100 // HTTP3 ErrCodeNoError
)

type Server interface {
	Serve() error
	Close() error
}

func convertToStdTLSConfig(config *Config) *tls.Config {
	var clientAuth tls.ClientAuthType
	if config.TLSConfig.ClientCAs != nil {
		clientAuth = tls.RequireAndVerifyClientCert
	} else {
		clientAuth = tls.NoClientCert
	}
	return http3.ConfigureTLSConfig(&tls.Config{
		Certificates:   config.TLSConfig.Certificates,
		GetCertificate: config.TLSConfig.GetCertificate,
		ClientCAs:      config.TLSConfig.ClientCAs,
		ClientAuth:     clientAuth,
	})
}

func NewServer(config *Config) (Server, error) {
	if err := config.fill(); err != nil {
		return nil, err
	}
	tlsConfig := convertToStdTLSConfig(config)
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     config.QUICConfig.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         config.QUICConfig.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: config.QUICConfig.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     config.QUICConfig.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 config.QUICConfig.MaxIdleTimeout,
		MaxIncomingStreams:             config.QUICConfig.MaxIncomingStreams,
		DisablePathMTUDiscovery:        config.QUICConfig.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           protocol.MaxDatagramFrameSize,
		AssumePeerMaxDatagramFrameSize: protocol.MaxDatagramFrameSize,
		DisablePathManager:             true,
	}
	tr := &quic.Transport{Conn: config.Conn}
	listener, err := tr.Listen(tlsConfig, quicConfig)
	if err != nil {
		err = errors.Join(err, tr.Close(), config.Conn.Close())
		return nil, err
	}
	return &serverImpl{
		config:   config,
		tr:       tr,
		listener: listener,
	}, nil
}

type serverImpl struct {
	config   *Config
	tr       *quic.Transport
	listener *quic.Listener
}

func (s *serverImpl) Serve() error {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleClient(conn)
	}
}

func (s *serverImpl) Close() error {
	err := errors.Join(s.listener.Close(), s.tr.Close(), s.config.Conn.Close())
	return err
}

func (s *serverImpl) handleClient(conn *quic.Conn) {
	handler := newH3sHandler(s.config, conn)
	h3s := http3.Server{
		Handler:          handler,
		StreamDispatcher: handler.ProxyStreamHijacker,
	}
	_ = h3s.ServeQUICConn(conn)
	_ = conn.CloseWithError(closeErrCodeOK, "")
}

type h3sHandler struct {
	config *Config
	conn   *quic.Conn

	authenticated bool
	authMutex     sync.Mutex

	udpSM *udpSessionManager // Only set after authentication
}

func newH3sHandler(config *Config, conn *quic.Conn) *h3sHandler {
	return &h3sHandler{
		config: config,
		conn:   conn,
	}
}

func (h *h3sHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Host == protocol.URLHost && r.URL.Path == protocol.URLPath {
		h.authMutex.Lock()
		defer h.authMutex.Unlock()
		if h.authenticated {
			// Already authenticated
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !h.config.DisableUDP,
				Rx:         h.config.BandwidthConfig.MaxRx,
				RxAuto:     h.config.IgnoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			return
		}
		authReq := protocol.AuthRequestFromHeader(r.Header)
		actualTx := authReq.Rx
		ok, _ := h.config.Authenticator.Authenticate(h.conn.RemoteAddr(), authReq.Auth, actualTx)
		if ok {
			// Set authenticated flag
			h.authenticated = true
			if h.config.IgnoreClientBandwidth {
				// Ignore client bandwidth and use the configured congestion controller.
				congestion.UseConfigured(h.conn, h.config.CongestionConfig.Type, h.config.CongestionConfig.BBRProfile)
				actualTx = 0
			} else {
				// actualTx = min(serverTx, clientRx)
				if h.config.BandwidthConfig.MaxTx > 0 && actualTx > h.config.BandwidthConfig.MaxTx {
					// We have a maxTx limit and the client is asking for more than that,
					// return and use the limit instead
					actualTx = h.config.BandwidthConfig.MaxTx
				}
				if actualTx > 0 {
					congestion.UseBrutal(h.conn, actualTx)
				} else {
					// Client doesn't know its own bandwidth, use the configured congestion controller.
					congestion.UseConfigured(h.conn, h.config.CongestionConfig.Type, h.config.CongestionConfig.BBRProfile)
				}
			}
			// Auth OK, send response
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !h.config.DisableUDP,
				Rx:         h.config.BandwidthConfig.MaxRx,
				RxAuto:     h.config.IgnoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			// Initialize UDP session manager (if UDP is enabled)
			// We use sync.Once to make sure that only one goroutine is started,
			// as ServeHTTP may be called by multiple goroutines simultaneously
			if !h.config.DisableUDP {
				go func() {
					sm := newUDPSessionManager(&udpIOImpl{h.conn, h.config.Outbound}, h.config.UDPIdleTimeout)
					h.udpSM = sm
					go sm.Run()
				}()
			}
		} else {
			// Auth failed, pretend to be a normal HTTP server
			h.masqHandler(w, r)
		}
	} else {
		// Not an auth request, pretend to be a normal HTTP server
		h.masqHandler(w, r)
	}
}

func (h *h3sHandler) ProxyStreamHijacker(ft http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	if err != nil || !h.authenticated {
		return false, nil
	}

	switch ft {
	case protocol.FrameTypeTCPRequest:
		// StreamDispatcher only peeks the frame type. Consume it so ReadTCPRequest
		// starts at address length, matching pre-upgrade StreamHijacker behavior.
		if _, err := quicvarint.Read(quicvarint.NewReader(stream)); err != nil {
			return false, err
		}
		// Wraps the stream with QStream, which handles Close() properly
		qStream := &utils.QStream{Stream: stream}
		go h.handleTCPRequest(qStream)
		return true, nil
	default:
		return false, nil
	}
}

func (h *h3sHandler) handleTCPRequest(stream *utils.QStream) {
	// Read request
	reqAddr, err := protocol.ReadTCPRequest(stream)
	if err != nil {
		_ = stream.Close()
		return
	}
	// Dial target
	tConn, err := h.config.Outbound.TCP(reqAddr)
	if err != nil {
		_ = protocol.WriteTCPResponse(stream, false, err.Error())
		_ = stream.Close()
		return
	}
	_ = protocol.WriteTCPResponse(stream, true, "Connected")
	// Start proxying
	_ = copyTwoWay(stream, tConn)
	// Cleanup
	_ = tConn.Close()
	_ = stream.Close()
}

func (h *h3sHandler) masqHandler(w http.ResponseWriter, r *http.Request) {
	if h.config.MasqHandler != nil {
		h.config.MasqHandler.ServeHTTP(w, r)
	} else {
		// Return 404 for everything
		http.NotFound(w, r)
	}
}

// udpIOImpl is the IO implementation for udpSessionManager
type udpIOImpl struct {
	Conn     *quic.Conn
	Outbound Outbound
}

func (io *udpIOImpl) ReceiveMessage() (*protocol.UDPMessage, error) {
	for {
		msg, err := io.Conn.ReceiveDatagram(context.Background())
		if err != nil {
			// Connection error, this will stop the session manager
			return nil, err
		}
		udpMsg, err := protocol.ParseUDPMessage(msg)
		if err != nil {
			// Invalid message, this is fine - just wait for the next
			continue
		}
		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		// Message larger than buffer, silent drop
		return nil
	}
	return io.Conn.SendDatagram(buf[:msgN])
}

func (io *udpIOImpl) UDP(reqAddr string) (UDPConn, error) {
	return io.Outbound.UDP(reqAddr)
}
