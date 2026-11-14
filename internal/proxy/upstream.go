package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/logutil"
)

const (
	upstreamStrategyRandom     = "random"
	upstreamStrategyRoundRobin = "roundrobin"
	upstreamHandshakeTimeout   = 10 * time.Second
	maxProxyResponseHeaderSize = 64 << 10
)

type upstreamRoute interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	RoundTrip(*http.Request) (*http.Response, error)
	CloseIdleConnections()
}

type upstreamPool struct {
	routes      []upstreamRoute
	strategy    string
	randomIndex func(int) int

	selectionMu sync.Mutex
	next        int
}

func newUpstreamPool(dialer Dialer, cfg UpstreamConfig, tlsConfig *tls.Config, randomIndex func(int) int) (*upstreamPool, error) {
	if randomIndex == nil {
		randomIndex = rand.IntN
	}
	if !cfg.Enabled {
		return &upstreamPool{
			routes:      []upstreamRoute{newDirectOutbound(dialer)},
			strategy:    upstreamStrategyRoundRobin,
			randomIndex: randomIndex,
		}, nil
	}
	if len(cfg.Proxies) == 0 {
		return nil, errors.New("at least one upstream proxy is required when upstream routing is enabled")
	}

	strategy := strings.ToLower(strings.TrimSpace(cfg.Strategy))
	if strategy == "" {
		strategy = upstreamStrategyRoundRobin
	}
	if strategy != upstreamStrategyRandom && strategy != upstreamStrategyRoundRobin {
		return nil, fmt.Errorf("unsupported upstream strategy %q", strategy)
	}
	routes := make([]upstreamRoute, 0, len(cfg.Proxies))
	for index, rawURL := range cfg.Proxies {
		route, err := newProxyEndpoint(dialer, rawURL, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("configure upstreams[%d]: %w", index, err)
		}
		routes = append(routes, route)
	}

	return &upstreamPool{
		routes:      routes,
		strategy:    strategy,
		randomIndex: randomIndex,
	}, nil
}

func (p *upstreamPool) RoundTrip(request *http.Request) (*http.Response, error) {
	return p.selectRoute().RoundTrip(request)
}

func (p *upstreamPool) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return p.selectRoute().DialContext(ctx, network, address)
}

func (p *upstreamPool) CloseIdleConnections() {
	for _, route := range p.routes {
		route.CloseIdleConnections()
	}
}

func (p *upstreamPool) selectRoute() upstreamRoute {
	if p.strategy == upstreamStrategyRandom {
		return p.routes[p.randomIndex(len(p.routes))]
	}

	p.selectionMu.Lock()
	route := p.routes[p.next]
	p.next = (p.next + 1) % len(p.routes)
	p.selectionMu.Unlock()
	return route
}

type proxyEndpoint struct {
	dialer    Dialer
	proxyURL  *url.URL
	address   string
	transport *http.Transport
	tlsConfig *tls.Config
}

func newProxyEndpoint(dialer Dialer, rawURL string, tlsConfig *tls.Config) (*proxyEndpoint, error) {
	proxyURL, address, err := parseProxyURL(rawURL)
	if err != nil {
		return nil, err
	}

	transportTLSConfig := cloneTLSConfig(tlsConfig)
	return &proxyEndpoint{
		dialer:    dialer,
		proxyURL:  proxyURL,
		address:   address,
		transport: newHTTPTransport(dialer, http.ProxyURL(proxyURL), transportTLSConfig),
		tlsConfig: transportTLSConfig,
	}, nil
}

func (e *proxyEndpoint) RoundTrip(request *http.Request) (*http.Response, error) {
	return e.transport.RoundTrip(request)
}

func (e *proxyEndpoint) CloseIdleConnections() {
	e.transport.CloseIdleConnections()
}

func (e *proxyEndpoint) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("upstream proxies support only tcp, got %q", network)
	}
	if err := validateConnectTarget(target); err != nil {
		return nil, err
	}

	conn, err := e.dialer.DialContext(ctx, "tcp", e.address)
	if err != nil {
		return nil, fmt.Errorf("dial upstream proxy: %w", err)
	}
	stopCancelClose := context.AfterFunc(ctx, func() {
		logutil.Close("canceled upstream proxy connection", conn)
	})
	fail := func(operationErr error) (net.Conn, error) {
		stopCancelClose()
		if contextErr := ctx.Err(); contextErr != nil {
			operationErr = contextErr
		} else if contextDeadline, ok := ctx.Deadline(); ok && !time.Now().Before(contextDeadline) {
			// The socket timer can fire before the context timer publishes Err.
			var timeoutErr net.Error
			if errors.As(operationErr, &timeoutErr) && timeoutErr.Timeout() {
				operationErr = context.DeadlineExceeded
			}
		}
		return nil, closeProxyAfterError(conn, operationErr)
	}

	deadline := time.Now().Add(upstreamHandshakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fail(fmt.Errorf("set upstream proxy handshake deadline: %w", err))
	}

	tunneled := conn
	if e.proxyURL.Scheme == "https" {
		endpointTLSConfig := e.tlsConfig.Clone()
		endpointTLSConfig.ServerName = e.proxyURL.Hostname()
		tlsConn := tls.Client(conn, endpointTLSConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fail(fmt.Errorf("TLS handshake with upstream proxy: %w", err))
		}
		tunneled = tlsConn
	}

	switch e.proxyURL.Scheme {
	case "http", "https":
		tunneled, err = connectHTTPProxy(tunneled, e.proxyURL.User, target)
	case "socks5", "socks5h":
		err = connectSOCKS5Proxy(tunneled, e.proxyURL.User, target)
	default:
		err = fmt.Errorf("unsupported upstream proxy scheme %q", e.proxyURL.Scheme)
	}
	if err != nil {
		return fail(err)
	}

	if !stopCancelClose() && ctx.Err() != nil {
		return nil, closeProxyAfterError(conn, ctx.Err())
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, closeProxyAfterError(conn, fmt.Errorf("clear upstream proxy handshake deadline: %w", err))
	}
	return tunneled, nil
}

func parseProxyURL(rawURL string) (*url.URL, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, "", errors.New("invalid proxy URL")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme == "socks" {
		parsed.Scheme = "socks5"
	}
	switch parsed.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, "", fmt.Errorf("unsupported proxy scheme %q", parsed.Scheme)
	}
	if parsed.Hostname() == "" || strings.ContainsAny(parsed.Hostname(), " \t\r\n/") {
		return nil, "", errors.New("proxy URL has no valid hostname")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return nil, "", errors.New("proxy URL has an invalid port")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, "", errors.New("proxy URL must not contain a path")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return nil, "", errors.New("proxy URL must not contain a query or fragment")
	}
	if parsed.User != nil && parsed.User.Username() == "" {
		return nil, "", errors.New("proxy username must not be empty")
	}
	if parsed.User != nil && (parsed.Scheme == "socks5" || parsed.Scheme == "socks5h") {
		password, _ := parsed.User.Password()
		if len(parsed.User.Username()) > 255 || len(password) > 255 {
			return nil, "", errors.New("SOCKS username and password must be at most 255 bytes")
		}
	}

	port := parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			port = "1080"
		}
	} else if value, err := strconv.Atoi(port); err != nil || value < 1 || value > 65535 {
		return nil, "", errors.New("proxy port must be between 1 and 65535")
	}
	parsed.Path = ""
	return parsed, net.JoinHostPort(parsed.Hostname(), port), nil
}

func cloneTLSConfig(source *tls.Config) *tls.Config {
	if source == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cloned := source.Clone()
	if cloned.MinVersion == 0 {
		cloned.MinVersion = tls.VersionTLS12
	}
	return cloned
}

func validateConnectTarget(target string) error {
	if strings.ContainsAny(target, "\r\n") {
		return errors.New("CONNECT target contains a control character")
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("CONNECT target must be in host:port form: %w", err)
	}
	if host == "" || strings.ContainsAny(host, " \t\r\n/") {
		return errors.New("CONNECT target must contain a valid hostname")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("CONNECT target port must be between 1 and 65535")
	}
	return nil
}

func connectHTTPProxy(conn net.Conn, user *url.Userinfo, target string) (net.Conn, error) {
	header := make(http.Header)
	header.Set("User-Agent", "")
	if user != nil {
		password, _ := user.Password()
		credentials := user.Username() + ":" + password
		header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
	}
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: header,
	}
	if err := request.Write(conn); err != nil {
		return nil, fmt.Errorf("write HTTP proxy CONNECT request: %w", err)
	}

	limited := &io.LimitedReader{R: conn, N: maxProxyResponseHeaderSize + 1}
	reader := bufio.NewReader(limited)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		if limited.N == 0 {
			return nil, errors.New("HTTP proxy CONNECT response headers are too large")
		}
		return nil, fmt.Errorf("read HTTP proxy CONNECT response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP proxy CONNECT failed with status %d", response.StatusCode)
	}
	if err := response.Body.Close(); err != nil {
		return nil, fmt.Errorf("close HTTP proxy CONNECT response: %w", err)
	}
	return &bufferedProxyConn{Conn: conn, reader: reader}, nil
}

func connectSOCKS5Proxy(conn net.Conn, user *url.Userinfo, target string) error {
	methods := []byte{0x00}
	if user != nil {
		methods = append(methods, 0x02)
	}
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if err := writeAll(conn, greeting); err != nil {
		return fmt.Errorf("write SOCKS5 greeting: %w", err)
	}
	selection := make([]byte, 2)
	if _, err := io.ReadFull(conn, selection); err != nil {
		return fmt.Errorf("read SOCKS5 authentication selection: %w", err)
	}
	if selection[0] != 0x05 {
		return fmt.Errorf("SOCKS5 proxy returned version %d", selection[0])
	}
	switch selection[1] {
	case 0x00:
	case 0x02:
		if user == nil {
			return errors.New("SOCKS5 proxy requested credentials that are not configured")
		}
		if err := authenticateSOCKS5(conn, user); err != nil {
			return err
		}
	case 0xff:
		return errors.New("SOCKS5 proxy rejected all authentication methods")
	default:
		return fmt.Errorf("SOCKS5 proxy selected unsupported authentication method %d", selection[1])
	}

	request, err := socks5ConnectRequest(target)
	if err != nil {
		return err
	}
	if err := writeAll(conn, request); err != nil {
		return fmt.Errorf("write SOCKS5 CONNECT request: %w", err)
	}
	return readSOCKS5ConnectResponse(conn)
}

func authenticateSOCKS5(conn net.Conn, user *url.Userinfo) error {
	username := []byte(user.Username())
	passwordText, _ := user.Password()
	password := []byte(passwordText)
	if len(username) == 0 || len(username) > 255 || len(password) > 255 {
		return errors.New("invalid SOCKS5 username or password length")
	}
	request := make([]byte, 0, 3+len(username)+len(password))
	request = append(request, 0x01, byte(len(username)))
	request = append(request, username...)
	request = append(request, byte(len(password)))
	request = append(request, password...)
	if err := writeAll(conn, request); err != nil {
		return fmt.Errorf("write SOCKS5 authentication: %w", err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read SOCKS5 authentication response: %w", err)
	}
	if response[0] != 0x01 || response[1] != 0x00 {
		return errors.New("SOCKS5 authentication failed")
	}
	return nil
}

func socks5ConnectRequest(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("split SOCKS5 target: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("SOCKS5 target port must be between 1 and 65535")
	}

	request := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			request = append(request, 0x01)
			request = append(request, ipv4...)
		} else {
			request = append(request, 0x04)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("SOCKS5 target hostname must be between 1 and 255 bytes")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	return request, nil
}

func readSOCKS5ConnectResponse(conn net.Conn) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read SOCKS5 CONNECT response: %w", err)
	}
	if header[0] != 0x05 {
		return fmt.Errorf("SOCKS5 CONNECT response has version %d", header[0])
	}
	if header[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT failed with reply code %d", header[1])
	}

	addressLength := 0
	switch header[3] {
	case 0x01:
		addressLength = net.IPv4len
	case 0x04:
		addressLength = net.IPv6len
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return fmt.Errorf("read SOCKS5 bound hostname length: %w", err)
		}
		addressLength = int(length[0])
	default:
		return fmt.Errorf("SOCKS5 CONNECT response has address type %d", header[3])
	}
	boundAddress := make([]byte, addressLength+2)
	if _, err := io.ReadFull(conn, boundAddress); err != nil {
		return fmt.Errorf("read SOCKS5 bound address: %w", err)
	}
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func closeProxyAfterError(conn net.Conn, operationErr error) error {
	if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		return errors.Join(operationErr, fmt.Errorf("close upstream proxy connection: %w", closeErr))
	}
	return operationErr
}

type bufferedProxyConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedProxyConn) Read(data []byte) (int, error) {
	if c.reader.Buffered() > 0 {
		return c.reader.Read(data)
	}
	return c.Conn.Read(data)
}

func (c *bufferedProxyConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return nil
}

var _ outbound = (*upstreamPool)(nil)
