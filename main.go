package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ProxyAddr   string `yaml:"listen_addr"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	Proto       string `yaml:"proto"`
	CertPath    string `yaml:"pem_path"`
	KeyPath     string `yaml:"key_path"`
	SSHHost     string `yaml:"ssh_host"`
	SSHPort     int    `yaml:"ssh_port"`
	SSHUser     string `yaml:"ssh_user"`
	SSHPassword string `yaml:"ssh_pass"`
	SSHKeyFile  string `yaml:"ssh_key_file"`
}

// SSHManager manages the SSH connection with automatic reconnection and keepalive.
type SSHManager struct {
	config    *Config
	client    *ssh.Client
	mu        sync.RWMutex
	closed    chan struct{}
	closeOnce sync.Once
}

var config Config
var requestCounter uint64

func main() {
	configPath := flag.String("config", "config.yaml", "Path to the config file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("[STARTUP] Reading config file %s\n", *configPath)

	content, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] Error reading config file: %v", err)
	}

	err = yaml.Unmarshal(content, &config)
	if err != nil {
		log.Fatalf("[FATAL] Error parsing config file: %v", err)
	}

	sshMgr := NewSSHManager(&config)
	err = sshMgr.Connect()
	if err != nil {
		log.Fatalf("[FATAL] Error setting up SSH client: %v", err)
	}
	defer sshMgr.Close()

	// Start SSH keepalive and health monitoring
	go sshMgr.keepAliveLoop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := atomic.AddUint64(&requestCounter, 1)
		log.Printf("[REQ-%d] %s %s %s from %s", reqID, r.Method, r.Host, r.URL, r.RemoteAddr)
		if config.Username != "" && !basicAuth(w, r, reqID) {
			return
		}
		handleTunneling(w, r, sshMgr, reqID)
	})

	// Wrap with panic recovery
	recoveryHandler := panicRecoveryMiddleware(handler)

	server := &http.Server{
		Addr:              config.ProxyAddr,
		Handler:           recoveryHandler,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM
	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-shutdownCh
		log.Printf("[SHUTDOWN] Received signal %v, shutting down gracefully...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("[SHUTDOWN] HTTP server shutdown error: %v", err)
		}
	}()

	log.Printf("[STARTUP] Starting proxy server on %s (proto=%s)\n", config.ProxyAddr, config.Proto)
	if config.Proto == "https" {
		cert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
		if err != nil {
			log.Fatalf("[FATAL] Error loading TLS certificate: %v", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		listener, err := tls.Listen("tcp", config.ProxyAddr, tlsConfig)
		if err != nil {
			log.Fatalf("[FATAL] Error creating TLS listener: %v", err)
		}
		defer listener.Close()

		if err := server.Serve(listener); err != http.ErrServerClosed {
			log.Fatalf("[FATAL] HTTPS server error: %v", err)
		}
	} else {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("[FATAL] HTTP server error: %v", err)
		}
	}
	log.Println("[SHUTDOWN] Server stopped")
}

// ===================== SSH Manager =====================

func NewSSHManager(cfg *Config) *SSHManager {
	return &SSHManager{
		config: cfg,
		closed: make(chan struct{}),
	}
}

func (m *SSHManager) Connect() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connectLocked()
}

func (m *SSHManager) connectLocked() error {
	if m.client != nil {
		m.client.Close()
		m.client = nil
	}

	client, err := dialSSH(m.config)
	if err != nil {
		return fmt.Errorf("SSH dial failed: %w", err)
	}
	m.client = client
	log.Printf("[SSH] Connected to %s:%d as %s", m.config.SSHHost, m.config.SSHPort, m.config.SSHUser)
	return nil
}

func (m *SSHManager) reconnect() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if the current client is still alive
	if m.client != nil {
		_, _, err := m.client.SendRequest("keepalive@openssh.com", true, nil)
		if err == nil {
			return nil // Connection is fine
		}
		log.Printf("[SSH] Connection check failed: %v, reconnecting...", err)
	}

	var lastErr error
	for attempt := 1; attempt <= 5; attempt++ {
		log.Printf("[SSH] Reconnect attempt %d/5...", attempt)
		if err := m.connectLocked(); err != nil {
			lastErr = err
			log.Printf("[SSH] Reconnect attempt %d failed: %v", attempt, err)
			backoff := time.Duration(attempt*attempt) * time.Second
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			select {
			case <-time.After(backoff):
			case <-m.closed:
				return fmt.Errorf("SSH manager closed during reconnect")
			}
			continue
		}
		log.Printf("[SSH] Reconnected successfully on attempt %d", attempt)
		return nil
	}
	return fmt.Errorf("SSH reconnect failed after 5 attempts: %w", lastErr)
}

// GetClient returns the current SSH client, reconnecting if necessary.
func (m *SSHManager) GetClient() (*ssh.Client, error) {
	m.mu.RLock()
	client := m.client
	m.mu.RUnlock()

	if client != nil {
		return client, nil
	}

	if err := m.reconnect(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.client, nil
}

// Dial establishes a connection through the SSH tunnel, with automatic reconnection on failure.
func (m *SSHManager) Dial(network, addr string) (net.Conn, error) {
	client, err := m.GetClient()
	if err != nil {
		return nil, fmt.Errorf("SSH client unavailable: %w", err)
	}

	conn, err := client.Dial(network, addr)
	if err != nil {
		// The SSH connection may have died — try to reconnect once
		log.Printf("[SSH] Dial to %s failed (%v), attempting reconnect...", addr, err)
		if reconnErr := m.reconnect(); reconnErr != nil {
			return nil, fmt.Errorf("SSH dial failed and reconnect failed: dial=%v reconnect=%v", err, reconnErr)
		}
		client, err = m.GetClient()
		if err != nil {
			return nil, err
		}
		conn, err = client.Dial(network, addr)
		if err != nil {
			return nil, fmt.Errorf("SSH dial failed after reconnect: %w", err)
		}
	}
	return conn, nil
}

func (m *SSHManager) keepAliveLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	failCount := 0
	for {
		select {
		case <-ticker.C:
			m.mu.RLock()
			client := m.client
			m.mu.RUnlock()

			if client == nil {
				log.Printf("[SSH] No active client, triggering reconnect...")
				if err := m.reconnect(); err != nil {
					log.Printf("[SSH] Keepalive reconnect failed: %v", err)
				}
				continue
			}

			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				failCount++
				log.Printf("[SSH] Keepalive failed (count=%d): %v", failCount, err)
				if failCount >= 3 {
					log.Printf("[SSH] Keepalive failed %d times, forcing reconnect...", failCount)
					if err := m.reconnect(); err != nil {
						log.Printf("[SSH] Keepalive reconnect failed: %v", err)
					} else {
						failCount = 0
					}
				}
			} else {
				if failCount > 0 {
					log.Printf("[SSH] Keepalive recovered after %d failures", failCount)
				}
				failCount = 0
			}

		case <-m.closed:
			log.Println("[SSH] Keepalive loop stopped")
			return
		}
	}
}

func (m *SSHManager) Close() {
	m.closeOnce.Do(func() {
		close(m.closed)
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.client != nil {
			m.client.Close()
			m.client = nil
		}
		log.Println("[SSH] Manager closed")
	})
}

func dialSSH(cfg *Config) (*ssh.Client, error) {
	var auth []ssh.AuthMethod
	if cfg.SSHPassword != "" {
		auth = append(auth, ssh.Password(cfg.SSHPassword))
	}
	if cfg.SSHKeyFile != "" {
		key, err := os.ReadFile(cfg.SSHKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read SSH key file: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse SSH private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.SSHUser,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", cfg.SSHHost, cfg.SSHPort), sshConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// ===================== Middleware =====================

func panicRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[PANIC] Recovered from panic in %s %s: %v\n%s", r.Method, r.URL, rec, debug.Stack())
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ===================== Auth =====================

func basicAuth(w http.ResponseWriter, r *http.Request, reqID uint64) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		log.Printf("[REQ-%d] No Proxy-Authorization header", reqID)
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Authorization Required"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return false
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		log.Printf("[REQ-%d] Error decoding auth: %v", reqID, err)
		w.WriteHeader(http.StatusBadRequest)
		return false
	}

	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		log.Printf("[REQ-%d] Invalid auth format", reqID)
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Authorization Required"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return false
	}

	if pair[0] != config.Username || pair[1] != config.Password {
		log.Printf("[REQ-%d] Failed auth from %s user=%s", reqID, r.RemoteAddr, pair[0])
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Authorization Required"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return false
	}

	return true
}

// ===================== Proxy handlers =====================

func handleTunneling(w http.ResponseWriter, r *http.Request, sshMgr *SSHManager, reqID uint64) {
	if r.Method == http.MethodConnect {
		handleConnect(w, r, sshMgr, reqID)
	} else {
		handleHTTP(w, r, sshMgr, reqID)
	}
}

func handleConnect(w http.ResponseWriter, r *http.Request, sshMgr *SSHManager, reqID uint64) {
	destConn, err := sshMgr.Dial("tcp", r.Host)
	if err != nil {
		log.Printf("[REQ-%d] CONNECT dial to %s failed: %v", reqID, r.Host, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[REQ-%d] Hijacking not supported", reqID)
		destConn.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[REQ-%d] Hijack error: %v", reqID, err)
		destConn.Close()
		return
	}

	// Use a WaitGroup + done channel to close both sides when either transfer finishes
	done := make(chan struct{})
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			close(done)
			clientConn.Close()
			destConn.Close()
		})
	}

	go func() {
		defer closeBoth()
		transfer(destConn, clientConn, reqID, "client->dest")
	}()
	go func() {
		defer closeBoth()
		transfer(clientConn, destConn, reqID, "dest->client")
	}()
}

func handleHTTP(w http.ResponseWriter, r *http.Request, sshMgr *SSHManager, reqID uint64) {
	httpClient := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return sshMgr.Dial(network, addr)
			},
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}

	outReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		log.Printf("[REQ-%d] Error creating request: %v", reqID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for key, values := range r.Header {
		if key != "Proxy-Authorization" && key != "Proxy-Connection" {
			outReq.Header[key] = values
		}
	}

	resp, err := httpClient.Do(outReq)
	if err != nil {
		log.Printf("[REQ-%d] Error forwarding request to %s: %v", reqID, r.URL.Host, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(resp.StatusCode)

	n, err := io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("[REQ-%d] Error copying response (%d bytes written): %v", reqID, n, err)
	} else {
		log.Printf("[REQ-%d] Completed %s %d (%d bytes)", reqID, r.URL.Host, resp.StatusCode, n)
	}
}

func transfer(destination io.Writer, source io.Reader, reqID uint64, direction string) {
	n, err := io.Copy(destination, source)
	if err != nil {
		// Don't log "use of closed network connection" as error — it's expected on tunnel close
		errStr := err.Error()
		if strings.Contains(errStr, "use of closed network connection") ||
			strings.Contains(errStr, "connection reset by peer") ||
			strings.Contains(errStr, "broken pipe") {
			log.Printf("[REQ-%d] %s closed (%d bytes)", reqID, direction, n)
		} else {
			log.Printf("[REQ-%d] %s transfer error after %d bytes: %v", reqID, direction, n, err)
		}
	} else {
		log.Printf("[REQ-%d] %s done (%d bytes)", reqID, direction, n)
	}
}
