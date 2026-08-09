package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"
	"github.com/hightemp/http_ssh_proxy/internal/proxy"
	"github.com/hightemp/http_ssh_proxy/internal/sshmanager"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to the config file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("[STARTUP] Reading config file %s", *configPath)
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] Error loading config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil {
		log.Fatalf("[FATAL] Proxy stopped with an error: %v", err)
	}
}

func run(ctx context.Context, cfg *config.Config) error {
	sshManager := sshmanager.New(cfg)
	if err := sshManager.Connect(ctx); err != nil {
		return fmt.Errorf("set up SSH client: %w", err)
	}
	sshManager.StartKeepAlive(ctx)

	handler := proxy.NewHandler(proxy.Config{
		Username:          cfg.Username,
		Password:          cfg.Password,
		TunnelIdleTimeout: time.Duration(cfg.TunnelIdleTimeoutSeconds) * time.Second,
	}, sshManager)
	server := &http.Server{
		Addr:              cfg.ProxyAddr,
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	listener, err := proxyListener(cfg)
	if err != nil {
		return errors.Join(err, sshManager.Close())
	}
	log.Printf("[STARTUP] Starting proxy server on %s (proto=%s)", cfg.ProxyAddr, cfg.Proto)

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- server.Serve(listener)
	}()

	select {
	case serveErr := <-serveErrCh:
		shutdownErr := shutdown(server, handler, time.Duration(cfg.ShutdownTimeoutSeconds)*time.Second)
		return errors.Join(normalizeServeError(serveErr), shutdownErr, sshManager.Close())
	case <-ctx.Done():
		log.Println("[SHUTDOWN] Shutdown requested")
		shutdownErr := shutdown(server, handler, time.Duration(cfg.ShutdownTimeoutSeconds)*time.Second)
		serveErr := <-serveErrCh
		managerErr := sshManager.Close()
		log.Println("[SHUTDOWN] Server stopped")
		return errors.Join(shutdownErr, normalizeServeError(serveErr), managerErr)
	}
}

func proxyListener(cfg *config.Config) (net.Listener, error) {
	listener, err := net.Listen("tcp", cfg.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", cfg.ProxyAddr, err)
	}
	if cfg.Proto == "http" {
		return listener, nil
	}

	certificate, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		if closeErr := listener.Close(); closeErr != nil {
			return nil, errors.Join(
				fmt.Errorf("load TLS certificate: %w", err),
				fmt.Errorf("close listener after TLS error: %w", closeErr),
			)
		}
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}
	return tls.NewListener(listener, tlsConfig), nil
}

func shutdown(server *http.Server, handler *proxy.Handler, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result := make(chan error, 2)
	go func() {
		result <- server.Shutdown(ctx)
	}()
	go func() {
		result <- handler.Shutdown(ctx)
	}()

	var shutdownErrors []error
	for range 2 {
		if err := <-result; err != nil {
			shutdownErrors = append(shutdownErrors, err)
		}
	}
	if ctx.Err() != nil {
		if err := server.Close(); err != nil {
			shutdownErrors = append(shutdownErrors, fmt.Errorf("force-close HTTP server: %w", err))
		}
	}
	return errors.Join(shutdownErrors...)
}

func normalizeServeError(err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("serve proxy: %w", err)
}
