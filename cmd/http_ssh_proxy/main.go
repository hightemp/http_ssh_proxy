package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"
	"github.com/hightemp/http_ssh_proxy/internal/logutil"
	"github.com/hightemp/http_ssh_proxy/internal/proxy"
	"github.com/hightemp/http_ssh_proxy/internal/sshmanager"

	"gopkg.in/yaml.v3"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to the config file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("[STARTUP] Reading config file %s\n", *configPath)

	content, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] Error reading config file: %v", err)
	}

	var cfg config.Config
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		log.Fatalf("[FATAL] Error parsing config file: %v", err)
	}

	sshMgr := sshmanager.New(&cfg)
	if err := sshMgr.Connect(); err != nil {
		log.Fatalf("[FATAL] Error setting up SSH client: %v", err)
	}
	defer sshMgr.Close()

	// Start SSH keepalive and health monitoring.
	go sshMgr.KeepAlive()

	handler := proxy.NewHandler(proxy.Config{
		Username: cfg.Username,
		Password: cfg.Password,
	}, sshMgr)

	server := &http.Server{
		Addr:              cfg.ProxyAddr,
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
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

	log.Printf("[STARTUP] Starting proxy server on %s (proto=%s)\n", cfg.ProxyAddr, cfg.Proto)
	if cfg.Proto == "https" {
		cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
		if err != nil {
			log.Fatalf("[FATAL] Error loading TLS certificate: %v", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		listener, err := tls.Listen("tcp", cfg.ProxyAddr, tlsConfig)
		if err != nil {
			log.Fatalf("[FATAL] Error creating TLS listener: %v", err)
		}
		defer logutil.Close("TLS listener", listener)

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
