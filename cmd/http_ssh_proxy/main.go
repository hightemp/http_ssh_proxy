package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/hightemp/http_ssh_proxy/internal/app"
	"github.com/hightemp/http_ssh_proxy/internal/config"
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
	if err := app.Run(ctx, cfg); err != nil {
		log.Fatalf("[FATAL] Proxy stopped with an error: %v", err)
	}
}
